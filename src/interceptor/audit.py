"""
audit.py — Estado compartilhado, contadores e CORRELAÇÃO domínio <-> IP.

Esta é a "memória" do interceptador, escrita pela thread de processamento (T2)
e lida pelo painel (T4) e pela persistência. Por isso TODO acesso é protegido
por um `threading.Lock` — condição de corrida aqui apareceria como número
"pulando" no painel (ponto citado na arguição).

Estruturas principais:
  * counters       : contadores globais (pacotes, DNS, HTTP, TLS, bytes...)
  * dns_map        : IP de destino -> domínio (aprendido via respostas DNS)
  * destinations   : domínio/IP -> agregação (protocolos usados, bytes totais)
  * recent         : fila curta dos últimos eventos (para o painel)
"""

import threading
import time
from collections import deque, OrderedDict


class AuditState:
    def __init__(self, max_recent: int = 12):
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.counters = {
            "packets": 0,     # pacotes do fluxo da vítima
            "dns": 0,         # mensagens DNS observadas
            "http": 0,        # requisições HTTP
            "tls": 0,         # ClientHello/SNI observados
            "bytes": 0,       # volume total do fluxo da vítima
        }
        # Correlação: IP resolvido -> domínio (RFC 1035 tipo A).
        self.dns_map = {}
        # Agregação por chave de destino (domínio preferido, senão IP).
        # valor: {"domain", "ip", "protocols": set, "bytes": int}
        self.destinations = OrderedDict()
        self.recent = deque(maxlen=max_recent)
        self.arp_status = {}  # info de status do ARP para o painel
        # Lista de callbacks (ex.: persistência) chamados a cada evento.
        self._event_sinks = []

    # ---------------------------------------------------------------
    def add_event_sink(self, fn):
        """Registra um callback fn(event_dict) chamado a cada novo evento."""
        self._event_sinks.append(fn)

    def _emit(self, event: dict):
        for fn in self._event_sinks:
            try:
                fn(event)
            except Exception:
                pass

    # ---------------------------------------------------------------
    def note_packet(self, nbytes: int):
        with self.lock:
            self.counters["packets"] += 1
            self.counters["bytes"] += nbytes

    def learn_dns(self, domain: str, ips, src_ip: str, dst_ip: str):
        """
        Registra uma consulta/resposta DNS e alimenta a correlação.
        Importante: o IP associado ao domínio é o IP RESOLVIDO (registro A),
        nunca o IP do servidor DNS. Numa consulta (sem respostas) o IP fica
        indefinido até chegar a resposta ou a conexão web.
        """
        with self.lock:
            self.counters["dns"] += 1
            for ip in ips:
                self.dns_map[ip] = domain
            self._touch_destination(domain, ips[0] if ips else None, "DNS", 0)
        event = {
            "ts": time.time(), "type": "DNS",
            "src": src_ip, "dst": dst_ip,
            "domain": domain, "ips": ips, "bytes": 0,
        }
        with self.lock:
            self.recent.append(event)
        self._emit(event)

    def note_http(self, http: dict, src_ip: str, dst_ip: str, nbytes: int):
        with self.lock:
            self.counters["http"] += 1
            domain = http.get("host") or self.dns_map.get(dst_ip) or dst_ip
            self._touch_destination(domain, dst_ip, "HTTP", nbytes)
        event = {
            "ts": time.time(), "type": "HTTP",
            "src": src_ip, "dst": dst_ip,
            "domain": domain,
            "method": http.get("method"), "uri": http.get("uri"),
            "user_agent": http.get("user_agent"),
            "cookie": http.get("cookie"),
            "bytes": nbytes,
        }
        with self.lock:
            self.recent.append(event)
        self._emit(event)

    def note_tls(self, sni, src_ip: str, dst_ip: str, nbytes: int):
        with self.lock:
            self.counters["tls"] += 1
            domain = sni or self.dns_map.get(dst_ip) or dst_ip
            self._touch_destination(domain, dst_ip, "HTTPS", nbytes)
        event = {
            "ts": time.time(), "type": "HTTPS",
            "src": src_ip, "dst": dst_ip,
            "domain": domain, "sni": sni, "bytes": nbytes,
        }
        with self.lock:
            self.recent.append(event)
        self._emit(event)

    def add_flow_bytes(self, dst_ip: str, nbytes: int):
        """Soma bytes a um destino já conhecido (sem novo evento)."""
        with self.lock:
            domain = self.dns_map.get(dst_ip, dst_ip)
            key = self._dest_key(domain, dst_ip)
            if key in self.destinations:
                self.destinations[key]["bytes"] += nbytes

    # ---------------------------------------------------------------
    def _dest_key(self, domain: str, ip) -> str:
        return domain if domain else (ip or "?")

    def _touch_destination(self, domain, ip, proto, nbytes):
        """(Chamar sempre com self.lock já adquirido.)

        A chave de agregação é o domínio (quando conhecido). O campo `ip`
        guarda o IP de destino REAL associado ao domínio (resolvido via DNS ou
        o destino das conexões HTTP/HTTPS), sendo atualizado quando um IP
        melhor aparece — nunca sobrescrito por None.
        """
        key = self._dest_key(domain, ip)
        d = self.destinations.get(key)
        if d is None:
            d = {"domain": domain, "ip": ip, "protocols": set(), "bytes": 0}
            self.destinations[key] = d
        d["protocols"].add(proto)
        d["bytes"] += nbytes
        if domain and (not d["domain"] or d["domain"] == d["ip"]):
            d["domain"] = domain
        if ip and not d["ip"]:
            d["ip"] = ip

    # ---------------------------------------------------------------
    def snapshot(self):
        """Cópia consistente do estado para o painel (sob lock)."""
        with self.lock:
            return {
                "uptime": time.time() - self.start_time,
                "counters": dict(self.counters),
                "destinations": [
                    {
                        "domain": v["domain"] or "-", "ip": v["ip"] or "-",
                        "protocols": sorted(v["protocols"]),
                        "bytes": v["bytes"],
                    }
                    for v in self.destinations.values()
                ],
                "recent": list(self.recent),
                "arp_status": dict(self.arp_status),
            }
