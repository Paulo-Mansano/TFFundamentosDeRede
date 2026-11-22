"""
netutil.py — Utilidades de baixo nível para descobrir parâmetros da interface
de rede da máquina atacante (MAC, IP, máscara) e enumerar a sub-rede.

Tudo é obtido via `ioctl()` sobre um socket (chamadas nativas do kernel Linux)
ou lendo /sys e /proc. NÃO usamos nenhuma biblioteca de rede de alto nível
(Scapy, netifaces, psutil, etc.) — apenas a stdlib: socket, struct, fcntl.

Conceito (arguição): o kernel expõe informações da interface através de
"ioctls" (input/output control). Enviamos um pedido como SIOCGIFHWADDR e o
kernel devolve a estrutura `ifreq` preenchida com os bytes do endereço MAC.
"""

import socket
import struct
import fcntl
import ipaddress

# Constantes de ioctl do Linux (definidas em <linux/sockios.h>).
SIOCGIFHWADDR = 0x8927   # obtém o endereço de hardware (MAC) da interface
SIOCGIFADDR   = 0x8915   # obtém o endereço IPv4 da interface
SIOCGIFNETMASK = 0x891B  # obtém a máscara de rede da interface


def _ioctl_ifreq(ifname: str, request: int) -> bytes:
    """Executa um ioctl que recebe/retorna uma struct ifreq e devolve os bytes."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    try:
        # ifreq: 16 bytes para o nome da interface + payload.
        ifreq = struct.pack("256s", ifname.encode("utf-8")[:15])
        return fcntl.ioctl(s.fileno(), request, ifreq)
    finally:
        s.close()


def get_mac(ifname: str) -> bytes:
    """Retorna o MAC da interface como 6 bytes crus (ex.: b'\\x02\\x42...')."""
    info = _ioctl_ifreq(ifname, SIOCGIFHWADDR)
    # Nos bytes 18..24 fica o sa_data com o endereço de hardware.
    return info[18:24]


def get_ipv4(ifname: str) -> str:
    """Retorna o IPv4 da interface como string pontuada (ex.: '172.30.0.3')."""
    info = _ioctl_ifreq(ifname, SIOCGIFADDR)
    # bytes 20..24 contêm o endereço IPv4 dentro da sockaddr_in.
    return socket.inet_ntoa(info[20:24])


def get_netmask(ifname: str) -> str:
    """Retorna a máscara de rede da interface como string pontuada."""
    info = _ioctl_ifreq(ifname, SIOCGIFNETMASK)
    return socket.inet_ntoa(info[20:24])


def mac_to_str(b: bytes) -> str:
    """Converte 6 bytes de MAC em 'aa:bb:cc:dd:ee:ff'."""
    return ":".join("%02x" % x for x in b)


def str_to_mac(s: str) -> bytes:
    """Converte 'aa:bb:cc:dd:ee:ff' em 6 bytes."""
    return bytes(int(p, 16) for p in s.split(":"))


def default_iface() -> str:
    """
    Descobre a interface da rota default lendo /proc/net/route (sem libs).
    Cada linha traz Iface, Destination (hex), ... ; a rota default tem
    Destination == 00000000.
    """
    with open("/proc/net/route") as f:
        for line in f.readlines()[1:]:
            parts = line.strip().split()
            if len(parts) >= 2 and parts[1] == "00000000":
                return parts[0]
    # Alternativa: primeira interface não-loopback com IPv4.
    raise RuntimeError("Não foi possível determinar a interface default")


def hosts_in_subnet(ip: str, netmask: str):
    """
    Gera todos os endereços de host da sub-rede (exceto rede/broadcast),
    usado pela varredura ARP. Ex.: 172.30.0.0/24 -> 172.30.0.1 .. .254
    """
    net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    for host in net.hosts():
        yield str(host)


def iface_info(ifname: str) -> dict:
    """Agrupa todas as informações da interface num dicionário."""
    return {
        "name": ifname,
        "mac": get_mac(ifname),
        "ip": get_ipv4(ifname),
        "netmask": get_netmask(ifname),
    }
