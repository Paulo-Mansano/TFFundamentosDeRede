"""
parser.py — Decodificação MULTICAMADAS do quadro cru vindo do raw socket.

Avançamos da esquerda para a direita no quadro (Figura 4 do guia):
   Ethernet(14) -> IPv4(IHL*4) -> TCP(DataOffset*4) | UDP(8) -> payload

Pontos sensíveis (cobrados na arguição):
  * Byte order de rede = big-endian -> usamos o prefixo '!' no struct.unpack.
  * Cabeçalhos NÃO têm tamanho fixo: o offset da próxima camada é CALCULADO,
    nunca assumido (IPv4 via IHL, TCP via Data Offset).

Cada função devolve um dicionário com os campos e o offset/fatia do payload,
para o próximo nível decodificar. Retorna None quando o quadro não é do tipo
esperado (ex.: não é IPv4), permitindo filtrar cedo.
"""

import socket
import struct

ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

# Flags TCP (bit a bit no byte 13 do cabeçalho TCP).
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


def parse_ethernet(frame: bytes):
    """Decodifica o cabeçalho Ethernet (14 bytes fixos)."""
    if len(frame) < 14:
        return None
    dst, src, ethertype = struct.unpack("!6s6sH", frame[:14])
    return {
        "dst": dst,
        "src": src,
        "ethertype": ethertype,
        "payload_off": 14,
    }


def parse_ipv4(frame: bytes, off: int):
    """
    Decodifica IPv4 a partir do offset `off` (normalmente 14).
    O tamanho do cabeçalho vem do campo IHL (4 bits) × 4.
    """
    if len(frame) < off + 20:
        return None
    ver_ihl = frame[off]
    version = ver_ihl >> 4
    if version != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4          # tamanho REAL do cabeçalho IP
    total_len = struct.unpack("!H", frame[off + 2:off + 4])[0]
    ttl = frame[off + 8]
    proto = frame[off + 9]
    src_ip = socket.inet_ntoa(frame[off + 12:off + 16])
    dst_ip = socket.inet_ntoa(frame[off + 16:off + 20])
    return {
        "ihl": ihl,
        "total_len": total_len,
        "ttl": ttl,
        "proto": proto,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "payload_off": off + ihl,       # início de TCP/UDP
    }


def parse_tcp(frame: bytes, off: int):
    """
    Decodifica TCP a partir de `off`. O tamanho do cabeçalho vem do campo
    Data Offset (4 bits do byte 12) × 4. O payload é o que sobra.
    """
    if len(frame) < off + 20:
        return None
    sport, dport = struct.unpack("!HH", frame[off:off + 4])
    seq, ack = struct.unpack("!II", frame[off + 4:off + 12])
    data_off = (frame[off + 12] >> 4) * 4
    flags = frame[off + 13]
    payload_off = off + data_off
    return {
        "sport": sport,
        "dport": dport,
        "seq": seq,
        "ack": ack,
        "data_off": data_off,
        "flags": flags,
        "payload_off": payload_off,
        "payload": frame[payload_off:],
    }


def parse_udp(frame: bytes, off: int):
    """Decodifica UDP (cabeçalho fixo de 8 bytes)."""
    if len(frame) < off + 8:
        return None
    sport, dport, length, _csum = struct.unpack("!HHHH", frame[off:off + 8])
    payload_off = off + 8
    return {
        "sport": sport,
        "dport": dport,
        "length": length,
        "payload_off": payload_off,
        "payload": frame[payload_off:],
    }


def flags_to_str(flags: int) -> str:
    """Representação textual das flags TCP (ex.: 'SYN,ACK')."""
    names = []
    for bit, name in ((TCP_SYN, "SYN"), (TCP_ACK, "ACK"), (TCP_FIN, "FIN"),
                      (TCP_RST, "RST"), (TCP_PSH, "PSH"), (TCP_URG, "URG")):
        if flags & bit:
            names.append(name)
    return ",".join(names) if names else "-"


def decode(frame: bytes):
    """
    Decodifica o quadro inteiro e devolve uma estrutura em camadas:
      { 'eth': {...}, 'ip': {...}|None, 'l4': {...}|None, 'l4_proto': 'TCP'|'UDP',
        'payload': bytes }
    Só decodifica IPv4; ARP é tratado pelo módulo arp.py.
    """
    eth = parse_ethernet(frame)
    if eth is None or eth["ethertype"] != ETH_P_IP:
        return None
    ip = parse_ipv4(frame, eth["payload_off"])
    if ip is None:
        return None

    result = {"eth": eth, "ip": ip, "l4": None, "l4_proto": None,
              "payload": b""}

    if ip["proto"] == PROTO_TCP:
        tcp = parse_tcp(frame, ip["payload_off"])
        if tcp:
            result["l4"] = tcp
            result["l4_proto"] = "TCP"
            result["payload"] = tcp["payload"]
    elif ip["proto"] == PROTO_UDP:
        udp = parse_udp(frame, ip["payload_off"])
        if udp:
            result["l4"] = udp
            result["l4_proto"] = "UDP"
            result["payload"] = udp["payload"]
    elif ip["proto"] == PROTO_ICMP:
        result["l4_proto"] = "ICMP"
    return result
