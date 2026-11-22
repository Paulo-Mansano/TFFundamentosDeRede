"""
dns.py — Camada de APLICAÇÃO: parsing de mensagens DNS (UDP/53).

Objetivo (Seção 3.5 do enunciado):
  * Extrair o QNAME das consultas (tipo A/AAAA);
  * Nas respostas, extrair os IPs (registros tipo A) para correlacionar
    domínio <-> IP com as conexões web subsequentes.

Formato da mensagem DNS (RFC 1035):
  Header (12 B): ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
  Question(s):   QNAME (labels) + QTYPE(2) + QCLASS(2)
  Answer(s):     NAME + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA

QNAME é uma sequência de labels [len][bytes]...[0x00], ex.:
  3 'w''w''w' 6 'g''o''o''g''l''e' 3 'c''o''m' 0   -> "www.google.com"

Compressão de nomes (RFC 1035 §4.1.4): um label cujo 2 bits altos são 11
(>= 0xC0) é um PONTEIRO para outro ponto da mensagem. Tratamos isso ao pular
nomes nas respostas.
"""

import struct

DNS_TYPE_A = 1
DNS_TYPE_AAAA = 28
QR_RESPONSE = 0x8000  # bit QR no campo FLAGS


def _read_name(data: bytes, off: int):
    """
    Lê um nome DNS a partir de `off`, seguindo ponteiros de compressão.
    Devolve (nome, novo_offset) — o novo offset é o da posição logo após o
    nome no fluxo original (ponteiros não avançam o offset principal).
    """
    labels = []
    jumped = False
    original_off = off
    safety = 0
    while True:
        safety += 1
        if safety > 128 or off >= len(data):
            break
        length = data[off]
        if length == 0:
            off += 1
            break
        if (length & 0xC0) == 0xC0:
            # Ponteiro de compressão: 14 bits de offset.
            if off + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[off + 1]
            if not jumped:
                original_off = off + 2
            off = pointer
            jumped = True
            continue
        off += 1
        labels.append(data[off:off + length].decode("ascii", "replace"))
        off += length
    name = ".".join(labels)
    return name, (original_off if jumped else off)


def parse_dns(payload: bytes):
    """
    Decodifica uma mensagem DNS.
    Retorna dict:
      { 'is_response': bool, 'qname': str|None, 'qtype': int|None,
        'answers': [(nome, ip_str), ...] }
    """
    if len(payload) < 12:
        return None
    (_id, flags, qd, an, _ns, _ar) = struct.unpack("!HHHHHH", payload[:12])
    is_response = bool(flags & QR_RESPONSE)

    off = 12
    qname = None
    qtype = None
    # Lê a(s) Question(s) — normalmente uma.
    for i in range(qd):
        name, off = _read_name(payload, off)
        if off + 4 > len(payload):
            return None
        qtype, _qclass = struct.unpack("!HH", payload[off:off + 4])
        off += 4
        if i == 0:
            qname = name

    answers = []
    # Lê os Answers (apenas nas respostas).
    if is_response:
        for _ in range(an):
            if off >= len(payload):
                break
            _name, off = _read_name(payload, off)
            if off + 10 > len(payload):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH",
                                                        payload[off:off + 10])
            off += 10
            rdata = payload[off:off + rdlen]
            off += rdlen
            if rtype == DNS_TYPE_A and rdlen == 4:
                ip = ".".join(str(b) for b in rdata)
                answers.append((_name or qname, ip))
    return {
        "is_response": is_response,
        "qname": qname,
        "qtype": qtype,
        "answers": answers,
    }
