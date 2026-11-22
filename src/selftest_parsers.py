"""
Testes de unidade dos parsers binários (rodam em qualquer SO, sem raw socket).
Validam a manipulação byte a byte de ARP, IPv4/TCP/UDP, DNS e TLS SNI.
"""
import socket
import struct
import sys

sys.path.insert(0, ".")
from interceptor import arp, parser, dns, web


def build_eth_ip(proto, src_ip, dst_ip, l4):
    eth = (b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66"
           + struct.pack("!H", 0x0800))
    ihl = 5
    ver_ihl = (4 << 4) | ihl
    total = 20 + len(l4)
    ip = struct.pack("!BBHHHBBH", ver_ihl, 0, total, 0, 0, 64, proto, 0)
    ip += socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
    return eth + ip + l4


def build_tcp(sport, dport, payload, flags=0x18):
    data_off = 5
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0,
                      (data_off << 4), flags, 0, 0, 0)
    return tcp + payload


def build_udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def build_dns_query(qname):
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q = b""
    for label in qname.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack("!HH", 1, 1)  # type A, class IN
    return header + q


def build_dns_response(qname, ip):
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    q = b""
    for label in qname.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack("!HH", 1, 1)
    # Answer com ponteiro de compressão para o nome (offset 12).
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return header + q + ans


def build_client_hello(hostname):
    host = hostname.encode()
    # Extensão SNI
    server_name = b"\x00" + struct.pack("!H", len(host)) + host  # type host_name
    sni_list = struct.pack("!H", len(server_name)) + server_name
    ext_sni = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    extensions = ext_sni
    ext_block = struct.pack("!H", len(extensions)) + extensions

    body = b"\x03\x03" + b"\x00" * 32    # versão + random
    body += b"\x00"                       # session id len = 0
    body += struct.pack("!H", 2) + b"\x00\x2f"  # cipher suites
    body += b"\x01\x00"                    # compression: len1 + null
    body += ext_block

    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body  # 3B len
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record


def check(name, cond):
    print(f"  [{'OK ' if cond else 'FAIL'}] {name}")
    return cond


def main():
    ok = True

    # ---- ARP ----
    print("ARP:")
    req = arp.arp_request(b"\x11\x22\x33\x44\x55\x66", "172.30.0.3",
                          "172.30.0.10")
    ok &= check("ARP request tem 42 bytes", len(req) == 42)
    ok &= check("ethertype ARP 0x0806",
                struct.unpack("!H", req[12:14])[0] == 0x0806)
    poison = arp.arp_poison("172.30.0.10", b"\xaa"*6, "172.30.0.2", b"\xbb"*6)
    res = arp.parse_arp_reply(poison)
    ok &= check("parse do reply devolve SPA correto", res and res[0] == "172.30.0.2")

    # ---- IP/TCP/UDP ----
    print("Parser IP/TCP/UDP:")
    frame = build_eth_ip(6, "172.30.0.10", "172.31.0.80",
                         build_tcp(50000, 80, b"GET / HTTP/1.1\r\n\r\n"))
    pkt = parser.decode(frame)
    ok &= check("decode IPv4/TCP", pkt and pkt["l4_proto"] == "TCP")
    ok &= check("portas TCP corretas (src 50000, dst 80)",
                pkt["l4"]["sport"] == 50000 and pkt["l4"]["dport"] == 80)
    ok &= check("src/dst IP corretos",
                pkt["ip"]["src_ip"] == "172.30.0.10"
                and pkt["ip"]["dst_ip"] == "172.31.0.80")

    # ---- HTTP ----
    print("HTTP:")
    payload = (b"GET /login?u=admin HTTP/1.1\r\nHost: site-http.lab\r\n"
               b"User-Agent: curl/8.0\r\nCookie: sess=abc123\r\n\r\n")
    http = web.parse_http(payload)
    ok &= check("método GET", http and http["method"] == "GET")
    ok &= check("URI", http["uri"] == "/login?u=admin")
    ok &= check("Host", http["host"] == "site-http.lab")
    ok &= check("Cookie capturado", http["cookie"] == "sess=abc123")

    # ---- DNS ----
    print("DNS:")
    q = dns.parse_dns(build_dns_query("www.exemplo.com"))
    ok &= check("QNAME da consulta", q and q["qname"] == "www.exemplo.com")
    ok &= check("consulta não é resposta", q["is_response"] is False)
    r = dns.parse_dns(build_dns_response("www.exemplo.com", "93.184.216.34"))
    ok &= check("resposta tem registro A",
                r and ("www.exemplo.com", "93.184.216.34") in r["answers"])

    # ---- TLS SNI ----
    print("TLS SNI:")
    ch = build_client_hello("secreto.exemplo.com")
    ok &= check("detecta ClientHello", web.is_tls_client_hello(ch))
    sni = web.extract_sni(ch)
    ok &= check("extrai SNI = secreto.exemplo.com", sni == "secreto.exemplo.com")

    # SNI com extensões antes da SNI (robustez de offset)
    print("Resumo:")
    print("TODOS OS TESTES PASSARAM" if ok else "HOUVE FALHAS")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
