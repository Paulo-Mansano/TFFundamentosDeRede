"""
web.py — Camada de APLICAÇÃO/SEGURANÇA: inspeção de tráfego web.

Dois casos (Seção 3.6 do enunciado):

  HTTP (porta 80) — texto em claro:
     Linha de requisição: "GET /caminho HTTP/1.1"
     Cabeçalhos:          "Host: exemplo.com", "User-Agent: ...", "Cookie: ..."
     Extraímos método, URI, Host e alguns cabeçalhos sensíveis.

  HTTPS/TLS (porta 443) — só o SNI vaza (antes da cifragem):
     O ClientHello é enviado em claro. Percorremos a estrutura do TLS
     ClientHello (Tabela 5 do guia) até a extensão SNI (tipo 0x0000) e
     lemos o hostname. É esse campo que denuncia o site mesmo em HTTPS,
     porque o servidor precisa dele para escolher o certificado (virtual
     hosting) ANTES de a sessão estar cifrada.

Toda a leitura é feita com fatiamento de bytes e int.from_bytes — sem libs.
Validamos limites a cada passo para não quebrar com pacotes truncados.
"""

# ----------------------------- HTTP -----------------------------------

HTTP_METHODS = (b"GET", b"POST", b"HEAD", b"PUT", b"DELETE",
                b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE")


def parse_http(payload: bytes):
    """
    Se o payload TCP começar com uma requisição HTTP, devolve um dict com
    método, URI, versão, Host e cabeçalhos selecionados. Caso contrário None.
    """
    if not payload or not payload.startswith(HTTP_METHODS):
        return None
    try:
        text = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    except Exception:
        return None
    lines = text.split("\r\n")
    if not lines:
        return None
    request_line = lines[0].split(" ")
    if len(request_line) < 3:
        return None
    method, uri, version = request_line[0], request_line[1], request_line[2]

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    return {
        "method": method,
        "uri": uri,
        "version": version,
        "host": headers.get("host"),
        "user_agent": headers.get("user-agent"),
        "cookie": headers.get("cookie"),
        "headers": headers,
    }


# ----------------------------- TLS SNI --------------------------------

TLS_CONTENT_HANDSHAKE = 0x16
TLS_HS_CLIENT_HELLO = 0x01
EXT_SERVER_NAME = 0x0000


def extract_sni(payload: bytes):
    """
    Extrai o hostname do campo SNI de um TLS ClientHello.
    Retorna a string do domínio ou None.

    Percurso (todos os tamanhos lidos do próprio stream, nunca assumidos):
      TLS Record (5B): tipo(1)=0x16 + versão(2) + comprimento(2)
      Handshake (4B):  tipo(1)=0x01 + comprimento(3)
      ClientHello:     versão(2) + random(32)
                       + session_id (1B len + N)
                       + cipher_suites (2B len + N)
                       + compression (1B len + N)
                       + extensions (2B len total + extensões)
      Extensão SNI (tipo 0x0000):
                       ServerNameList (2B len) + tipo(1)=0x00 (host_name)
                       + nome (2B len + hostname)
    """
    p = payload
    n = len(p)
    if n < 5 or p[0] != TLS_CONTENT_HANDSHAKE:
        return None

    # TLS record length (bytes 3..5) — pode haver fragmentação; checamos limites.
    off = 5
    if off + 4 > n or p[off] != TLS_HS_CLIENT_HELLO:
        return None

    # Pula handshake header (4) + versão (2) + random (32).
    off += 4 + 2 + 32
    if off >= n:
        return None

    # Session ID.
    sid_len = p[off]
    off += 1 + sid_len
    if off + 2 > n:
        return None

    # Cipher Suites.
    cs_len = int.from_bytes(p[off:off + 2], "big")
    off += 2 + cs_len
    if off + 1 > n:
        return None

    # Compression Methods.
    comp_len = p[off]
    off += 1 + comp_len
    if off + 2 > n:
        return None

    # Extensions.
    ext_total = int.from_bytes(p[off:off + 2], "big")
    off += 2
    end = min(off + ext_total, n)

    while off + 4 <= end:
        etype = int.from_bytes(p[off:off + 2], "big")
        elen = int.from_bytes(p[off + 2:off + 4], "big")
        ebody = off + 4
        if etype == EXT_SERVER_NAME:
            # Dentro da extensão: ServerNameList(2) + type(1) + nameLen(2) + name
            if ebody + 5 > n:
                return None
            # ebody+0..2 = tamanho da lista; ebody+2 = tipo (0x00 = host_name)
            name_type = p[ebody + 2]
            if name_type != 0x00:
                off = ebody + elen
                continue
            name_len = int.from_bytes(p[ebody + 3:ebody + 5], "big")
            start = ebody + 5
            if start + name_len > n:
                return None
            try:
                return p[start:start + name_len].decode("ascii")
            except Exception:
                return None
        off = ebody + elen
    return None


def is_tls_client_hello(payload: bytes) -> bool:
    """Teste rápido: é um registro TLS Handshake / ClientHello?"""
    return len(payload) >= 6 and payload[0] == TLS_CONTENT_HANDSHAKE \
        and payload[5] == TLS_HS_CLIENT_HELLO
