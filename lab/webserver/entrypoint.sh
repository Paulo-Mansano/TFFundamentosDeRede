#!/bin/sh
set -e
# O webserver só está na srv_net; sua rota default é o gateway (.2),
# para conseguir responder à vítima que está na lab_net.
ip route replace default via 172.31.0.2 || true

# Gera um certificado TLS autoassinado cobrindo os domínios do laboratório.
CERT=/etc/nginx/lab.crt ; KEY=/etc/nginx/lab.key
if [ ! -f "$CERT" ]; then
  echo "[webserver] gerando certificado TLS autoassinado"
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$KEY" -out "$CERT" \
    -subj "/CN=lab" \
    -addext "subjectAltName=DNS:loja.lab,DNS:banco.lab,DNS:noticias.lab,DNS:video.lab,DNS:site-http.lab" \
    >/dev/null 2>&1
fi

# Conteúdo simples por site (para evidenciar Host/URI no HTTP).
mkdir -p /usr/share/nginx/html
echo "<h1>Loja Lab (HTTP em claro)</h1><p>pagina de teste</p>" > /usr/share/nginx/html/index.html
echo "[webserver] iniciando nginx (HTTP :80 e HTTPS :443 com SNI)"
exec nginx -g 'daemon off;'
