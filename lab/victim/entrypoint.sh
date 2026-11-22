#!/bin/sh
set -e
# A vítima roteia TUDO pelo gateway do laboratório (.2) e usa-o como DNS.
ip route replace default via 172.30.0.2 || true
echo "nameserver 172.30.0.2" > /etc/resolv.conf
echo "[victim] rota default -> 172.30.0.2 ; DNS -> 172.30.0.2"
ip route
exec sleep infinity
