#!/bin/sh
set -e
# O atacante é um host comum da lab_net: usa o gateway (.2) como rota default,
# para que, ao repassar (IP forward) o tráfego da vítima, ele saiba chegar ao
# gateway real e, por ele, ao webserver.
ip route replace default via 172.30.0.2 || true
echo "[attacker] pronto. Interface e rotas:"
ip -br addr ; ip route
exec sleep infinity
