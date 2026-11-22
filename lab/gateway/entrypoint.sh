#!/bin/sh
set -e
echo "[gateway] habilitando IP forwarding e roteamento entre lab_net e srv_net"
sysctl -w net.ipv4.ip_forward=1 >/dev/null
# Não enviar ICMP redirects (manteria rota direta e atrapalharia a didática).
sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null || true
echo "[gateway] rotas:"; ip route
echo "[gateway] iniciando dnsmasq (DNS *.lab -> 172.31.0.80)"
exec dnsmasq -k --conf-file=/etc/dnsmasq.conf
