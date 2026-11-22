#!/usr/bin/env bash
# Executa os 3 experimentos em sequência, com UMA captura global para a
# evidência captura_auditoria.pcap exigida no enunciado.
set -e
cd "$(dirname "$0")"; . ./lib.sh
cor "CAPTURA GLOBAL (captura_auditoria.pcap)"
docker exec $ATK pkill -INT tcpdump 2>/dev/null || true; sleep 1
docker exec -d $ATK sh -c "tcpdump -i $IFACE -w $EVID/captura_auditoria.pcap 2>/dev/null"
sleep 1
./exp1_http_vs_https.sh
./exp2_dns_https_correlacao.sh
./exp3_ip_forwarding.sh
docker exec $ATK pkill -INT tcpdump 2>/dev/null || true; sleep 1
cor "CONCLUÍDO — evidências em evidencias/"
ls -R ../evidencias 2>/dev/null || true
