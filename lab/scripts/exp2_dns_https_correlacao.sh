#!/usr/bin/env bash
# Experimento 2 — Correlação DNS -> HTTPS (4 sites) e efeito do DoH.
set -e
cd "$(dirname "$0")"; . ./lib.sh
OUT=$EVID/exp2
cor "EXPERIMENTO 2 — Correlação DNS -> HTTPS"
parar_interceptador
docker exec $ATK sh -c "rm -f $OUT/* 2>/dev/null" || true
iniciar_tcpdump "$OUT/exp2.pcap"
iniciar_interceptador "$OUT"
echo "[*] aguardando o envenenamento ARP estabilizar..."; sleep 5
cor "Acessando 4 sites distintos (DNS em claro + SNI)"
for s in loja.lab banco.lab noticias.lab video.lab; do
  echo "[vitima] HTTPS -> $s"; vitima_https "$s/"; sleep 1
done
sleep 2
cor "Agora com efeito do DoH (sem consulta UDP/53 na rede), SNI ainda vaza"
echo "[vitima] HTTPS (sem DNS) -> loja.lab"
vitima_https_sem_dns "loja.lab"
sleep 3
parar_interceptador
parar_tcpdump
cor "Linha do tempo capturada (captura_*.log)"
docker exec $ATK sh -c "cat $OUT/captura_*.log"
cor "Resumo consolidado (resumo_*.csv)"
docker exec $ATK sh -c "cat $OUT/resumo_*.csv"
echo "[OK] Evidências em evidencias/exp2/"
