#!/usr/bin/env bash
# Experimento 3 — Avaliação do IP forwarding (espionagem vs blackhole/DoS).
set -e
cd "$(dirname "$0")"; . ./lib.sh
OUT=$EVID/exp3
cor "EXPERIMENTO 3 — IP forwarding (blackhole)"
parar_interceptador
docker exec $ATK sh -c "rm -f $OUT/* 2>/dev/null" || true
iniciar_tcpdump "$OUT/exp3.pcap"
iniciar_interceptador "$OUT"
echo "[*] aguardando o envenenamento ARP estabilizar..."; sleep 5

cor "FASE A — forwarding LIGADO: navegação deve FUNCIONAR"
docker exec $ATK sh -c "cat /proc/sys/net/ipv4/ip_forward" | sed 's/^/ip_forward=/'
if docker exec $VIC curl -s -k -m 8 https://loja.lab/ >/dev/null 2>&1; then
  echo "[RESULTADO] navegação OK (espionagem silenciosa)"
else
  echo "[RESULTADO] navegação FALHOU (inesperado na fase A)"
fi

cor "FASE B — desligando ip_forward no atacante (ip_forward=0)"
docker exec $ATK sh -c "echo 0 > /proc/sys/net/ipv4/ip_forward"
docker exec $ATK sh -c "cat /proc/sys/net/ipv4/ip_forward" | sed 's/^/ip_forward=/'
echo "[vitima] tentando navegar (deve dar TIMEOUT = blackhole/DoS)..."
if docker exec $VIC curl -s -k -m 8 https://loja.lab/ >/dev/null 2>&1; then
  echo "[RESULTADO] navegação OK (inesperado)"
else
  echo "[RESULTADO] navegação TRAVOU — ataque degradou para Negação de Serviço"
fi

cor "FASE C — religando ip_forward (ip_forward=1): navegação VOLTA"
docker exec $ATK sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
if docker exec $VIC curl -s -k -m 8 https://loja.lab/ >/dev/null 2>&1; then
  echo "[RESULTADO] navegação RESTABELECIDA"
else
  echo "[RESULTADO] navegação ainda falha (verificar)"
fi

sleep 2
parar_interceptador
parar_tcpdump
cor "Log do interceptador"
docker exec $ATK sh -c "cat $OUT/captura_*.log 2>/dev/null | tail -15"
echo "[OK] Evidências em evidencias/exp3/"
