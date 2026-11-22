#!/usr/bin/env bash
# lib.sh — funções de apoio compartilhadas pelos scripts de experimento.
# Dirigem o laboratório Docker via `docker exec`. Funcionam em Linux e no
# Git Bash (Windows). Todos os ataques ocorrem DENTRO das redes Docker.

# No Git Bash (Windows), impede a conversão automática de caminhos POSIX
# (/app/...) para caminhos Windows (C:\...). Inofensivo em Linux.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

ATK=lab-attacker
VIC=lab-victim
GW=lab-gateway
WEB=lab-webserver

VICTIM_IP=172.30.0.10
GATEWAY_IP=172.30.0.2
IFACE=eth0

# Diretório de evidências dentro do atacante (montado em ../evidencias).
EVID=/app/evidencias

cor() { printf '\n\033[1;36m==== %s ====\033[0m\n' "$1"; }

# Garante que nenhum interceptador antigo esteja rodando.
parar_interceptador() {
  docker exec $ATK pkill -INT -f "interceptor" 2>/dev/null || true
  sleep 4   # tempo para a auto-cura concluir (rajadas ARP + restaurações)
  docker exec $ATK pkill -KILL -f "interceptor" 2>/dev/null || true
}

# Inicia o interceptador em background. $1 = diretório de saída.
iniciar_interceptador() {
  local outdir="$1"
  docker exec $ATK mkdir -p "$outdir"
  docker exec -d $ATK sh -c \
    "cd /app/src && PYTHONUNBUFFERED=1 python3 -u -m interceptor \
       --victim $VICTIM_IP --gateway $GATEWAY_IP -i $IFACE --interval 1 \
       --no-panel --outdir '$outdir' > '$outdir/interceptor_terminal.txt' 2>&1"
}

# Captura um snapshot RENDERIZADO do painel (sem --no-panel), por ~4s.
# $1 = arquivo de saída .txt
snapshot_painel() {
  local out="$1"
  docker exec -d $ATK sh -c \
    "cd /app/src && PYTHONUNBUFFERED=1 timeout 4 python3 -u -m interceptor \
       --victim $VICTIM_IP --gateway $GATEWAY_IP -i $IFACE --interval 1 \
       --outdir /tmp/painel_tmp > /tmp/painel_raw.ansi 2>&1 || true"
}

# Inicia tcpdump (evidência .pcap). $1 = caminho do pcap.
iniciar_tcpdump() {
  local pcap="$1"
  docker exec $ATK mkdir -p "$(dirname "$pcap")"
  docker exec -d $ATK sh -c "tcpdump -i $IFACE -w '$pcap' 2>/dev/null"
  sleep 1
}

parar_tcpdump() {
  docker exec $ATK pkill -INT tcpdump 2>/dev/null || true
  sleep 1
}

# Mostra as caches ARP dos três nós (evidência do envenenamento).
mostrar_arp() {
  echo "--- ARP vítima ---";  docker exec $VIC ip neigh show
  echo "--- ARP gateway ---"; docker exec $GW  ip neigh show
}

# Tráfego HTTP com cabeçalhos sensíveis (método, URI, UA, Cookie).
vitima_http() {
  docker exec $VIC curl -s -m 10 \
    -A "NavegadorVitima/1.0" -b "sessao=TOKEN_SECRETO_123" \
    "http://$1" >/dev/null 2>&1 || true
}

# Tráfego HTTPS (gera ClientHello com SNI). -k: aceita cert autoassinado.
vitima_https() {
  docker exec $VIC curl -s -k -m 10 \
    -A "NavegadorVitima/1.0" -b "sessao=TOKEN_SECRETO_123" \
    "https://$1" >/dev/null 2>&1 || true
}

# HTTPS SEM consulta DNS na rede (--resolve): emula, para o sniffer local,
# o efeito do DoH — a consulta UDP/53 não trafega, mas o SNI continua vazando.
vitima_https_sem_dns() {
  local host="$1"
  docker exec $VIC curl -s -k -m 10 --resolve "$host:443:172.31.0.80" \
    "https://$host/" >/dev/null 2>&1 || true
}
