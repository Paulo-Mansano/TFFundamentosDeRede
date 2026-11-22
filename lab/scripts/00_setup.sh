#!/usr/bin/env bash
# Sobe o laboratório isolado e valida o baseline (sem ataque).
set -e
cd "$(dirname "$0")/.."
echo "[*] Construindo imagens..."; docker compose build
echo "[*] Subindo containers..."; docker compose up -d
sleep 5
echo "[*] Baseline — vítima resolve e navega via gateway:"
docker exec lab-victim getent hosts loja.lab
docker exec lab-victim curl -s -m 8 http://loja.lab/baseline && echo
docker exec lab-victim curl -s -k -m 8 https://banco.lab/ && echo
echo "[OK] Ambiente pronto."
