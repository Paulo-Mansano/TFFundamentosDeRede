#!/usr/bin/env bash
# Derruba o laboratório e remove as redes isoladas.
cd "$(dirname "$0")/.."
docker compose down
echo "[OK] Laboratório removido."
