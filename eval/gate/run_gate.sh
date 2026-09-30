#!/usr/bin/env bash
# Self-contained release gate: spins a throwaway enforce stack (recommended
# posture: CRS score mode, engine decides), measures detection/FPR/latency
# against the gates, tears down, and leaves a report in eval/out/.
set -euo pipefail
cd "$(dirname "$0")/../.."

pick() { for p in "$@"; do ss -ltnH "sport = :$p" | grep -q . || { echo "$p"; return; }; done; }
PORT="$(pick 8090 8091 8092 8093)"
BASE_APP_PORT="$(pick 8190 8191 8192 8193)"

TMP="$(mktemp -d)"
trap 'docker compose -p sentinel-gate down -v >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT

cat > "$TMP/sentinel.yaml" <<Y
upstream: { url: "http://app:3000" }
mode: enforce
defaults: { crs: { mode: score } }
Y
cat > "$TMP/compose.yaml" <<Y
name: sentinel-gate
include:
  - path: $PWD/deploy/compose/sentinel.compose.yaml
    project_directory: .
services:
  app:
    image: bkimminich/juice-shop:v17.3.0
  app-baseline:
    image: bkimminich/juice-shop:v17.3.0
    ports: ["127.0.0.1:${BASE_APP_PORT}:3000"]
Y
echo "gate: bringing up enforce stack on :$PORT (baseline app :$BASE_APP_PORT)"
export SENTINEL_M2_RATE_MAX=100000000 SENTINEL_M2_FANOUT_MAX=100000000
( cd "$TMP" && SENTINEL_PUBLIC_PORT=$PORT SENTINEL_METRICS_ADDR=127.0.0.1:0 SENTINEL_M2_RATE_MAX=$SENTINEL_M2_RATE_MAX SENTINEL_M2_FANOUT_MAX=$SENTINEL_M2_FANOUT_MAX docker compose up -d --wait >/dev/null 2>&1 )
for _ in $(seq 1 40); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$PORT/ || true)" = 200 ] && break; sleep 2
done

python3 eval/gate/gate.py "http://127.0.0.1:$PORT" "http://127.0.0.1:$BASE_APP_PORT" eval/out
rc=$?
exit $rc
