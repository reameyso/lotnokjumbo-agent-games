#!/bin/bash
# Supervised localtunnel -> local server. The public URL is printed to
# lt.log on start and CHANGES on every restart (random subdomain unless a
# fixed --subdomain is reserved). If this restarts, re-read lt.log.
cd "$(dirname "$0")" || exit 1
while true; do
  echo "[$(date -u +%FT%TZ)] starting localtunnel -> http://127.0.0.1:${PORT:-3000}" >> lt.log
  ./node_modules/.bin/lt --port "${PORT:-3000}" --print-requests >> lt.log 2>&1
  echo "[$(date -u +%FT%TZ)] localtunnel exited (code $?); restarting in 5s" >> lt.log
  sleep 5
done
