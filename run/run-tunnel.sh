#!/bin/bash
# Supervised Cloudflare quick tunnel (trycloudflare) -> local server.
# The public URL is printed to run/tunnel.log on start and CHANGES on
# every restart (trycloudflare assigns a random subdomain). If this
# process restarts, re-read run/tunnel.log for the new URL and update
# the dashboard endpoint.
cd "$(dirname "$0")" || exit 1
while true; do
  echo "[$(date -u +%FT%TZ)] starting tunnel -> http://127.0.0.1:${PORT:-3000}" >> tunnel.log
  ./cloudflared tunnel --url "http://127.0.0.1:${PORT:-3000}" >> tunnel.log 2>&1
  echo "[$(date -u +%FT%TZ)] tunnel exited (code $?); restarting in 5s" >> tunnel.log
  sleep 5
done
