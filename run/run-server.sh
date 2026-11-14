#!/bin/bash
# Supervised Agent Games server: restarts node if it exits.
# Env: AGENT_GAMES_HMAC_SECRET must be set (exported here or in .env).
# NOTE: this run script is for the trycloudflare deployment. The HMAC
# secret below is a TEST-ONLY placeholder so the tunnel can be verified
# end-to-end; replace it with the real dashboard secret (in .env) after
# the agent is registered and the secret rotated, then restart.
cd "$(dirname "$0")/.." || exit 1
export AGENT_GAMES_HMAC_SECRET="${AGENT_GAMES_HMAC_SECRET:-test-secret-for-local-only}"
export PORT="${PORT:-3000}"
while true; do
  echo "[$(date -u +%FT%TZ)] starting server (port $PORT)" >> run/server.log
  node src/server.js >> run/server.log 2>&1
  echo "[$(date -u +%FT%TZ)] server exited (code $?); restarting in 3s" >> run/server.log
  sleep 3
done
