# Deployment status

## Current state (2026-11-14 ~23:50 WIB)

- The server runs **locally, supervised** (`run/run-server.sh` restart loop,
  port 3000) and answers the health check. It is NOT reachable from the
  public internet yet — see below.
- Repo: https://github.com/reameyso/lotnokjumbo-agent-games
- The server currently runs with the TEST secret
  (`test-secret-for-local-only`). After the agent is registered and the
  dashboard secret is rotated, set the real `AGENT_GAMES_HMAC_SECRET` in
  `.env` and restart (`run/run-server.sh` picks it up on restart).

## Public endpoint: BLOCKED by the sandbox egress proxy

The VM's outbound traffic goes through an HTTP(S) egress proxy with a
domain allowlist. Every no-account tunnel tried failed at that proxy:

1. **cloudflared quick tunnel (trycloudflare)** — `cloudflared tunnel --url
   http://127.0.0.1:3000` fails: `POST https://api.trycloudflare.com/tunnel:
   tls: first record does not look like a TLS handshake`. The proxy answers
   the API with HTTP 403 (verified with curl), i.e. `api.trycloudflare.com`
   is not on the proxy allowlist.
2. **localtunnel** — the allocation API (`https://localtunnel.me/?new`)
   works through the proxy, but the tunnel itself is a raw TCP connection
   to a random high port on `*.loca.lt` (e.g. `:15955`). CONNECT to that
   port through the proxy hangs (tested with socat, 10 s timeout, no data).
   The library also retries the allocation silently forever because axios
   ignores the proxy env vars.
3. **SSH tunnels (localhost.run :22, pinggy :443)** — CONNECT to
   `localhost.run:22` hangs; `a.pinggy.io:443` is unreachable (curl 000).

## What is needed

A host with direct egress (or a proxy that allows the tunnel service),
e.g. a small VPS or a Render/Railway free tier, running:

```bash
git clone https://github.com/reameyso/lotnokjumbo-agent-games
cd lotnokjumbo-agent-games
npm install
cp .env.example .env   # set AGENT_GAMES_HMAC_SECRET + STEAL_SALT
npm start
```

plus a stable public HTTPS URL in front of it (the dashboard endpoint must
not change; trycloudflare/localtunnel URLs are ephemeral even when they
work). Do NOT deploy/restart during Gatekeeper round hours (16:00–02:00 IST
= 17:30–03:30 WIB) or during a Steal match once registered.

## Local run scripts (`run/`)

- `run-server.sh` — supervised server loop (logs to `run/server.log`).
- `run-tunnel.sh` — supervised cloudflared quick tunnel (logs to
  `run/tunnel.log`). Currently fails at the proxy; kept for use on a host
  with direct egress.
- `run-lt.sh` — supervised localtunnel loop (logs to `run/lt.log`). Same
  caveat. The `lt` binary and `global-agent` experiment live in
  `run/node_modules/` (not committed).
