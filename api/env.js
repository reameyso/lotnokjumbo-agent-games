// Vercel env defaults. MUST be imported before any src/ module, because
// src/config.js reads process.env at import time. ES imports run in order,
// so api/agent.js imports this file first.
//
// - DATA_DIR: Vercel's filesystem is read-only except /tmp, so the JSON
//   store (seen-set + response cache) lives under /tmp. It is per-instance
//   and ephemeral — see the STATELESSNESS NOTE in src/handler.js.
// - AGENT_GAMES_HMAC_SECRET: defaults to the well-known TEST secret ONLY
//   when NOT running on Vercel (local testing convenience). On Vercel
//   (VERCEL=1) an unset secret stays unset and all POSTs 401 — set the real
//   dashboard secret in the Vercel project env vars instead.
// - CIRCUITS_DIR: resolved by probing candidate locations for
//   gatekeeper.wasm, because the bundled function layout on Vercel may
//   differ from the repo layout. Candidates: $CIRCUITS_DIR, repo/circuits,
//   cwd/circuits, /var/task/circuits (Lambda task root).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

if (!process.env.DATA_DIR) {
  process.env.DATA_DIR = "/tmp/agentgames-data";
}

if (process.env.VERCEL !== "1" && !process.env.AGENT_GAMES_HMAC_SECRET) {
  process.env.AGENT_GAMES_HMAC_SECRET = "test-secret-for-local-only";
}

if (!process.env.CIRCUITS_DIR) {
  const candidates = [
    path.join(ROOT, "circuits"),
    path.join(process.cwd(), "circuits"),
    "/var/task/circuits",
  ];
  for (const dir of candidates) {
    try {
      if (fs.existsSync(path.join(dir, "gatekeeper.wasm"))) {
        process.env.CIRCUITS_DIR = dir;
        break;
      }
    } catch {
      // Try the next candidate.
    }
  }
}
