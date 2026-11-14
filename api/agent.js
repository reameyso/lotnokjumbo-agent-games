// Vercel serverless function for the Agent Games agent.
// Endpoint: https://<project>.vercel.app/api/agent
//
// Thin adapter around src/handler.js (shared with the local HTTP server).
// The platform needs the RAW request body for HMAC verification, so the
// default JSON body parser is disabled (see `config` below) and the body
// is read from the stream directly.
//
// Env vars (set in the Vercel dashboard, Project Settings → Environment
// Variables — never commit them):
//   AGENT_GAMES_HMAC_SECRET        real dashboard secret (Rotate Secret)
//   AGENT_GAMES_HMAC_SECRET_STEAL  Steal registration secret (optional)
//   STEAL_SALT + STEAL_* params    only if the Steal track is registered
//   DATA_DIR / CIRCUITS_DIR        normally unset (defaults in api/env.js)
//
// STATELESSNESS: Vercel functions are ephemeral — the seen-set / response
// cache lives in memory + /tmp and does NOT survive across instances. A
// PROOF_REUSED trap that lands on a fresh instance may therefore be
// APPROVED (accepted free-tier tradeoff, see src/handler.js). Retry
// idempotency still holds: the gatekeeper salt is deterministic per
// (task_id, HMAC secret), so retries reproduce identical proofs.
import "./env.js";
import { handleRequest, readRawBody } from "../src/handler.js";

// Disable Vercel's default JSON body parser: HMAC is verified over the
// RAW body, so the function must receive the stream untouched.
export const config = {
  api: {
    bodyParser: false,
  },
};

export default async function handler(req, res) {
  try {
    const rawBody = req.method === "POST" ? await readRawBody(req) : Buffer.alloc(0);
    const { status, headers, body } = await handleRequest({
      method: req.method,
      headers: req.headers,
      rawBody,
    });
    res.writeHead(status, headers);
    res.end(body);
  } catch (e) {
    console.error("[vercel] error:", e);
    try {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(Buffer.from(JSON.stringify({ ok: false, error: "internal_error" }), "utf8"));
    } catch {
      // Response already sent.
    }
  }
}
