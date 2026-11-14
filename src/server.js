// Agent Games agent server — Proof Gatekeeper + Steal the VFY.
// Plain Node.js http server. No framework, no LLM in the decision path.
// All protocol logic lives in src/handler.js (shared with the Vercel
// serverless function in api/agent.js); this file is only the HTTP transport.
import http from "node:http";
import { config } from "./config.js";
import { handleRequest, readRawBody, saveStateNow } from "./handler.js";

const server = http.createServer(async (req, res) => {
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
    console.error("[server] error:", e);
    try {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(Buffer.from(JSON.stringify({ ok: false, error: "internal_error" }), "utf8"));
    } catch {
      // Response already sent.
    }
  }
});

server.listen(config.port, () => {
  console.log(`[server] listening on :${config.port} (GET health, POST /agent)`);
});

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
function shutdown() {
  console.log("[server] shutting down");
  saveStateNow();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
