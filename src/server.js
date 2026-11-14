// Agent Games agent server — Proof Gatekeeper + Steal the VFY.
// Plain Node.js http server. No framework, no LLM in the decision path.
//
// Protocol summary:
// - GET (any path) -> 200 {"ok":true}
// - POST: x-agent-games-signature = hex HMAC-SHA256 over the RAW body.
//   Verified BEFORE parsing. 401 when no configured key matches, or when no
//   HMAC secret is configured at all.
// - Preflight  {type:"agent-games.preflight.v1"} -> {"ok":true,"protocolVersion":"v1"}
// - Gatekeeper {type:"agent-games.proof-gatekeeper.v1"} -> decision + proof
// - Steal      {eventId:"steal-the-vfy"} -> policy action + nested policyProof
// - Every response is signed with the key that verified the request.
// - Retries return the IDENTICAL stored response body (idempotency).
import http from "node:http";
import crypto from "node:crypto";
import { config } from "./config.js";
import { hmacHex, keyCandidates, verifySignature } from "./hmac.js";
import { createStore } from "./store.js";
import { decideGatekeeper } from "./decision.js";
import { Prover, buildGatekeeperInputs, withDeadline } from "./prover.js";
import { randomSalt31 } from "./field.js";
import {
  ACTION_CODE,
  buildStealInputs,
  computeCommitment,
  computePublicInputsHash,
  decideStealAction,
  publicInputsHashFromSignals,
  saltToDecimal,
  stealIdempotencyKey,
} from "./steal.js";

const PROOF_BUDGET_MS = 45_000;
const PROOF_MARGIN_MS = 5_000;
const MAX_BODY_BYTES = 1_000_000;

const store = createStore(config.dataDir);
const prover = new Prover(config.circuitsDir);

// Steal commitment (derived from env params + salt; the salt itself is
// never logged). Undefined when STEAL_SALT is not set -> Steal falls back
// to HOLD with a bare policyProof.
let stealCommitment = null;
if (config.stealSalt) {
  try {
    stealCommitment = computeCommitment(config.stealParams, config.stealSalt);
    console.log(`[steal] commitment ${stealCommitment}`);
  } catch (e) {
    console.error(`[steal] commitment failed: ${e.message}`);
  }
} else {
  console.warn("[steal] STEAL_SALT not set — Steal turns will fall back to HOLD");
}

if (!config.hmacSecret && !config.hmacSecretSteal) {
  console.warn(
    "[hmac] WARNING: no AGENT_GAMES_HMAC_SECRET configured — all POSTs will 401 until it is set",
  );
}

const secrets = [config.hmacSecret, config.hmacSecretSteal].filter(Boolean);

// In-flight map: idempotency key -> Promise<body>. Concurrent retries of
// the same task wait for the same answer instead of re-deciding/re-proving.
const inflight = new Map();

function sendJson(res, status, body, signKey) {
  const raw = Buffer.from(JSON.stringify(body), "utf8");
  const headers = { "content-type": "application/json" };
  if (signKey) headers["x-agent-games-signature"] = hmacHex(raw, signKey);
  res.writeHead(status, headers);
  res.end(raw);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

// ---------------------------------------------------------------------------
// Gatekeeper
// ---------------------------------------------------------------------------
async function handleGatekeeper(env) {
  const taskId = typeof env.task_id === "string" ? env.task_id : "";
  const mode = env.mode === "practice" ? "practice" : "competition";
  const key = `${mode}:${taskId}`;

  const cached = store.getResponse(key);
  if (cached) return cached.body;
  if (inflight.has(key)) return inflight.get(key);

  const work = (async () => {
    const input = env.input || {};
    const { decision, reason_code } = decideGatekeeper(input, (tx) =>
      store.hasSeen(mode, tx),
    );

    // The seen-set records proof_tx ONLY on APPROVE, per mode.
    if (decision === "APPROVE") store.markSeen(mode, input.proof_tx);

    const response = {
      decision,
      reason_code,
      proof_tx: typeof input.proof_tx === "string" ? input.proof_tx : undefined,
    };
    if (response.proof_tx === undefined) delete response.proof_tx;

    // PROOF_REUSED and malformed inputs carry no proof.
    const provable =
      reason_code !== "PROOF_REUSED" && reason_code !== "PUBLIC_INPUT_MISMATCH";
    if (provable) {
      const salt = randomSalt31();
      const inputs = buildGatekeeperInputs(input, taskId, decision, salt);
      // Proof budget: 45 s, keeping a 5 s margin before deadline_at.
      let budget = PROOF_BUDGET_MS;
      if (typeof env.deadline_at === "string") {
        const deadlineMs = Date.parse(env.deadline_at);
        if (Number.isFinite(deadlineMs)) {
          budget = Math.min(budget, deadlineMs - PROOF_MARGIN_MS - Date.now());
        }
      }
      if (budget > 0) {
        const result = await withDeadline(prover.gatekeeper(inputs), budget);
        if (result.ok) {
          response.proof = result.value.proof;
          response.public_signals = result.value.publicSignals;
        } else {
          // A failed proof NEVER changes the decision.
          console.warn(`[gatekeeper] proof failed for ${taskId}: ${result.reason}`);
        }
      } else {
        console.warn(`[gatekeeper] no proof budget left for ${taskId}`);
      }
      store.putResponse(key, response, salt);
    } else {
      store.putResponse(key, response, null);
    }
    return response;
  })();

  inflight.set(key, work);
  try {
    return await work;
  } finally {
    inflight.delete(key);
  }
}

// ---------------------------------------------------------------------------
// Steal the VFY
// ---------------------------------------------------------------------------
async function handleSteal(env) {
  const matchId = typeof env.matchId === "string" ? env.matchId : "";
  const turn = Number(env.turn);
  const key = `${matchId.toLowerCase()}:${turn}`;

  const cached = store.getSteal(key);
  if (cached) return cached.body;
  if (inflight.has(key)) return inflight.get(key);

  const work = (async () => {
    const state = env.state || {};
    const selfBalance = Number(state.selfBalance);
    const opponentBalance = Number(state.opponentBalance);
    const malformed =
      !/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(matchId) ||
      !Number.isInteger(turn) ||
      turn < 0 ||
      !Number.isFinite(selfBalance) ||
      selfBalance < 0 ||
      !Number.isFinite(opponentBalance) ||
      opponentBalance < 0;

    const fallback = (action) => ({
      protocolVersion: "v1",
      matchId,
      turn,
      action,
      policyProof: { circuitVersion: "v1" },
      agentTimestamp: new Date().toISOString(),
      idempotencyKey: stealIdempotencyKey(matchId, turn),
    });

    if (malformed || !stealCommitment) {
      if (malformed) console.warn(`[steal] malformed turn envelope for ${matchId}`);
      const body = fallback({ type: "HOLD" });
      store.putSteal(key, body);
      return body;
    }

    const action = decideStealAction(
      { selfBalance, opponentBalance },
      config.stealParams,
    );
    const amount = action.type === "EXTRACT" ? action.amount : 0;
    const actionCode = ACTION_CODE[action.type];

    const publicInputsHash = computePublicInputsHash({
      commitment: stealCommitment,
      matchId,
      turn,
      selfBalance,
      opponentBalance,
      actionCode,
      amount,
      circuitVersion: 1,
    });

    let proof = null;
    let publicSignals = null;
    try {
      const inputs = buildStealInputs({
        commitment: stealCommitment,
        matchId,
        turn,
        selfBalance,
        opponentBalance,
        action: action.type,
        amount,
        params: config.stealParams,
        saltDecimal: saltToDecimal(config.stealSalt),
      });
      const result = await withDeadline(prover.stealPolicy(inputs), PROOF_BUDGET_MS);
      if (result.ok) {
        proof = result.value.proof;
        publicSignals = result.value.publicSignals;
        // Cross-check: the hash recomputed from the circuit's 8 named
        // public signals (signals[1..8]) must equal the hash we send.
        try {
          const fromSignals = publicInputsHashFromSignals(publicSignals);
          if (fromSignals.toLowerCase() !== publicInputsHash.toLowerCase()) {
            console.warn(
              `[steal] publicInputsHash mismatch (signals ${fromSignals} != computed ${publicInputsHash}); falling back to HOLD`,
            );
            proof = null;
            publicSignals = null;
          }
        } catch (e) {
          console.warn(`[steal] hash cross-check failed: ${e.message}; falling back to HOLD`);
          proof = null;
          publicSignals = null;
        }
      } else {
        console.warn(`[steal] proof failed for ${matchId} turn ${turn}: ${result.reason}`);
      }
    } catch (e) {
      console.warn(`[steal] proof error for ${matchId} turn ${turn}: ${e.message}`);
    }

    let body;
    if (proof) {
      body = {
        protocolVersion: "v1",
        matchId,
        turn,
        action,
        policyProof: {
          circuitVersion: "v1",
          publicInputsHash,
          proof,
          public_signals: publicSignals,
        },
        agentTimestamp: new Date().toISOString(),
        idempotencyKey: stealIdempotencyKey(matchId, turn),
      };
    } else {
      // NEVER an unproven EXTRACT/FORTIFY.
      body = fallback({ type: "HOLD" });
    }
    store.putSteal(key, body);
    return body;
  })();

  inflight.set(key, work);
  try {
    return await work;
  } finally {
    inflight.delete(key);
  }
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET") {
      const key = secrets.length ? keyCandidates(secrets[0])[0] : null;
      return sendJson(res, 200, { ok: true }, key);
    }
    if (req.method !== "POST") {
      return sendJson(res, 405, { ok: false, error: "method_not_allowed" }, null);
    }

    const rawBody = await readBody(req);

    // HMAC is verified BEFORE parsing. No secret configured -> 401.
    if (secrets.length === 0) {
      console.warn("[hmac] POST rejected: no secret configured");
      return sendJson(res, 401, { ok: false, error: "hmac_not_configured" }, null);
    }
    const { ok, key } = verifySignature(
      rawBody,
      req.headers["x-agent-games-signature"],
      secrets,
    );
    if (!ok) {
      return sendJson(res, 401, { ok: false, error: "invalid_signature" }, null);
    }

    let env;
    try {
      env = JSON.parse(rawBody.toString("utf8"));
    } catch {
      return sendJson(res, 400, { ok: false, error: "invalid_json" }, key);
    }
    if (!env || typeof env !== "object") {
      return sendJson(res, 400, { ok: false, error: "invalid_envelope" }, key);
    }

    if (env.type === "agent-games.preflight.v1") {
      return sendJson(res, 200, { ok: true, protocolVersion: "v1" }, key);
    }
    if (env.type === "agent-games.proof-gatekeeper.v1") {
      const body = await handleGatekeeper(env);
      return sendJson(res, 200, body, key);
    }
    if (env.eventId === "steal-the-vfy") {
      const body = await handleSteal(env);
      return sendJson(res, 200, body, key);
    }
    return sendJson(res, 400, { ok: false, error: "unknown_envelope" }, key);
  } catch (e) {
    console.error("[server] error:", e);
    try {
      sendJson(res, 500, { ok: false, error: "internal_error" }, null);
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
  try {
    store.saveNow();
  } catch {}
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
