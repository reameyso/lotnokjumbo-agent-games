// Preflight + HMAC + gatekeeper round-trip tests against a running server
// with a TEST secret only ("test-secret-for-local-only").
// Run: node test/preflight.test.mjs
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const TEST_SECRET = "test-secret-for-local-only";
const HEX_SECRET = "11".repeat(32); // 64 hex chars -> key is the 32 decoded bytes

function hmacHex(body, key) {
  return crypto.createHmac("sha256", key).update(body).digest("hex");
}

async function startServer(port, secret) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ag-test-"));
  const child = spawn(process.execPath, ["src/server.js"], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(port),
      AGENT_GAMES_HMAC_SECRET: secret,
      STEAL_SALT: "",
      DATA_DIR: dataDir,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let out = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (out += d));
  // Wait for the listening line.
  for (let i = 0; i < 50; i++) {
    if (out.includes("listening on")) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  if (!out.includes("listening on")) {
    child.kill();
    throw new Error("server did not start: " + out);
  }
  return { child, dataDir };
}

async function stopServer({ child, dataDir }) {
  child.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 300));
  fs.rmSync(dataDir, { recursive: true, force: true });
}

async function post(port, bodyObj, secret, { prefix = false, keyForm = "utf8" } = {}) {
  const raw = Buffer.from(JSON.stringify(bodyObj), "utf8");
  let key = Buffer.from(secret, "utf8");
  if (keyForm === "hex") key = Buffer.from(secret, "hex");
  let sig = hmacHex(raw, key);
  if (prefix) sig = "sha256=" + sig;
  const res = await fetch(`http://127.0.0.1:${port}/agent`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": sig },
    body: raw,
  });
  const text = await res.text();
  return { status: res.status, body: text, sigHeader: res.headers.get("x-agent-games-signature") };
}

function verifyResponseSignature(rawText, sigHeader, secret, keyForm = "utf8") {
  let key = Buffer.from(secret, "utf8");
  if (keyForm === "hex") key = Buffer.from(secret, "hex");
  return sigHeader === hmacHex(Buffer.from(rawText, "utf8"), key);
}

const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const gatekeeperTask = (taskId) => ({
  type: "agent-games.proof-gatekeeper.v1",
  task_id: taskId,
  mode: "practice",
  issued_at: new Date().toISOString(),
  deadline_at: new Date(Date.now() + 60000).toISOString(),
  input: {
    registered_vk: VK,
    proof_vk: VK,
    minimum: "100",
    public_balance: "500",
    expiry_block: 200,
    current_block: 100,
    recipient: "0x1111111111111111111111111111111111111111",
    condition_recipient: "0x1111111111111111111111111111111111111111",
    amount: "50",
    max_transfer: "50",
    proof_tx: "0x" + "aa".repeat(32),
  },
});

// --- Server 1: plain-text secret ---
{
  const srv = await startServer(3101, TEST_SECRET);
  try {
    // GET health check.
    const health = await fetch("http://127.0.0.1:3101/agent");
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { ok: true });
    console.log("GET health: PASS");

    // Unsigned POST -> 401.
    const unsigned = await fetch("http://127.0.0.1:3101/agent", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ type: "agent-games.preflight.v1" }),
    });
    assert.equal(unsigned.status, 401);
    console.log("unsigned POST 401: PASS");

    // Wrong secret -> 401.
    const wrong = await post(3101, { type: "agent-games.preflight.v1" }, "wrong-secret");
    assert.equal(wrong.status, 401);
    console.log("wrong-secret POST 401: PASS");

    // Preflight with correct secret (sha256= prefix) -> 200 + signed.
    const pre = await post(
      3101,
      { type: "agent-games.preflight.v1", agent_id: "test", issued_at: "x", nonce: "y" },
      TEST_SECRET,
      { prefix: true },
    );
    assert.equal(pre.status, 200);
    assert.deepEqual(JSON.parse(pre.body), { ok: true, protocolVersion: "v1" });
    assert.ok(verifyResponseSignature(pre.body, pre.sigHeader, TEST_SECRET));
    console.log("preflight round-trip + response signature: PASS");

    // Gatekeeper: APPROVE + proof attached + signed response.
    const gk = await post(3101, gatekeeperTask("roundtrip-1"), TEST_SECRET);
    assert.equal(gk.status, 200);
    const gkBody = JSON.parse(gk.body);
    assert.equal(gkBody.decision, "APPROVE");
    assert.equal(gkBody.reason_code, "VALID_CONDITION");
    assert.ok(gkBody.proof, "proof must be attached");
    assert.ok(Array.isArray(gkBody.public_signals) && gkBody.public_signals.length === 13);
    assert.ok(verifyResponseSignature(gk.body, gk.sigHeader, TEST_SECRET));
    console.log("gatekeeper APPROVE + proof + signature: PASS");

    // Retry of the same task returns the IDENTICAL body.
    const gk2 = await post(3101, gatekeeperTask("roundtrip-1"), TEST_SECRET);
    assert.equal(gk2.status, 200);
    assert.equal(gk2.body, gk.body, "retry must return the identical stored body");
    console.log("gatekeeper retry idempotency: PASS");

    // Reuse of the same proof_tx in a NEW task -> PROOF_REUSED, no proof.
    const gk3 = await post(3101, gatekeeperTask("roundtrip-2"), TEST_SECRET);
    assert.equal(JSON.parse(gk3.body).reason_code, "PROOF_REUSED");
    assert.ok(!JSON.parse(gk3.body).proof, "PROOF_REUSED must not attach a proof");
    console.log("gatekeeper PROOF_REUSED: PASS");
  } finally {
    await stopServer(srv);
  }
}

// --- Server 2: 64-hex-char secret (key = hex-decoded 32 bytes) ---
{
  const srv = await startServer(3102, HEX_SECRET);
  try {
    const pre = await post(
      3102,
      { type: "agent-games.preflight.v1" },
      HEX_SECRET,
      { keyForm: "hex" },
    );
    assert.equal(pre.status, 200, "hex-key preflight must verify");
    assert.ok(verifyResponseSignature(pre.body, pre.sigHeader, HEX_SECRET, "hex"));
    // The UTF-8 form of the same secret must ALSO verify (server tries both
    // key forms), and the response must be signed with the key that verified.
    const utf8Form = await post(3102, { type: "agent-games.preflight.v1" }, HEX_SECRET, {
      keyForm: "utf8",
    });
    assert.equal(utf8Form.status, 200, "utf8 form must also verify (both forms are tried)");
    assert.ok(verifyResponseSignature(utf8Form.body, utf8Form.sigHeader, HEX_SECRET, "utf8"));
    assert.ok(!verifyResponseSignature(utf8Form.body, utf8Form.sigHeader, HEX_SECRET, "hex"));
    console.log("hex-secret key form: PASS");
  } finally {
    await stopServer(srv);
  }
}

// --- Server 3: no secret at all -> all POSTs 401, GET still works ---
{
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ag-test-"));
  const child = spawn(process.execPath, ["src/server.js"], {
    cwd: ROOT,
    env: { ...process.env, PORT: "3103", AGENT_GAMES_HMAC_SECRET: "", AGENT_GAMES_HMAC_SECRET_STEAL: "", DATA_DIR: dataDir },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let out = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (out += d));
  for (let i = 0; i < 50; i++) {
    if (out.includes("listening on")) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  try {
    assert.ok(out.includes("WARNING"), "startup must warn when no secret is set");
    const health = await fetch("http://127.0.0.1:3103/agent");
    assert.equal(health.status, 200);
    const denied = await post(3103, { type: "agent-games.preflight.v1" }, TEST_SECRET);
    assert.equal(denied.status, 401);
    assert.equal(JSON.parse(denied.body).error, "hmac_not_configured");
    console.log("no-secret 401 + warning: PASS");
  } finally {
    child.kill("SIGTERM");
    await new Promise((r) => setTimeout(r, 300));
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
}

console.log("preflight round-trip tests: ALL PASS");
