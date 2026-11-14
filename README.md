# lotnokjumbo-agent-games

Agent server for [Agent Games](https://agentgames.zkverify.io) (zkVerify, Season 01),
competitor handle **lotnokjumbo**. Two tracks on one endpoint:

- **Proof Gatekeeper** — deterministic 7-check decision on proof-transfer tasks,
  with a Groth16 proof (Circom/BN128) attached to every decision.
- **Steal the VFY** — threshold policy (FORTIFY / EXTRACT / HOLD) proven by the
  vfy-policy circuit against a Poseidon strategy commitment.

Plain Node.js, no framework, no LLM in the decision path. Decisions are
deterministic; a failed proof never changes a decision.

## Deploy

### Local / persistent host

```bash
npm install
cp .env.example .env   # fill in the secrets (see below)
npm start              # listens on $PORT (default 3000)
```

The JSON store (`./data` by default) keeps the seen-set and the response
cache on disk, so `PROOF_REUSED` detection survives restarts.

### Vercel (serverless, free tier)

The same code also runs as a Vercel serverless function — see
`api/agent.js` + `vercel.json`. Deploy from this repo (Vercel dashboard →
Add New → Project → import `reameyso/lotnokjumbo-agent-games`), then set
these env vars in Project Settings → Environment Variables:

| Variable | Meaning |
|---|---|
| `AGENT_GAMES_HMAC_SECRET` | **Required.** The real dashboard secret (Rotate Secret, shown once). Without it, all POSTs 401. |
| `AGENT_GAMES_HMAC_SECRET_STEAL` | Steal registration secret (only if the Steal track is registered) |
| `STEAL_SALT` / `STEAL_*` | Steal commitment inputs (only if the Steal track is registered) |

Endpoint: `https://<project>.vercel.app/api/agent` — register exactly this
path as the agent endpoint on the dashboard, then run preflight.

**Statelessness tradeoff (free tier):** Vercel functions are ephemeral —
the seen-set / response cache lives in memory + `/tmp` and does NOT
survive across instances. A `PROOF_REUSED` trap that lands on a fresh
instance may therefore be APPROVED instead of rejected (the earlier
APPROVE is not remembered cross-instance). Retry idempotency still holds:
the gatekeeper salt is deterministic per `(task_id, HMAC secret)`, so a
retry reproduces the identical proof and response body even on a fresh
instance. After registering the agent and rotating the secret, replace the
test secret with the real one in the Vercel env vars (never commit it).

Deploy-time checks that could not be verified locally: whether
`includeFiles: "circuits/**"` actually bundles the wasm/zkey/VK files into
the function (the code probes `repo/circuits`, `cwd/circuits`, and
`/var/task/circuits` at startup), the cold-start time (local proving is
~1.2 s; the function `maxDuration` is set to 60 s), and that Vercel
honours `bodyParser: false` for the raw-body HMAC check. Verify with a
signed preflight against the deployed URL right after the first deploy.

## Protocol

- `GET` any path → `200 {"ok":true}` (health check).
- `POST` → header `x-agent-games-signature` must be hex HMAC-SHA256 over the
  **raw** request body. The key is the secret as UTF-8 bytes, or hex-decoded
  to 32 bytes when the secret is 64 hex chars (both forms are tried).
  Responses are signed the same way, with the key that verified the request.
  `401` when no key matches — or when no secret is configured at all.
- Preflight `{type:"agent-games.preflight.v1"}` → `{"ok":true,"protocolVersion":"v1"}`.
- Gatekeeper `{type:"agent-games.proof-gatekeeper.v1"}` → `{decision, reason_code,
  proof?, public_signals?, proof_tx?}`.
- Steal `{eventId:"steal-the-vfy"}` → `{protocolVersion:"v1", matchId, turn,
  action, policyProof, agentTimestamp, idempotencyKey}` with the proof nested
  inside `policyProof` (never top-level).

Retries return the identical stored response body. Gatekeeper `proof_tx` is
recorded in the seen-set **only on APPROVE**, per mode, so a rejected proof
reused later is decided fresh.

### Gatekeeper decision order (first failure names the trap)

1. `proof_tx` already seen (APPROVE-only) → `PROOF_REUSED` (no proof)
2. `proof_vk != registered_vk` → `VK_SUBSTITUTION`
3. `public_balance < minimum` → `THRESHOLD_MISMATCH`
4. `current_block >= expiry_block` → `EXPIRED_CONDITION`
5. `recipient != condition_recipient` → `RECIPIENT_MISMATCH`
6. `amount > max_transfer` → `AMOUNT_OVERFLOW`
7. else `APPROVE` / `VALID_CONDITION`

Boundaries: `amount == max` approves, `balance == minimum` approves,
`expiry == current` is expired. Malformed input → `PUBLIC_INPUT_MISMATCH`.

Circuit inputs (13, decimal strings mod BN254 p): minimum, publicBalance,
amount, maxTransfer, recipient, conditionRecipient, expiryBlock,
currentBlock, taskId (= keccak256(taskId UTF-8) mod p), salt (fresh random
31 bytes per task, stored with the record), decision (1/0),
registeredVkHash, proofVkHash. The circuit's public signals are, in order:
Poseidon(salt, taskId), registeredVkHash, proofVkHash, minimum,
publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
amount, maxTransfer, decision, taskId. Proofs are verified locally against
the exported VK before being attached; proof budget 45 s with a 5 s margin
before `deadline_at`. The circuit itself also enforces the decision, so a
proof can only be generated for a consistent decision.

### Steal policy

`selfBalance < fortifyBelow` → FORTIFY; else `opponentBalance >
extractAbove` and not disabled → EXTRACT `extractAmount`; else HOLD.
Commitment = Poseidon9([extractAmount, fortifyBelow, extractAbove,
extractDisabled, 0, 0, 0, 0, salt]). `publicInputsHash` = keccak256 of the
8 named public inputs as 32-byte big-endian words (commitment, matchId,
turn, selfBalance, opponentBalance, actionCode, amount, circuitVersion).
`idempotencyKey` = UUIDv5 of `steal-the-vfy:{matchId}:{turn}` (namespace
`6ba7b811-9dad-11d1-80b4-00c04fd430c8`). The vfy-policy public signals are,
in order: a circuit-internal binding value, commitment, matchId, turnNumber,
selfBalance, opponentBalance, action, amount, circuitVersion. On any proof
failure the turn falls back to HOLD with a bare `policyProof`
`{circuitVersion:"v1"}` — never an unproven EXTRACT/FORTIFY.

## Environment

| Variable | Meaning |
|---|---|
| `PORT` | Listen port (default 3000) |
| `AGENT_GAMES_HMAC_SECRET` | Gatekeeper HMAC secret (dashboard → Rotate Secret, shown once) |
| `AGENT_GAMES_HMAC_SECRET_STEAL` | Steal HMAC secret (second registration; falls back to the main secret) |
| `STEAL_SALT` | 32-byte hex salt for the Steal commitment (generated once, never shared) |
| `STEAL_EXTRACT_AMOUNT` / `STEAL_FORTIFY_BELOW` / `STEAL_EXTRACT_ABOVE` / `STEAL_EXTRACT_DISABLED` | Strategy params (defaults 10 / 60 / 40 / 0; frozen once the commitment is registered) |
| `DATA_DIR` | Seen-set / response-cache store (default `./data`) |

The server 401s all POSTs until a secret is set. Never commit `.env`,
a secret, the salt, or the strategy params.

```bash
# Show the Steal commitment hash to register on the dashboard:
node scripts/commitment.mjs
```

## Tests

```bash
npm test   # decision unit tests, proof tests, preflight round-trip
```

- `test/decision.test.mjs` — all 7 traps, check order, boundaries, malformed input.
- `test/proof.test.mjs` — gatekeeper proof for a sample valid task, verified
  locally against the exported VK; asserts the 13 public signals.
- `test/steal.test.mjs` — policy, UUIDv5, commitment, publicInputsHash,
  vfy-policy proof + local verification + hash cross-check.
- `test/preflight.test.mjs` — signed preflight / gatekeeper / retry round-trip
  against a live server with a test-only secret, both key forms, and the
  no-secret 401 case.
- The Vercel handler (`api/agent.js`) was tested the same way via a
  throwaway script (deleted after): GET health, signed preflight,
  gatekeeper APPROVE with a locally verified proof using the deterministic
  salt, VK_SUBSTITUTION trap, and retry idempotency — all PASS.

## Layout

```
src/handler.js   shared request handler (local server + Vercel function)
src/server.js    HTTP server (thin wrapper over handler.js)
api/agent.js     Vercel serverless function (thin wrapper over handler.js)
api/env.js       Vercel env defaults (runs before any src/ import)
vercel.json      maxDuration 60, includeFiles circuits/**
src/decision.js  Gatekeeper decision logic (pure)
src/prover.js    snarkjs Groth16 proving + local verification
src/steal.js     Steal policy, commitment, hashes, UUIDv5
src/hmac.js      HMAC-SHA256 verify/sign (UTF-8 / hex key forms)
src/store.js     JSON store: seen-set + response cache
src/field.js     BN254 field helpers (+ deterministic gatekeeper salt)
circuits/        gatekeeper + vfy-policy wasm/zkey/VK (from agentgames.zkverify.io)
```

## Notes

- Proof generation takes ~1–1.5 s per proof on this host; the 45 s budget
  is ample. (snarkjs leaves worker threads alive after proving; that only
  delays process exit in one-shot scripts, not request handling.)
- Do not deploy/restart during Gatekeeper round hours (16:00–02:00 IST) or
  during a Steal match once registered.
