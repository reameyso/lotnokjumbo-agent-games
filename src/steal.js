// Steal the VFY: threshold policy, Poseidon commitment, publicInputsHash,
// UUIDv5 idempotency key, and vfy-policy circuit inputs.
// Policy (thresholds are the operator's choice, frozen in the commitment):
//   selfBalance < fortifyBelow            -> FORTIFY
//   opponentBalance > extractAbove && !extractDisabled -> EXTRACT extractAmount
//   else                                  -> HOLD
// Fallback (no commitment / proof failure): HOLD with a bare policyProof
// {circuitVersion:"v1"} — NEVER an unproven EXTRACT/FORTIFY.
import crypto from "node:crypto";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { poseidon9 } from "poseidon-lite";
import { decToField, hexToField, modP } from "./field.js";

export const ACTION_CODE = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 };
export const UUID_NAMESPACE_DNS = "6ba7b811-9dad-11d1-80b4-00c04fd430c8";

/**
 * Normalize a Steal salt to a decimal string. Accepts 0x-prefixed hex,
 * bare 64-hex-char strings, or plain decimal strings.
 */
export function saltToDecimal(salt) {
  const s = String(salt).trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s).toString(10);
  if (/^[0-9a-fA-F]{64}$/.test(s)) return BigInt("0x" + s).toString(10);
  if (/^\d+$/.test(s)) return BigInt(s).toString(10);
  throw new Error("STEAL_SALT must be hex (64 chars, optional 0x) or decimal");
}

export function decideStealAction(state, params) {
  const self = Number(state.selfBalance);
  const opp = Number(state.opponentBalance);
  if (self < params.fortifyBelow) return { type: "FORTIFY" };
  if (opp > params.extractAbove && !params.extractDisabled) {
    return { type: "EXTRACT", amount: params.extractAmount };
  }
  return { type: "HOLD" };
}

/** UUIDv5 (SHA-1) of a name under a namespace UUID. */
export function uuidv5(name, namespace = UUID_NAMESPACE_DNS) {
  const nsBytes = Buffer.from(namespace.replace(/-/g, ""), "hex");
  const hash = crypto
    .createHash("sha1")
    .update(Buffer.concat([nsBytes, Buffer.from(name, "utf8")]))
    .digest();
  hash[6] = (hash[6] & 0x0f) | 0x50; // version 5
  hash[8] = (hash[8] & 0x3f) | 0x80; // variant RFC 4122
  const hex = hash.subarray(0, 16).toString("hex");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join("-");
}

export function stealIdempotencyKey(matchId, turn) {
  return uuidv5(`steal-the-vfy:${String(matchId).toLowerCase()}:${turn}`);
}

/**
 * Commitment = Poseidon9([p1,p2,p3,p4,0,0,0,0,salt]) as 0x + 64 hex digits.
 * strategyParams are the 4 policy values + 4 zero padding slots.
 */
export function computeCommitment(params, salt) {
  const saltDec = saltToDecimal(salt);
  const saltField = BigInt(decToField(saltDec));
  const inputs = [
    BigInt(params.extractAmount),
    BigInt(params.fortifyBelow),
    BigInt(params.extractAbove),
    BigInt(params.extractDisabled),
    0n, 0n, 0n, 0n,
    modP(saltField),
  ];
  const out = poseidon9(inputs);
  return "0x" + modP(out).toString(16).padStart(64, "0");
}

/**
 * publicInputsHash = keccak256 of 8 words, each 32-byte big-endian, in order:
 * commitment, matchId (UUID dashes removed -> BigInt), turn, selfBalance,
 * opponentBalance, actionCode, amount, circuitVersion (1). Returned 0x hex.
 */
export function computePublicInputsHash({
  commitment,
  matchId,
  turn,
  selfBalance,
  opponentBalance,
  actionCode,
  amount,
  circuitVersion = 1,
}) {
  const words = Buffer.concat([
    word256(BigInt(commitment)),
    word256(BigInt("0x" + String(matchId).replace(/-/g, ""))),
    word256(turn),
    word256(selfBalance),
    word256(opponentBalance),
    word256(actionCode),
    word256(amount),
    word256(circuitVersion),
  ]);
  return "0x" + Buffer.from(keccak_256(words)).toString("hex");
}

const word256 = (v) => {
  const b = BigInt(v);
  if (b < 0n || b >= 1n << 256n) throw new Error("word out of range");
  return Buffer.from(b.toString(16).padStart(64, "0"), "hex");
};

/**
 * Recompute the publicInputsHash from the circuit's public signals.
 * The 8 named public inputs are signals[1..8] (signals[0] is a
 * circuit-internal binding value); the hash is keccak256 over those 8
 * words, each 32-byte big-endian, in circuit order.
 */
export function publicInputsHashFromSignals(publicSignals) {
  if (!Array.isArray(publicSignals) || publicSignals.length !== 9) {
    throw new Error("expected 9 public signals");
  }
  const words = Buffer.concat(publicSignals.slice(1).map((s) => word256(BigInt(s))));
  return "0x" + Buffer.from(keccak_256(words)).toString("hex");
}

/** Build the vfy-policy circuit inputs (decimal strings, mod p). */
export function buildStealInputs({
  commitment,
  matchId,
  turn,
  selfBalance,
  opponentBalance,
  action,
  amount,
  params,
  saltDecimal,
}) {
  const strategyParams = [
    String(params.extractAmount),
    String(params.fortifyBelow),
    String(params.extractAbove),
    String(params.extractDisabled),
    "0", "0", "0", "0",
  ];
  return {
    commitment: hexToField(commitment),
    matchId: modP(BigInt("0x" + String(matchId).replace(/-/g, ""))).toString(10),
    turnNumber: decToField(turn),
    selfBalance: decToField(selfBalance),
    opponentBalance: decToField(opponentBalance),
    action: decToField(ACTION_CODE[action]),
    amount: decToField(amount),
    circuitVersion: "1",
    strategyParams,
    salt: decToField(saltDecimal),
  };
}
