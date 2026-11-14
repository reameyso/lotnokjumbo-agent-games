// Groth16 proving via snarkjs (gatekeeper + vfy-policy circuits).
// A failed proof NEVER changes the decision — callers return the decision
// without proof on any proving error or budget timeout.
import fs from "node:fs";
import path from "node:path";
import * as snarkjs from "snarkjs";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { decToField, hexToField, modP } from "./field.js";

function keccak256HexToField(utf8Str) {
  const digest = keccak_256(new TextEncoder().encode(utf8Str));
  return modP(BigInt("0x" + Buffer.from(digest).toString("hex"))).toString(10);
}

/** Build the 13 gatekeeper circuit inputs (all decimal strings, mod p). */
export function buildGatekeeperInputs(input, taskId, decision, salt) {
  return {
    minimum: decToField(input.minimum),
    publicBalance: decToField(input.public_balance),
    amount: decToField(input.amount),
    maxTransfer: decToField(input.max_transfer),
    recipient: hexToField(input.recipient),
    conditionRecipient: hexToField(input.condition_recipient),
    expiryBlock: decToField(input.expiry_block),
    currentBlock: decToField(input.current_block),
    taskId: keccak256HexToField(taskId),
    salt: decToField(salt),
    decision: decision === "APPROVE" ? "1" : "0",
    registeredVkHash: hexToField(input.registered_vk),
    proofVkHash: hexToField(input.proof_vk),
  };
}

export class Prover {
  constructor(circuitsDir) {
    this.circuitsDir = circuitsDir;
    this.gkWasm = path.join(circuitsDir, "gatekeeper.wasm");
    this.gkZkey = path.join(circuitsDir, "gatekeeper_final.zkey");
    this.gkVk = JSON.parse(
      fs.readFileSync(path.join(circuitsDir, "gatekeeper_vk.json"), "utf8"),
    );
    this.vfyWasm = path.join(circuitsDir, "vfy-policy.wasm");
    this.vfyZkey = path.join(circuitsDir, "vfy-policy_final.zkey");
    this.vfyVk = JSON.parse(
      fs.readFileSync(path.join(circuitsDir, "vfy-policy_vk.json"), "utf8"),
    );
  }

  /** Generate + locally verify a gatekeeper proof. Throws on any failure. */
  async gatekeeper(inputs) {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      inputs,
      this.gkWasm,
      this.gkZkey,
    );
    const ok = await snarkjs.groth16.verify(this.gkVk, publicSignals, proof);
    if (!ok) throw new Error("gatekeeper proof failed local verification");
    return { proof, publicSignals };
  }

  /** Generate + locally verify a vfy-policy proof. Throws on any failure. */
  async stealPolicy(inputs) {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      inputs,
      this.vfyWasm,
      this.vfyZkey,
    );
    const ok = await snarkjs.groth16.verify(this.vfyVk, publicSignals, proof);
    if (!ok) throw new Error("vfy-policy proof failed local verification");
    return { proof, publicSignals };
  }
}

/**
 * Run a promise with a hard deadline. Resolves { ok: true, value } or
 * { ok: false, reason: "timeout" }. The underlying work may keep running;
 * the caller must not await it afterwards.
 */
export function withDeadline(promise, ms) {
  return new Promise((resolve) => {
    let done = false;
    const timer = setTimeout(() => {
      if (!done) {
        done = true;
        resolve({ ok: false, reason: "timeout" });
      }
    }, Math.max(0, ms));
    promise.then(
      (value) => {
        if (!done) {
          done = true;
          clearTimeout(timer);
          resolve({ ok: true, value });
        }
      },
      (err) => {
        if (!done) {
          done = true;
          clearTimeout(timer);
          resolve({ ok: false, reason: err?.message || String(err) });
        }
      },
    );
  });
}
