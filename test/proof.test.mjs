// Gatekeeper proof test: generate a proof for a sample VALID task and
// verify it locally with snarkjs against the exported verification key.
// Also asserts the 13 public signals match the expected circuit inputs.
// Run: node test/proof.test.mjs
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { poseidon2 } from "poseidon-lite";
import { Prover, buildGatekeeperInputs } from "../src/prover.js";
import { modP, randomSalt31 } from "../src/field.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const prover = new Prover(path.join(ROOT, "circuits"));

const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const input = {
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
  proof_tx: "0x" + "ff".repeat(32),
};
const taskId = "test-task-0001";
const salt = randomSalt31();

const inputs = buildGatekeeperInputs(input, taskId, "APPROVE", salt);
console.log("circuit inputs:", JSON.stringify(inputs, null, 2));

const t0 = Date.now();
const { proof, publicSignals } = await prover.gatekeeper(inputs);
console.log(`proof generated + locally verified in ${Date.now() - t0} ms`);

assert.equal(publicSignals.length, 13, "13 public signals expected");
// Circuit public-signal order, discovered empirically (two independent
// runs; the spec lists the INPUT names, not this order):
//   [0] Poseidon(salt, taskId)  [1] registeredVkHash  [2] proofVkHash
//   [3] minimum  [4] publicBalance  [5] expiryBlock  [6] currentBlock
//   [7] recipient  [8] conditionRecipient  [9] amount  [10] maxTransfer
//   [11] decision  [12] taskId
assert.equal(
  publicSignals[0],
  modP(poseidon2([BigInt(inputs.salt), BigInt(inputs.taskId)])).toString(10),
  "signals[0] must be Poseidon(salt, taskId)",
);
assert.equal(publicSignals[1], inputs.registeredVkHash);
assert.equal(publicSignals[2], inputs.proofVkHash);
assert.equal(publicSignals[3], inputs.minimum);
assert.equal(publicSignals[4], inputs.publicBalance);
assert.equal(publicSignals[5], inputs.expiryBlock);
assert.equal(publicSignals[6], inputs.currentBlock);
assert.equal(publicSignals[7], inputs.recipient);
assert.equal(publicSignals[8], inputs.conditionRecipient);
assert.equal(publicSignals[9], inputs.amount);
assert.equal(publicSignals[10], inputs.maxTransfer);
assert.equal(publicSignals[11], "1", "decision APPROVE = 1");
assert.equal(publicSignals[12], inputs.taskId);
assert.equal(proof.protocol, "groth16");
assert.equal(proof.curve, "bn128");
console.log("gatekeeper proof test: PASS");
process.exit(0);
