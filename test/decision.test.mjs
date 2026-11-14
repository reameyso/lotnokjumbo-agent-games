// Decision-logic unit tests: all 7 traps + boundaries.
// Run: node --test test/decision.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import { decideGatekeeper } from "../src/decision.js";

const VK = "0x" + "ab".repeat(32);
const OTHER_VK = "0x" + "cd".repeat(32);
const ADDR = "0x" + "11".repeat(20);
const OTHER_ADDR = "0x" + "22".repeat(20);
const TX = "0x" + "ff".repeat(32);

function validInput(overrides = {}) {
  return {
    registered_vk: VK,
    proof_vk: VK,
    minimum: "100",
    public_balance: "100",
    expiry_block: 200,
    current_block: 100,
    recipient: ADDR,
    condition_recipient: ADDR,
    amount: "50",
    max_transfer: "50",
    proof_tx: TX,
    ...overrides,
  };
}

const neverSeen = () => false;
const alwaysSeen = () => true;

test("valid task APPROVEs", () => {
  const r = decideGatekeeper(validInput(), neverSeen);
  assert.equal(r.decision, "APPROVE");
  assert.equal(r.reason_code, "VALID_CONDITION");
});

test("trap 1: reused proof_tx REJECTs PROOF_REUSED", () => {
  const r = decideGatekeeper(validInput(), alwaysSeen);
  assert.equal(r.decision, "REJECT");
  assert.equal(r.reason_code, "PROOF_REUSED");
});

test("trap 2: VK substitution REJECTs VK_SUBSTITUTION", () => {
  const r = decideGatekeeper(validInput({ proof_vk: OTHER_VK }), neverSeen);
  assert.equal(r.reason_code, "VK_SUBSTITUTION");
});

test("trap 3: balance below minimum REJECTs THRESHOLD_MISMATCH", () => {
  const r = decideGatekeeper(validInput({ public_balance: "99" }), neverSeen);
  assert.equal(r.reason_code, "THRESHOLD_MISMATCH");
});

test("trap 4: expired condition REJECTs EXPIRED_CONDITION", () => {
  const r = decideGatekeeper(validInput({ current_block: 200 }), neverSeen);
  assert.equal(r.reason_code, "EXPIRED_CONDITION");
  const r2 = decideGatekeeper(validInput({ current_block: 201 }), neverSeen);
  assert.equal(r2.reason_code, "EXPIRED_CONDITION");
});

test("trap 5: recipient mismatch REJECTs RECIPIENT_MISMATCH", () => {
  const r = decideGatekeeper(validInput({ recipient: OTHER_ADDR }), neverSeen);
  assert.equal(r.reason_code, "RECIPIENT_MISMATCH");
});

test("trap 6: amount over max REJECTs AMOUNT_OVERFLOW", () => {
  const r = decideGatekeeper(validInput({ amount: "51" }), neverSeen);
  assert.equal(r.reason_code, "AMOUNT_OVERFLOW");
});

test("check order: reuse beats VK substitution", () => {
  const r = decideGatekeeper(validInput({ proof_vk: OTHER_VK }), alwaysSeen);
  assert.equal(r.reason_code, "PROOF_REUSED");
});

test("check order: VK beats threshold", () => {
  const r = decideGatekeeper(
    validInput({ proof_vk: OTHER_VK, public_balance: "0" }),
    neverSeen,
  );
  assert.equal(r.reason_code, "VK_SUBSTITUTION");
});

test("check order: threshold beats expiry", () => {
  const r = decideGatekeeper(
    validInput({ public_balance: "0", current_block: 999 }),
    neverSeen,
  );
  assert.equal(r.reason_code, "THRESHOLD_MISMATCH");
});

test("check order: expiry beats recipient", () => {
  const r = decideGatekeeper(
    validInput({ current_block: 999, recipient: OTHER_ADDR }),
    neverSeen,
  );
  assert.equal(r.reason_code, "EXPIRED_CONDITION");
});

test("check order: recipient beats amount", () => {
  const r = decideGatekeeper(
    validInput({ recipient: OTHER_ADDR, amount: "999" }),
    neverSeen,
  );
  assert.equal(r.reason_code, "RECIPIENT_MISMATCH");
});

test("boundary: amount == max APPROVEs", () => {
  const r = decideGatekeeper(validInput({ amount: "50", max_transfer: "50" }), neverSeen);
  assert.equal(r.decision, "APPROVE");
});

test("boundary: balance == minimum APPROVEs", () => {
  const r = decideGatekeeper(validInput({ public_balance: "100", minimum: "100" }), neverSeen);
  assert.equal(r.decision, "APPROVE");
});

test("boundary: expiry == current is EXPIRED", () => {
  const r = decideGatekeeper(validInput({ current_block: 200, expiry_block: 200 }), neverSeen);
  assert.equal(r.reason_code, "EXPIRED_CONDITION");
});

test("boundary: current one below expiry APPROVEs", () => {
  const r = decideGatekeeper(validInput({ current_block: 199, expiry_block: 200 }), neverSeen);
  assert.equal(r.decision, "APPROVE");
});

test("malformed: bad hex REJECTs PUBLIC_INPUT_MISMATCH", () => {
  const r = decideGatekeeper(validInput({ proof_vk: "not-hex" }), neverSeen);
  assert.equal(r.reason_code, "PUBLIC_INPUT_MISMATCH");
});

test("malformed: non-decimal amount REJECTs PUBLIC_INPUT_MISMATCH", () => {
  const r = decideGatekeeper(validInput({ amount: "10.5" }), neverSeen);
  assert.equal(r.reason_code, "PUBLIC_INPUT_MISMATCH");
});

test("malformed: missing field REJECTs PUBLIC_INPUT_MISMATCH", () => {
  const input = validInput();
  delete input.proof_tx;
  const r = decideGatekeeper(input, neverSeen);
  assert.equal(r.reason_code, "PUBLIC_INPUT_MISMATCH");
});

test("malformed: negative block REJECTs PUBLIC_INPUT_MISMATCH", () => {
  const r = decideGatekeeper(validInput({ current_block: -1 }), neverSeen);
  assert.equal(r.reason_code, "PUBLIC_INPUT_MISMATCH");
});

test("hex compare is case-insensitive", () => {
  const upper = (h) => h.slice(0, 2) + h.slice(2).toUpperCase();
  const r = decideGatekeeper(
    validInput({ proof_vk: upper(VK), recipient: upper(ADDR) }),
    neverSeen,
  );
  assert.equal(r.decision, "APPROVE");
});

test("big values: 10^30 amounts compare correctly", () => {
  const big = "1000000000000000000000000000000";
  const r = decideGatekeeper(
    validInput({ minimum: big, public_balance: big, amount: big, max_transfer: big }),
    neverSeen,
  );
  assert.equal(r.decision, "APPROVE");
  const r2 = decideGatekeeper(
    validInput({ minimum: big, public_balance: big, amount: big + "1", max_transfer: big }),
    neverSeen,
  );
  assert.equal(r2.reason_code, "AMOUNT_OVERFLOW");
});
