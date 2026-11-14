// Proof Gatekeeper decision logic — pure, deterministic, no I/O.
// Checks run IN ORDER; the first failure names the trap.
//   1. proof_tx already in seen-set (APPROVE-only, per mode) -> PROOF_REUSED
//   2. proof_vk != registered_vk                          -> VK_SUBSTITUTION
//   3. public_balance < minimum                           -> THRESHOLD_MISMATCH
//   4. current_block >= expiry_block                      -> EXPIRED_CONDITION
//   5. recipient != condition_recipient                   -> RECIPIENT_MISMATCH
//   6. amount > max_transfer                              -> AMOUNT_OVERFLOW
//   7. else APPROVE                                       -> VALID_CONDITION
// Boundaries: amount == max APPROVEs, balance == min APPROVEs,
// expiry == current is EXPIRED. A REJECTED proof_tx reused later is decided
// fresh (it was never added to the seen-set).
// Malformed input -> REJECT PUBLIC_INPUT_MISMATCH (no proof attached).

const HEX40 = /^0x[0-9a-fA-F]{40}$/;
const HEX64 = /^0x[0-9a-fA-F]{64}$/;
const DEC = /^\d+$/;

export function validateGatekeeperInput(input) {
  if (!input || typeof input !== "object") return "input missing";
  const hexFields = [
    ["registered_vk", HEX64],
    ["proof_vk", HEX64],
    ["recipient", HEX40],
    ["condition_recipient", HEX40],
    ["proof_tx", HEX64],
  ];
  for (const [name, re] of hexFields) {
    if (typeof input[name] !== "string" || !re.test(input[name])) {
      return `field ${name} is not valid 0x hex`;
    }
  }
  for (const name of ["minimum", "public_balance", "amount", "max_transfer"]) {
    if (typeof input[name] !== "string" || !DEC.test(input[name])) {
      return `field ${name} is not a decimal string`;
    }
  }
  for (const name of ["expiry_block", "current_block"]) {
    if (
      typeof input[name] !== "number" ||
      !Number.isInteger(input[name]) ||
      input[name] < 0
    ) {
      return `field ${name} is not a non-negative integer`;
    }
  }
  return null;
}

/**
 * @param {object} input envelope input (validated)
 * @param {(proofTx: string) => boolean} hasSeen seen-set lookup (per mode)
 * @returns {{ decision: "APPROVE"|"REJECT", reason_code: string }}
 */
export function decideGatekeeper(input, hasSeen) {
  const bad = validateGatekeeperInput(input);
  if (bad) return { decision: "REJECT", reason_code: "PUBLIC_INPUT_MISMATCH" };

  // 1. Reuse — seen-set holds APPROVE-only proof_tx values.
  if (hasSeen(input.proof_tx)) {
    return { decision: "REJECT", reason_code: "PROOF_REUSED" };
  }
  // 2. VK substitution (case-insensitive hex compare).
  if (input.proof_vk.toLowerCase() !== input.registered_vk.toLowerCase()) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION" };
  }
  // 3. Balance below the required minimum.
  if (BigInt(input.public_balance) < BigInt(input.minimum)) {
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH" };
  }
  // 4. Condition expired (expiry == current counts as expired).
  if (input.current_block >= input.expiry_block) {
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION" };
  }
  // 5. Recipient mismatch.
  if (input.recipient.toLowerCase() !== input.condition_recipient.toLowerCase()) {
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH" };
  }
  // 6. Amount above the max transfer (amount == max is fine).
  if (BigInt(input.amount) > BigInt(input.max_transfer)) {
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW" };
  }
  // 7. Valid.
  return { decision: "APPROVE", reason_code: "VALID_CONDITION" };
}
