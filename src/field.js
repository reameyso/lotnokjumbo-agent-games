// BN254 field helpers (Groth16 / bn128 curve order field).
export const BN254_P = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);

export function modP(n) {
  const v = BigInt(n) % BN254_P;
  return v >= 0n ? v : v + BN254_P;
}

/** 0x hex string -> field element (decimal string). */
export function hexToField(hex) {
  if (typeof hex !== "string" || !/^0x[0-9a-fA-F]+$/.test(hex)) {
    throw new Error(`not 0x hex: ${String(hex).slice(0, 40)}`);
  }
  return modP(BigInt(hex)).toString(10);
}

/** Decimal string / number / bigint -> field element (decimal string). */
export function decToField(v) {
  if (typeof v === "number") {
    if (!Number.isInteger(v) || v < 0) throw new Error("not a non-negative integer");
    return modP(BigInt(v)).toString(10);
  }
  if (typeof v === "bigint") return modP(v).toString(10);
  if (typeof v === "string" && /^\d+$/.test(v)) return modP(BigInt(v)).toString(10);
  throw new Error(`not a decimal integer: ${String(v).slice(0, 40)}`);
}

/** Random 31-byte salt as a field element (decimal string). */
export function randomSalt31() {
  const buf = new Uint8Array(31);
  globalThis.crypto.getRandomValues(buf);
  return modP(BigInt("0x" + Buffer.from(buf).toString("hex"))).toString(10);
}
