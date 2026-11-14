// HMAC-SHA256 (hex) over raw request/response bodies.
// Key rule: the secret is used as UTF-8 bytes, OR hex-decoded to 32 bytes
// when the secret is exactly 64 hex chars. Both forms are tried on verify;
// responses are signed with the key that verified the request.
import crypto from "node:crypto";

export function keyCandidates(secret) {
  const keys = [];
  if (!secret) return keys;
  keys.push(Buffer.from(secret, "utf8"));
  if (/^[0-9a-fA-F]{64}$/.test(secret)) {
    const hexKey = Buffer.from(secret, "hex");
    if (!hexKey.equals(keys[0])) keys.push(hexKey);
  }
  return keys;
}

export function hmacHex(body, key) {
  return crypto.createHmac("sha256", key).update(body).digest("hex");
}

function safeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/**
 * Verify the x-agent-games-signature header against the raw body.
 * @param {Buffer} body raw request body
 * @param {string|undefined} header header value (optional "sha256=" prefix)
 * @param {string[]} secrets configured secrets (main first, steal second)
 * @returns {{ ok: boolean, key: Buffer|null }} key = the key that matched
 */
export function verifySignature(body, header, secrets) {
  if (!header || typeof header !== "string") return { ok: false, key: null };
  let sig = header.trim();
  if (sig.toLowerCase().startsWith("sha256=")) sig = sig.slice(7);
  if (!/^[0-9a-fA-F]{64}$/.test(sig)) return { ok: false, key: null };
  const sigLower = sig.toLowerCase();
  for (const secret of secrets) {
    for (const key of keyCandidates(secret)) {
      if (safeEqualHex(hmacHex(body, key), sigLower)) {
        return { ok: true, key };
      }
    }
  }
  return { ok: false, key: null };
}
