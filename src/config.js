// Minimal .env loader + config. No external deps.
// Env vars (see .env.example):
//   PORT, AGENT_GAMES_HMAC_SECRET, AGENT_GAMES_HMAC_SECRET_STEAL,
//   STEAL_SALT, STEAL_EXTRACT_AMOUNT, STEAL_FORTIFY_BELOW,
//   STEAL_EXTRACT_ABOVE, STEAL_EXTRACT_DISABLED, DATA_DIR
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export function loadDotEnv(file = path.join(ROOT, ".env")) {
  try {
    const text = fs.readFileSync(file, "utf8");
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eq = trimmed.indexOf("=");
      if (eq === -1) continue;
      const key = trimmed.slice(0, eq).trim();
      let val = trimmed.slice(eq + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      if (!(key in process.env)) process.env[key] = val;
    }
  } catch {
    // No .env file — env vars only.
  }
}

loadDotEnv();

const intEnv = (name, def) => {
  const v = process.env[name];
  if (v === undefined || v === "") return def;
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? n : def;
};

export const config = {
  root: ROOT,
  port: intEnv("PORT", 3000),
  hmacSecret: process.env.AGENT_GAMES_HMAC_SECRET || "",
  hmacSecretSteal: process.env.AGENT_GAMES_HMAC_SECRET_STEAL || "",
  stealSalt: process.env.STEAL_SALT || "",
  stealParams: {
    extractAmount: intEnv("STEAL_EXTRACT_AMOUNT", 10),
    fortifyBelow: intEnv("STEAL_FORTIFY_BELOW", 60),
    extractAbove: intEnv("STEAL_EXTRACT_ABOVE", 40),
    extractDisabled: intEnv("STEAL_EXTRACT_DISABLED", 0),
  },
  dataDir: process.env.DATA_DIR || path.join(ROOT, "data"),
  circuitsDir: path.join(ROOT, "circuits"),
};
