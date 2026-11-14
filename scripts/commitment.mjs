// Print the Steal strategy commitment hash (ONLY the hash).
// Usage: node scripts/commitment.mjs
// Reads STEAL_SALT + STEAL_* params from .env. The salt is never printed.
import { config } from "../src/config.js";
import { computeCommitment } from "../src/steal.js";

if (!config.stealSalt) {
  console.error("STEAL_SALT is not set in .env");
  process.exit(1);
}
console.log(computeCommitment(config.stealParams, config.stealSalt));
