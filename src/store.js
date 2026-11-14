// JSON file store: seen-set (APPROVE-only proof_tx, per mode) + idempotent
// response cache + per-task salt. Atomic writes (tmp file + rename).
// State shape:
// {
//   seen: { competition: ["0x..."], practice: ["0x..."] },
//   responses: { "<mode>:<task_id>": { body, salt } },
//   steal: { "<matchId>:<turn>": { body } }
// }
import fs from "node:fs";
import path from "node:path";

export function createStore(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });
  const file = path.join(dataDir, "state.json");
  let state = { seen: { competition: [], practice: [] }, responses: {}, steal: {} };
  try {
    const raw = fs.readFileSync(file, "utf8");
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") {
      state.seen = parsed.seen && typeof parsed.seen === "object" ? parsed.seen : state.seen;
      state.seen.competition = Array.isArray(state.seen.competition) ? state.seen.competition : [];
      state.seen.practice = Array.isArray(state.seen.practice) ? state.seen.practice : [];
      state.responses = parsed.responses && typeof parsed.responses === "object" ? parsed.responses : {};
      state.steal = parsed.steal && typeof parsed.steal === "object" ? parsed.steal : {};
    }
  } catch {
    // Missing or corrupt file: start empty (a corrupt file is overwritten
    // on the next save; the previous state is not recoverable here).
  }

  let saveTimer = null;
  function save() {
    const tmp = file + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(state), "utf8");
    fs.renameSync(tmp, file);
  }
  // Debounced save so bursts of tasks don't fsync on every write; a final
  // synchronous save happens on process exit via saveNow().
  function saveSoon() {
    if (saveTimer) return;
    saveTimer = setTimeout(() => {
      saveTimer = null;
      try {
        save();
      } catch (e) {
        console.error("[store] save failed:", e.message);
      }
    }, 200);
  }

  const normTx = (tx) => String(tx).trim().toLowerCase();

  return {
    state,
    hasSeen(mode, proofTx) {
      const set = state.seen[mode] || [];
      return set.includes(normTx(proofTx));
    },
    markSeen(mode, proofTx) {
      if (!state.seen[mode]) state.seen[mode] = [];
      const tx = normTx(proofTx);
      if (!state.seen[mode].includes(tx)) {
        state.seen[mode].push(tx);
        saveSoon();
      }
    },
    getResponse(key) {
      return state.responses[key] || null;
    },
    putResponse(key, body, salt) {
      state.responses[key] = { body, salt };
      saveSoon();
    },
    getSteal(key) {
      return state.steal[key] || null;
    },
    putSteal(key, body) {
      state.steal[key] = { body };
      saveSoon();
    },
    saveNow() {
      if (saveTimer) {
        clearTimeout(saveTimer);
        saveTimer = null;
      }
      save();
    },
  };
}

// In-memory-only store with the same interface as createStore().
// Used when the file store cannot be created (e.g. a read-only or
// missing DATA_DIR on a serverless host): the agent keeps working, it
// just loses persistence across restarts. Never throws.
export function createMemoryStore() {
  const state = { seen: { competition: [], practice: [] }, responses: {}, steal: {} };
  const normTx = (tx) => String(tx).trim().toLowerCase();
  return {
    state,
    hasSeen(mode, proofTx) {
      const set = state.seen[mode] || [];
      return set.includes(normTx(proofTx));
    },
    markSeen(mode, proofTx) {
      if (!state.seen[mode]) state.seen[mode] = [];
      const tx = normTx(proofTx);
      if (!state.seen[mode].includes(tx)) state.seen[mode].push(tx);
    },
    getResponse(key) {
      return state.responses[key] || null;
    },
    putResponse(key, body, salt) {
      state.responses[key] = { body, salt };
    },
    getSteal(key) {
      return state.steal[key] || null;
    },
    putSteal(key, body) {
      state.steal[key] = { body };
    },
    saveNow() {},
  };
}
