// The IDV enclave's part of retiring a chain: forget per-poll records.
//
//   node retire-polls.cjs            # counts only
//   node retire-polls.cjs --apply    # erases, in one transaction
//
// Poll IDs repeat when a deployment starts a new chain (Populist's are bill
// IDs), so the enclave's per-poll records from the retired chain would refuse
// or misroute the new chain's ballots: which per-poll key a Didit session was
// signed for (consumed_sessions) and the per-poll vote-recovery records.
//
// Kept: recovery_keys, device_secrets and their consumed-session guards. They
// belong to a person or a device, not a poll, and make keyless recovery work on
// any chain. Kept outside this database: the audit log bucket (an audit record).

const path = require("node:path");
const Database = require("better-sqlite3");

const DB_PATH = path.join(process.env.KEY_DIR || "/etc/populist-idv-enclave", "consumed-sessions.db");
const POLL_TABLES = ["consumed_sessions", "vote_recovery_sessions", "recovered_vote_devices", "authorized_vote_devices"];

const apply = process.argv.includes("--apply");
const db = new Database(DB_PATH, {fileMustExist: true});
const present = new Set(db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map(r => r.name));
const counts = POLL_TABLES.filter(t => present.has(t)).map(t => [t, db.prepare(`SELECT count(*) AS n FROM ${t}`).get().n]);
if (apply) {
  db.transaction(() => { for (const [t] of counts) db.prepare(`DELETE FROM ${t}`).run(); })();
}
for (const [t, n] of counts) console.log(`${t}: ${n} row(s)${apply && n ? " deleted" : ""}`);
for (const t of POLL_TABLES.filter(t => !present.has(t))) console.log(`${t}: (no table)`);
console.log(apply ? "done" : "(dry run: nothing changed; add --apply)");
