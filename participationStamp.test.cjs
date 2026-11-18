const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const Database = require("better-sqlite3");
const { hmacHex, installVoteShareRoutes } = require("./voteShareGrants.cjs");
const { installParticipationStamp, stampRequestMessage, stampMessage, decodeStamp } = require("./participationStamp.cjs");

const enclave = crypto.generateKeyPairSync("ed25519");
const ENROLL_SECRET = "5e".repeat(32);
const COMMITMENT = crypto.createHash("sha256").update(Buffer.from(ENROLL_SECRET, "hex")).digest("hex");
const POLL = "6f0e0f8a-1111-4222-8333-944445555666";
const sha = (s) => crypto.createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");
const aliceHash = sha("P:USA:X123" + POLL);

function snapshot(voters, votes = voters.map((_, i) => ({ ballot_id: `ballot-${i}`, choices: ["yes"] }))) {
  const records = JSON.stringify({ contract: "shyvoting-inspection-v1", poll: { poll_id: POLL }, votes, voters: voters.map((identity_hash) => ({ identity_hash })) });
  return { height: 42, records, records_root: sha("shyvoting-state-v2:poll:" + POLL + "\0" + records) };
}

async function setup(ledger) {
  const routes = {};
  const app = { post: (p, h) => { routes[p] = h; } };
  const db = new Database(":memory:");
  const logged = [];
  installVoteShareRoutes(app, { db, privateKey: enclave.privateKey,
    checkDiditSession: async () => ({ status: "Approved", uid: "alice", vendor_data: JSON.stringify({ device_commitment: COMMITMENT }),
      id_verification: { document_type: "P", country: "USA", document_number: "X123" } }),
    firebaseUidOf: (d) => d.uid, documentKeyOf: (d) => `${d.id_verification.document_type}:${d.id_verification.country}:${d.id_verification.document_number}` });
  installParticipationStamp(app, { db, privateKey: enclave.privateKey, readInspection: async () => ledger, log: async (r) => logged.push(r) });
  const call = async (p, body) => {
    let status = 200, payload;
    await routes[p]({ body }, { set() {}, status(s) { status = s; return this; }, json(b) { payload = b; return this; } });
    return { status, body: payload };
  };
  const enrolled = (await call("/device-secret/enroll", { session_id: "s1", user_id: "alice", enrollment_secret: ENROLL_SECRET })).body;
  const ask = (overrides = {}) => {
    const timestamp = new Date().toISOString();
    const body = { user_id: "alice", device_id: enrolled.device_id, poll_id: POLL, timestamp, identity_key: enrolled.identity_key_hex, ...overrides };
    body.mac = overrides.mac || hmacHex(enrolled.secret_hex, stampRequestMessage(body.user_id, body.device_id, body.poll_id, timestamp));
    return call("/participation-stamp", body);
  };
  return { ask, logged };
}

test("a counted participant gets a stamp that names neither them nor their ballot", async () => {
  const ledger = snapshot(["aa".repeat(32), aliceHash, "bb".repeat(32)]);
  const { ask, logged } = await setup(ledger);
  const first = await ask(), second = await ask();
  assert.equal(first.status, 200);
  const stamp = decodeStamp(first.body.stamp);
  assert.equal(stamp.height, 42);
  assert.equal(stamp.recordsRoot, ledger.records_root);
  assert.equal(crypto.verify(null, Buffer.from(stampMessage(POLL, 42, ledger.records_root, stamp.nonceHex)), enclave.publicKey, Buffer.from(stamp.signatureHex, "hex")), true);
  assert.notEqual(first.body.stamp, second.body.stamp, "fresh nonce each time");
  for (const text of [first.body.stamp, JSON.stringify(first.body), JSON.stringify(logged)]) {
    assert.ok(!text.includes(aliceHash) && !text.includes("ballot-1"), "no identity hash or ballot anywhere");
  }
});

test("no stamp without a counted vote, a consistent ledger, or the device's proof", async () => {
  assert.equal((await (await setup(snapshot(["aa".repeat(32)]))).ask()).status, 404, "not a participant");
  const tampered = { ...snapshot([aliceHash]), records_root: "00".repeat(32) };
  assert.equal((await (await setup(tampered)).ask()).status, 404, "records don't match their commitment");
  const mismatch = snapshot([aliceHash, "aa".repeat(32)], [{ ballot_id: "ballot-0", choices: ["yes"] }]);
  assert.equal((await (await setup(mismatch)).ask()).status, 404, "count-match fails");
  const { ask } = await setup(snapshot([aliceHash]));
  assert.equal((await ask({ mac: "11".repeat(32) })).status, 403, "wrong device secret");
  assert.equal((await ask({ identity_key: "22".repeat(32) })).status, 403, "wrong identity key");
});
