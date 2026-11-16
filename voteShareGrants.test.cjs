const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const Database = require("better-sqlite3");
const { keyAttestationMessage, keyRequestMessage, verifyEd25519, hmacHex, installVoteShareRoutes } = require("./voteShareGrants.cjs");

const enclave = crypto.generateKeyPairSync("ed25519");
const enclavePub = enclave.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
const devicePub = crypto.generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");

function setup() {
  const routes = {};
  const app = { post: (p, h) => { routes[p] = h; } };
  const logged = [];
  installVoteShareRoutes(app, {
    db: new Database(":memory:"),
    privateKey: enclave.privateKey,
    checkDiditSession: async (id) => ({ status: id.startsWith("declined") ? "Declined" : "Approved", uid: "alice" }),
    firebaseUidOf: (d) => d.uid,
    log: async (r) => logged.push(r)
  });
  const call = async (p, body) => {
    let status = 200, payload;
    const res = { set() {}, status(s) { status = s; return this; }, json(b) { payload = b; return this; } };
    await routes[p]({ body }, res);
    return { status, body: payload };
  };
  return { call, logged };
}

function keyRequest(enrolled, { userId = "alice", pub = devicePub, timestamp = new Date().toISOString(), secret = enrolled.secret_hex } = {}) {
  return { user_id: userId, device_id: enrolled.device_id, pub_key: pub, timestamp,
    mac: hmacHex(secret, keyRequestMessage(userId, enrolled.device_id, pub, timestamp)) };
}

test("a verification enrolls one device, once; the session is useless after that", async () => {
  const { call } = setup();
  assert.equal((await call("/device-secret/enroll", { session_id: "declined-1", user_id: "alice" })).status, 403);
  assert.equal((await call("/device-secret/enroll", { session_id: "s1", user_id: "bob" })).status, 403, "alice's verification can't enroll bob");
  const first = await call("/device-secret/enroll", { session_id: "s1", user_id: "alice" });
  assert.equal(first.status, 200);
  assert.match(first.body.secret_hex, /^[0-9a-f]{64}$/);
  const again = await call("/device-secret/enroll", { session_id: "s1", user_id: "alice" });
  assert.equal(again.status, 409, "whoever learns the session id later gets nothing");
});

test("only the enrolled device's secret gets its key vouched for", async () => {
  const { call, logged } = setup();
  const enrolled = (await call("/device-secret/enroll", { session_id: "s1", user_id: "alice" })).body;
  const ok = await call("/vote-share/attest-key", keyRequest(enrolled));
  assert.equal(ok.status, 200);
  assert.equal(verifyEd25519(enclavePub, keyAttestationMessage("alice", devicePub), ok.body.key_attestation_sig), true);
  assert.equal((await call("/vote-share/attest-key", keyRequest(enrolled, { secret: "11".repeat(32) }))).status, 403, "wrong secret");
  assert.equal((await call("/vote-share/attest-key", keyRequest(enrolled, { userId: "bob" }))).status, 403, "another account");
  const stale = new Date(Date.now() - 3600e3).toISOString();
  assert.equal((await call("/vote-share/attest-key", keyRequest(enrolled, { timestamp: stale }))).status, 400, "replayed request");
  assert.ok(logged.every((r) => !("session_id" in r) && !("secret_hex" in r)), "neither the session nor the secret is logged");
});
