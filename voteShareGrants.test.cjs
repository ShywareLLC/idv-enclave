const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const Database = require("better-sqlite3");
const { keyAttestationMessage, keyRequestMessage, ballotKeyRequestMessage, verifyEd25519, hmacHex, installVoteShareRoutes } = require("./voteShareGrants.cjs");

const enclave = crypto.generateKeyPairSync("ed25519");
const enclavePub = enclave.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
const ENROLL_SECRET = "5e".repeat(32);
const COMMITMENT = crypto.createHash("sha256").update(Buffer.from(ENROLL_SECRET, "hex")).digest("hex");
const devicePub = crypto.generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");

function setup() {
  const routes = {};
  const app = { post: (p, h) => { routes[p] = h; } };
  const logged = [];
  installVoteShareRoutes(app, {
    db: new Database(":memory:"),
    privateKey: enclave.privateKey,
    checkDiditSession: async (id) => ({ status: id.startsWith("declined") ? "Declined" : "Approved", uid: "alice",
      vendor_data: JSON.stringify({ userId: "alice", device_commitment: COMMITMENT }),
      id_verification: { document_type: "P", country: "USA", document_number: "X123" } }),
    firebaseUidOf: (d) => d.uid,
    documentKeyOf: (d) => `${d.id_verification.document_type}:${d.id_verification.country}:${d.id_verification.document_number}`,
    log: async (r) => logged.push(r),
    logAttest: async (r) => logged.push(r)
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
  assert.equal((await call("/device-secret/enroll", { session_id: "declined-1", user_id: "alice", enrollment_secret: ENROLL_SECRET })).status, 403);
  assert.equal((await call("/device-secret/enroll", { session_id: "s1", user_id: "bob", enrollment_secret: ENROLL_SECRET })).status, 403, "alice's verification can't enroll bob");
  const first = await call("/device-secret/enroll", { session_id: "s1", user_id: "alice", enrollment_secret: ENROLL_SECRET });
  assert.equal(first.status, 200);
  assert.match(first.body.secret_hex, /^[0-9a-f]{64}$/);
  const again = await call("/device-secret/enroll", { session_id: "s1", user_id: "alice", enrollment_secret: ENROLL_SECRET });
  assert.equal(again.status, 409, "whoever learns the session id later gets nothing");
});

test("only the enrolled device's secret gets its key vouched for", async () => {
  const { call, logged } = setup();
  const enrolled = (await call("/device-secret/enroll", { session_id: "s1", user_id: "alice", enrollment_secret: ENROLL_SECRET })).body;
  const ok = await call("/vote-share/attest-key", keyRequest(enrolled));
  assert.equal(ok.status, 200);
  assert.equal(verifyEd25519(enclavePub, keyAttestationMessage("alice", devicePub), ok.body.key_attestation_sig), true);
  assert.equal((await call("/vote-share/attest-key", keyRequest(enrolled, { secret: "11".repeat(32) }))).status, 403, "wrong secret");
  assert.equal((await call("/vote-share/attest-key", keyRequest(enrolled, { userId: "bob" }))).status, 403, "another account");
  const stale = new Date(Date.now() - 3600e3).toISOString();
  assert.equal((await call("/vote-share/attest-key", keyRequest(enrolled, { timestamp: stale }))).status, 400, "replayed request");
  assert.ok(logged.every((r) => !("session_id" in r) && !("secret_hex" in r)), "neither the session nor the secret is logged");
});

test("ballot keys need the enrolled device and its identity key, never a session id", async () => {
  const { call, logged } = setup();
  const enrolled = (await call("/device-secret/enroll", { session_id: "s1", user_id: "alice", enrollment_secret: ENROLL_SECRET })).body;
  assert.match(enrolled.identity_key_hex, /^[0-9a-f]{64}$/);
  const ballot = ({ secret = enrolled.secret_hex, identityKey = enrolled.identity_key_hex, poll = "poll-1" } = {}) => {
    const timestamp = new Date().toISOString();
    return { user_id: "alice", device_id: enrolled.device_id, voter_pub_key: devicePub, poll_id: poll, timestamp, identity_key: identityKey,
      mac: hmacHex(secret, ballotKeyRequestMessage("alice", enrolled.device_id, devicePub, poll, timestamp)) };
  };
  const ok = await call("/attest", ballot());
  assert.equal(ok.status, 200);
  const expected = crypto.createHash("sha256").update("P:USA:X123poll-1").digest("hex");
  assert.equal(ok.body.identity_hash, expected, "the same identity_hash as the session-based attest computed");
  const digest = crypto.createHash("sha256").update(devicePub + "poll-1" + expected).digest();
  assert.equal(crypto.verify(null, digest, enclave.publicKey, Buffer.from(ok.body.idv_attestation_sig, "hex")), true, "what the chain verifies");
  assert.equal((await call("/attest", { session_id: "s1", voter_pub_key: devicePub, poll_id: "poll-1" })).status, 400, "a session id alone");
  assert.equal((await call("/attest", ballot({ secret: "22".repeat(32) }))).status, 403, "without the device secret");
  assert.equal((await call("/attest", ballot({ identityKey: "33".repeat(32) }))).status, 403, "without the identity key");
  assert.ok(!JSON.stringify(logged).includes("X123"), "the document number is never logged");
});

test("only the device holding the pre-scan secret can enroll with a session, whoever else knows its id", async () => {
  const { call } = setup();
  const other = await call("/device-secret/enroll", { session_id: "s1", user_id: "alice", enrollment_secret: "77".repeat(32) });
  assert.equal(other.status, 403);
  assert.equal(other.body.code, "commitment_mismatch");
  const noSecret = await call("/device-secret/enroll", { session_id: "s1", user_id: "alice" });
  assert.equal(noSecret.status, 400, "no secret at all");
  assert.match(noSecret.body.error, /enrollment_secret missing/);
  assert.equal((await call("/device-secret/enroll", { session_id: "s1", user_id: "alice", enrollment_secret: ENROLL_SECRET })).status, 200,
    "a failed attempt doesn't burn the session for its owner");
});
