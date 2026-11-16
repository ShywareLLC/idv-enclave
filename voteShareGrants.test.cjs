const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { keyAttestationMessage, verifyEd25519, installVoteShareKeyRoute } = require("./voteShareGrants.cjs");

const enclave = crypto.generateKeyPairSync("ed25519");
const enclavePub = enclave.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
const devicePub = crypto.generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");

function fakeApp() {
  const routes = {};
  return { post: (p, h) => { routes[p] = h; }, call: async (p, body) => {
    let status = 200, payload;
    const res = { set() {}, status(s) { status = s; return this; }, json(b) { payload = b; return this; } };
    await routes[p]({ body }, res);
    return { status, payload };
  } };
}

test("the enclave vouches for a device key only for the account the verification belongs to", async () => {
  const app = fakeApp();
  const logged = [];
  installVoteShareKeyRoute(app, {
    privateKey: enclave.privateKey,
    checkDiditSession: async (id) => ({ status: id === "declined" ? "Declined" : "Approved", uid: "alice" }),
    firebaseUidOf: (d) => d.uid,
    log: async (r) => logged.push(r)
  });
  assert.equal((await app.call("/vote-share/attest-key", { session_id: "s", user_id: "alice", pub_key: "nothex" })).status, 400);
  assert.equal((await app.call("/vote-share/attest-key", { session_id: "declined", user_id: "alice", pub_key: devicePub })).status, 403);
  assert.equal((await app.call("/vote-share/attest-key", { session_id: "s", user_id: "bob", pub_key: devicePub })).status, 403,
    "alice's verification can't vouch for a key on bob's account");
  const ok = await app.call("/vote-share/attest-key", { session_id: "s", user_id: "alice", pub_key: devicePub });
  assert.equal(ok.status, 200);
  assert.equal(verifyEd25519(enclavePub, keyAttestationMessage("alice", devicePub), ok.payload.key_attestation_sig), true);
  assert.equal(verifyEd25519(enclavePub, keyAttestationMessage("bob", devicePub), ok.payload.key_attestation_sig), false);
  assert.ok(logged.every((r) => !("session_id" in r)), "the Didit session isn't logged");
});
