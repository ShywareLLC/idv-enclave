const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { issueGrant, verifyGrant, validateRequest, installVoteShareGrantRoute } = require("./voteShareGrants.cjs");

const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
const publicKeyHex = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");

test("a grant verifies with the enclave key, and any change breaks it", () => {
  const { grant, signature } = issueGrant(privateKey, { grantor_uid: "alice", grantee_uid: "bob" });
  assert.equal(grant.purpose, "vote_share");
  assert.equal(verifyGrant(publicKeyHex, grant, signature), true);
  assert.equal(verifyGrant(publicKeyHex, { ...grant, grantee_uid: "mallory" }, signature), false, "can't be re-pointed");
  assert.equal(verifyGrant(publicKeyHex, { ...grant, scope: "everything" }, signature), false);
  const other = crypto.generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
  assert.equal(verifyGrant(other, grant, signature), false, "only the enclave's key");
});

test("requests must name two different accounts and a known scope", () => {
  assert.equal(validateRequest({ grantor_uid: "a", grantee_uid: "a" }), "a grant must name another account");
  assert.equal(validateRequest({ grantor_uid: "a", grantee_uid: "b", scope: "x" }), "scope is not supported");
  assert.equal(validateRequest({ grantor_uid: "a", grantee_uid: "b" }), null);
});

function fakeApp() {
  const routes = {};
  return { post: (p, h) => { routes[p] = h; }, call: async (p, body, headers = {}) => {
    let status = 200, payload;
    const res = { set() {}, status(s) { status = s; return this; }, json(b) { payload = b; return this; } };
    await routes[p]({ body, get: (h) => headers[h.toLowerCase()] }, res);
    return { status, payload };
  } };
}

test("only the granter's own approved verification gets a signed grant", async () => {
  const app = fakeApp();
  const logged = [];
  installVoteShareGrantRoute(app, {
    privateKey,
    checkDiditSession: async (id) => ({ status: id === "ok" || id === "someone-else" ? "Approved" : "Declined", uid: id === "someone-else" ? "carol" : "alice" }),
    firebaseUidOf: (d) => d.uid,
    authorized: (req) => req.get("authorization") === "Bearer s",
    logGrant: async (r) => logged.push(r)
  });
  const auth = { authorization: "Bearer s" };
  assert.equal((await app.call("/vote-share/grant", { session_id: "ok", grantor_uid: "alice", grantee_uid: "bob" })).status, 401);
  assert.equal((await app.call("/vote-share/grant", { session_id: "no", grantor_uid: "alice", grantee_uid: "bob" }, auth)).status, 403);
  assert.equal((await app.call("/vote-share/grant", { session_id: "someone-else", grantor_uid: "alice", grantee_uid: "bob" }, auth)).status, 403,
    "another person's verification can't grant alice's votes");
  const ok = await app.call("/vote-share/grant", { session_id: "ok", grantor_uid: "alice", grantee_uid: "bob" }, auth);
  assert.equal(ok.status, 200);
  assert.equal(verifyGrant(publicKeyHex, ok.payload.grant, ok.payload.signature), true);
  assert.deepEqual(Object.keys(logged[0]).sort(), ["grant_id", "grantee_uid", "grantor_uid", "scope", "timestamp"], "no vote data logged");
});
