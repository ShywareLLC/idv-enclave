// Vote-share grants: the enclave's half of letting a verified voter give
// another account ongoing access to their votes, the same shape as the PHI
// "ongoing provider disclosure" consent.
//
// Only the granter is verified, and only here, once: the caller presents the
// granter's Didit session, the enclave re-checks it with Didit itself and that
// it is bound to the granter's Firebase account, then signs the grant with the
// enclave's Ed25519 key. The grantee is just a named Firebase account. Access
// is checked later by the reconciling authority against this signature, the
// grantee's own sign-in and its own withdrawal list; the enclave is never in
// the access path, so it never learns when a grant is used.

const crypto = require("node:crypto");

const GRANT_VERSION = 1;
const SCOPES = new Set(["all_votes"]);
const UID = /^[A-Za-z0-9:_-]{1,128}$/;

/// The exact bytes that are signed: fixed key order, no whitespace.
function grantMessage(grant) {
  return JSON.stringify({
    v: grant.v, grant_id: grant.grant_id, purpose: grant.purpose, scope: grant.scope,
    grantor_uid: grant.grantor_uid, grantee_uid: grant.grantee_uid, issued_at: grant.issued_at
  });
}

function validateRequest({ grantor_uid, grantee_uid, scope = "all_votes" } = {}) {
  if (typeof grantor_uid !== "string" || !UID.test(grantor_uid)) return "grantor_uid is invalid";
  if (typeof grantee_uid !== "string" || !UID.test(grantee_uid)) return "grantee_uid is invalid";
  if (grantor_uid === grantee_uid) return "a grant must name another account";
  if (!SCOPES.has(scope)) return "scope is not supported";
  return null;
}

/// Builds and signs a grant. `privateKey` is the enclave's Ed25519 KeyObject.
function issueGrant(privateKey, { grantor_uid, grantee_uid, scope = "all_votes" }, now = new Date()) {
  const grant = {
    v: GRANT_VERSION, grant_id: crypto.randomUUID(), purpose: "vote_share", scope,
    grantor_uid, grantee_uid, issued_at: now.toISOString()
  };
  const signature = crypto.sign(null, Buffer.from(grantMessage(grant)), privateKey).toString("hex");
  return { grant, signature };
}

/// Verifies a grant against the enclave's public key (raw 32-byte hex).
function verifyGrant(publicKeyHex, grant, signatureHex) {
  try {
    const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(publicKeyHex, "hex")]);
    const key = crypto.createPublicKey({ key: der, format: "der", type: "spki" });
    return crypto.verify(null, Buffer.from(grantMessage(grant)), key, Buffer.from(signatureHex, "hex"));
  } catch {
    return false;
  }
}

/// The route: granter-only verification, then a signed grant.
/// `checkDiditSession(sessionId)` and `firebaseUidOf(decision)` are the
/// enclave's existing Didit helpers; `authorized(req)` checks the caller.
function installVoteShareGrantRoute(app, { privateKey, checkDiditSession, firebaseUidOf, authorized, logGrant = async () => {} }) {
  app.post("/vote-share/grant", async (req, res) => {
    res.set("Cache-Control", "no-store");
    if (!authorized(req)) return res.status(401).json({ error: "unauthorized" });
    const body = req.body || {};
    const invalid = validateRequest(body);
    if (invalid || typeof body.session_id !== "string" || !body.session_id) {
      return res.status(400).json({ error: invalid || "session_id is required" });
    }
    let decision;
    try {
      decision = await checkDiditSession(body.session_id);
    } catch {
      return res.status(503).json({ error: "Identity verification unavailable" });
    }
    let boundUid = null;
    try { boundUid = firebaseUidOf(decision); } catch { boundUid = null; }
    if (decision?.status !== "Approved" || boundUid !== body.grantor_uid) {
      return res.status(403).json({ error: "The granter's identity verification failed" });
    }
    const issued = issueGrant(privateKey, { grantor_uid: body.grantor_uid, grantee_uid: body.grantee_uid, scope: body.scope || "all_votes" });
    // Who shares with whom is recorded; how anyone voted never reaches here.
    await logGrant({ timestamp: issued.grant.issued_at, grant_id: issued.grant.grant_id,
      grantor_uid: issued.grant.grantor_uid, grantee_uid: issued.grant.grantee_uid, scope: issued.grant.scope });
    return res.json(issued);
  });
}

module.exports = { GRANT_VERSION, grantMessage, validateRequest, issueGrant, verifyGrant, installVoteShareGrantRoute };
