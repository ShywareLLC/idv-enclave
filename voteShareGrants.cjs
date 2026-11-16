// Vote-share grants, the voting way: the enclave vouches for the granter's
// DEVICE KEY, and the device signs every grant itself.
//
// Same split as POST /attest for ballots. The device generates its own
// Ed25519 key (it never leaves the device) and calls this endpoint directly
// with its Didit session. The enclave re-checks Didit itself, confirms the
// session is bound to the claimed Firebase account, and signs a statement
// binding that public key to that account. The device then signs each grant
// (grantee, scope, time) with its private key; the reconciling authority
// checks both signatures, on storing the grant and on every access. Nobody
// without the device key can produce a grant: not Populist's server, not this
// enclave. Only the granter is verified; the grantee is only named, and the
// enclave is never in the access path.

const crypto = require("node:crypto");

const UID = /^[A-Za-z0-9:_-]{1,128}$/;
const PUB_HEX = /^[0-9a-f]{64}$/;

/// The bytes the enclave signs: newline-joined fields (identical in every language).
function keyAttestationMessage(userId, pubKeyHex) {
  return ["shyware-vote-share-key-v1", userId, pubKeyHex].join("\n");
}

function verifyEd25519(publicKeyHex, message, signatureHex) {
  try {
    const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(publicKeyHex, "hex")]);
    const key = crypto.createPublicKey({ key: der, format: "der", type: "spki" });
    return crypto.verify(null, Buffer.from(message, "utf8"), key, Buffer.from(signatureHex, "hex"));
  } catch {
    return false;
  }
}

/// POST /vote-share/attest-key {session_id, user_id, pub_key}: called by the
/// device itself, like /attest. `checkDiditSession` and `firebaseUidOf` are
/// the enclave's existing Didit helpers.
function installVoteShareKeyRoute(app, { privateKey, checkDiditSession, firebaseUidOf, log = async () => {} }) {
  app.post("/vote-share/attest-key", async (req, res) => {
    res.set("Cache-Control", "no-store");
    const { session_id, user_id, pub_key } = req.body || {};
    if (typeof session_id !== "string" || !session_id || typeof user_id !== "string" || !UID.test(user_id)
        || typeof pub_key !== "string" || !PUB_HEX.test(pub_key)) {
      return res.status(400).json({ error: "session_id, user_id and pub_key (32-byte hex) are required" });
    }
    let decision;
    try {
      decision = await checkDiditSession(session_id);
    } catch {
      return res.status(503).json({ error: "Identity verification unavailable" });
    }
    let boundUid = null;
    try { boundUid = firebaseUidOf(decision); } catch { boundUid = null; }
    if (decision?.status !== "Approved" || boundUid !== user_id) {
      await log({ timestamp: new Date().toISOString(), user_id, outcome: "verification_failed" });
      return res.status(403).json({ error: "Identity verification failed" });
    }
    const signature = crypto.sign(null, Buffer.from(keyAttestationMessage(user_id, pub_key), "utf8"), privateKey).toString("hex");
    await log({ timestamp: new Date().toISOString(), user_id, pub_key, outcome: "signed" });
    return res.json({ user_id, pub_key, key_attestation_sig: signature });
  });
}

module.exports = { keyAttestationMessage, verifyEd25519, installVoteShareKeyRoute };
