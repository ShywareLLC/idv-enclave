// identity_hash: a poll's participant entry (List 2).
//
// v1 was sha256(document_type:country:document_number || poll_id). Document
// numbers are few enough to try them all, so anyone could reverse a public
// participant entry into a document number, and anyone holding a shared
// entry could tie a name to one.
//
// v2 is HMAC-SHA256 under a key only this enclave can compute, derived (HKDF)
// from its Ed25519 signing key -- no new secret to provision, and stable
// across relaunches because the signing key is. Without that key an entry
// can't be recomputed from a document number. Still one entry per document
// per poll, so uniqueness on the ledger is unchanged.
const crypto = require("node:crypto");

let hmacKey = null;

/// Called once at startup with the enclave's Ed25519 private key.
function configureIdentityHash(privateKey) {
  const key = privateKey instanceof crypto.KeyObject ? privateKey : crypto.createPrivateKey(privateKey);
  const seed = key.export({ format: "der", type: "pkcs8" }).subarray(-32);
  hmacKey = Buffer.from(crypto.hkdfSync("sha256", seed, Buffer.alloc(0), Buffer.from("shyware-identity-hash-v2", "utf8"), 32));
}

function identityHashOf(documentKey, pollId) {
  if (!hmacKey) throw new Error("identity hash key not configured");
  return crypto.createHmac("sha256", hmacKey).update(`${documentKey}\n${pollId}`, "utf8").digest("hex");
}

module.exports = { configureIdentityHash, identityHashOf };
