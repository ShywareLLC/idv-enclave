// Device secrets: ballots and vote-share grants without trusting a Didit
// session id (session ids are on the public ledger and in Populist's DB).
//
// 1. Device secret (POST /device-secret/enroll). Right after the person's
//    Didit verification (the face scan) is Approved, the device presents that
//    session once; the enclave re-checks it with Didit, consumes it for good,
//    and returns a fresh 32-byte secret it also keeps. From then on a session
//    id is useless here -- whoever learns one later (Populist's server, a log
//    reader, anyone reading the chain) can't enroll again with it.
//    It also returns an identity key: the verified document reference is
//    stored here only encrypted under that key, which the enclave does not
//    keep, so this database alone reveals no document numbers.
// 1b. Ballot keys (POST /attest). The device proves it holds the secret and
//    presents the identity key; the enclave decrypts the document reference
//    in memory, computes the poll's identity_hash exactly as before and signs
//    the same statement the chain verifies.
// 2. Key statement (POST /vote-share/attest-key). The device proves it holds
//    the secret with an HMAC over (account, device, its signing key, time);
//    the enclave vouches that the signing key is the account's.
// 3. The device signs each grant with that key; the reconciling authority
//    checks both signatures on storing it and on every access.
//
// Only the granter is verified; the grantee is only named, and the enclave is
// never in the access path.

const crypto = require("node:crypto");

const UID = /^[A-Za-z0-9:_-]{1,128}$/;
const PUB_HEX = /^[0-9a-f]{64}$/;
const MAC_HEX = /^[0-9a-f]{64}$/;
const DEVICE_ID = /^[0-9a-f-]{36}$/;
const MAX_SKEW_MS = 5 * 60 * 1000;

/// The bytes the enclave signs: newline-joined fields (identical in every language).
function keyAttestationMessage(userId, pubKeyHex) {
  return ["shyware-vote-share-key-v1", userId, pubKeyHex].join("\n");
}

/// The bytes the device MACs with its secret to ask for a key statement.
function keyRequestMessage(userId, deviceId, pubKeyHex, timestamp) {
  return ["shyware-vote-share-key-request-v1", userId, deviceId, pubKeyHex, timestamp].join("\n");
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

function hmacHex(secretHex, message) {
  return crypto.createHmac("sha256", Buffer.from(secretHex, "hex")).update(message, "utf8").digest("hex");
}

function sameHex(a, b) {
  const left = Buffer.from(a, "hex"), right = Buffer.from(b, "hex");
  return left.length === right.length && left.length > 0 && crypto.timingSafeEqual(left, right);
}

function createDeviceSecretTables(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS device_secrets (
      device_id TEXT PRIMARY KEY,
      firebase_uid TEXT NOT NULL,
      secret_hex TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);
  // Shared with voteRecovery.cjs (same definition there).
  db.exec("CREATE TABLE IF NOT EXISTS authorized_vote_devices(poll_id TEXT NOT NULL,identity_hash TEXT NOT NULL,voter_pub_key TEXT NOT NULL,PRIMARY KEY(poll_id,identity_hash,voter_pub_key))");
  if (!db.prepare("PRAGMA table_info(device_secrets)").all().some((c) => c.name === "document_ct")) {
    db.exec("ALTER TABLE device_secrets ADD COLUMN document_ct TEXT NULL");
  }
  // Every session ever presented for enrollment, kept forever: one use only.
  db.exec(`
    CREATE TABLE IF NOT EXISTS consumed_device_secret_sessions (
      session_hash TEXT PRIMARY KEY,
      firebase_uid TEXT NOT NULL,
      consumed_at TEXT NOT NULL
    )
  `);
}

/// Installs /device-secret/enroll and /vote-share/attest-key.
/// `checkDiditSession` and `firebaseUidOf` are the enclave's Didit helpers.
/// AES-256-GCM: iv || tag || ciphertext, hex.
function sealDocument(keyHex, documentKey) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", Buffer.from(keyHex, "hex"), iv);
  const body = Buffer.concat([cipher.update(documentKey, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString("hex");
}

function openDocument(keyHex, sealedHex) {
  const sealed = Buffer.from(sealedHex, "hex");
  const decipher = crypto.createDecipheriv("aes-256-gcm", Buffer.from(keyHex, "hex"), sealed.subarray(0, 12));
  decipher.setAuthTag(sealed.subarray(12, 28));
  return Buffer.concat([decipher.update(sealed.subarray(28)), decipher.final()]).toString("utf8");
}

/// Verifies the device's HMAC over `fields` with its enrolled secret; returns its row or null.
function provenDevice(db, userId, deviceId, fields, mac) {
  const device = db.prepare("SELECT secret_hex, document_ct FROM device_secrets WHERE device_id = ? AND firebase_uid = ?").get(deviceId, userId);
  if (!device || !sameHex(hmacHex(device.secret_hex, fields.join("\n")), mac)) return null;
  return device;
}

/// The ballot request the device MACs (no session id anywhere).
function ballotKeyRequestMessage(userId, deviceId, voterPubKeyHex, pollId, timestamp) {
  return ["shyware-ballot-key-request-v1", userId, deviceId, voterPubKeyHex, pollId, timestamp].join("\n");
}

function installVoteShareRoutes(app, { db, privateKey, checkDiditSession, firebaseUidOf, documentKeyOf, log = async () => {}, logAttest = async () => {}, now = () => Date.now() }) {
  createDeviceSecretTables(db);
  // Sessions are kept as hashes: the table itself never holds a usable id.
  const sessionHash = (id) => crypto.createHash("sha256").update(id, "utf8").digest("hex");

  app.post("/device-secret/enroll", async (req, res) => {
    res.set("Cache-Control", "no-store");
    const { session_id, user_id } = req.body || {};
    if (typeof session_id !== "string" || !session_id || typeof user_id !== "string" || !UID.test(user_id)) {
      return res.status(400).json({ error: "session_id and user_id are required" });
    }
    const hash = sessionHash(session_id);
    if (db.prepare("SELECT 1 FROM consumed_device_secret_sessions WHERE session_hash = ?").get(hash)) {
      await log({ timestamp: new Date(now()).toISOString(), user_id, outcome: "session_already_used" });
      return res.status(409).json({ error: "This verification was already used to enroll a device", code: "session_used" });
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
      await log({ timestamp: new Date(now()).toISOString(), user_id, outcome: "verification_failed" });
      return res.status(403).json({ error: "Identity verification failed" });
    }
    let documentKey;
    try { documentKey = documentKeyOf(decision); } catch { documentKey = null; }
    if (!documentKey) return res.status(403).json({ error: "The verification has no identity document" });
    const deviceId = crypto.randomUUID();
    const secretHex = crypto.randomBytes(32).toString("hex");
    const identityKeyHex = crypto.randomBytes(32).toString("hex");   // not kept here
    const documentCt = sealDocument(identityKeyHex, documentKey);
    const at = new Date(now()).toISOString();
    try {
      db.transaction(() => {
        db.prepare("INSERT INTO consumed_device_secret_sessions (session_hash, firebase_uid, consumed_at) VALUES (?, ?, ?)").run(hash, user_id, at);
        db.prepare("INSERT INTO device_secrets (device_id, firebase_uid, secret_hex, created_at, document_ct) VALUES (?, ?, ?, ?, ?)").run(deviceId, user_id, secretHex, at, documentCt);
      })();
    } catch {
      // A concurrent enrollment with the same session won the race.
      return res.status(409).json({ error: "This verification was already used to enroll a device", code: "session_used" });
    }
    await log({ timestamp: at, user_id, device_id: deviceId, outcome: "enrolled" });
    return res.json({ device_id: deviceId, secret_hex: secretHex, identity_key_hex: identityKeyHex });
  });

  app.post("/vote-share/attest-key", async (req, res) => {
    res.set("Cache-Control", "no-store");
    const { user_id, device_id, pub_key, timestamp, mac } = req.body || {};
    if (typeof user_id !== "string" || !UID.test(user_id) || typeof device_id !== "string" || !DEVICE_ID.test(device_id)
        || typeof pub_key !== "string" || !PUB_HEX.test(pub_key) || typeof mac !== "string" || !MAC_HEX.test(mac)
        || typeof timestamp !== "string") {
      return res.status(400).json({ error: "user_id, device_id, pub_key, timestamp and mac are required" });
    }
    const at = Date.parse(timestamp);
    if (!Number.isFinite(at) || Math.abs(now() - at) > MAX_SKEW_MS) {
      return res.status(400).json({ error: "The request is stale; sign it again" });
    }
    const device = provenDevice(db, user_id, device_id, keyRequestMessage(user_id, device_id, pub_key, timestamp).split("\n"), mac);
    if (!device) {
      await log({ timestamp: new Date(now()).toISOString(), user_id, device_id, outcome: "device_proof_failed" });
      return res.status(403).json({ error: "This device isn't enrolled for this account", code: "device_not_enrolled" });
    }
    const signature = crypto.sign(null, Buffer.from(keyAttestationMessage(user_id, pub_key), "utf8"), privateKey).toString("hex");
    await log({ timestamp: new Date(now()).toISOString(), user_id, device_id, pub_key, outcome: "signed" });
    return res.json({ user_id, pub_key, key_attestation_sig: signature });
  });

  // POST /attest -- ballot key statement, proven by the device, not a session.
  // Signs exactly what the chain verifies: sha256(voter_pub_key || poll_id || identity_hash).
  app.post("/attest", async (req, res) => {
    res.set("Cache-Control", "no-store");
    const timestamp = new Date(now()).toISOString();
    const { user_id, device_id, voter_pub_key, poll_id, timestamp: requestedAt, mac, identity_key } = req.body || {};
    if (typeof user_id !== "string" || !UID.test(user_id) || typeof device_id !== "string" || !DEVICE_ID.test(device_id)
        || typeof voter_pub_key !== "string" || !PUB_HEX.test(voter_pub_key) || typeof poll_id !== "string" || !poll_id || poll_id.length > 128
        || typeof mac !== "string" || !MAC_HEX.test(mac) || typeof identity_key !== "string" || !PUB_HEX.test(identity_key)
        || typeof requestedAt !== "string") {
      await logAttest({ timestamp, outcome: "bad_request", httpStatus: 400 });
      return res.status(400).json({ error: "user_id, device_id, voter_pub_key, poll_id, timestamp, mac and identity_key are required" });
    }
    const at = Date.parse(requestedAt);
    if (!Number.isFinite(at) || Math.abs(now() - at) > MAX_SKEW_MS) return res.status(400).json({ error: "The request is stale; sign it again" });
    const device = provenDevice(db, user_id, device_id, ballotKeyRequestMessage(user_id, device_id, voter_pub_key, poll_id, requestedAt).split("\n"), mac);
    if (!device) {
      await logAttest({ timestamp, poll_id, outcome: "device_proof_failed", httpStatus: 403 });
      return res.status(403).json({ error: "This device isn't enrolled for this account", code: "device_not_enrolled" });
    }
    if (!device.document_ct) return res.status(403).json({ error: "This device must enroll again", code: "device_not_enrolled" });
    let documentKey;
    try { documentKey = openDocument(identity_key, device.document_ct); } catch {
      await logAttest({ timestamp, poll_id, outcome: "identity_key_failed", httpStatus: 403 });
      return res.status(403).json({ error: "Identity key doesn't match this device", code: "device_not_enrolled" });
    }
    const identityHash = crypto.createHash("sha256").update(Buffer.from(documentKey + poll_id, "utf8")).digest("hex");
    db.prepare("INSERT OR IGNORE INTO authorized_vote_devices(poll_id,identity_hash,voter_pub_key) VALUES (?,?,?)").run(poll_id, identityHash, voter_pub_key);
    const digest = crypto.createHash("sha256").update(Buffer.from(`${voter_pub_key}${poll_id}${identityHash}`, "utf8")).digest();
    const signature = crypto.sign(null, digest, privateKey);
    // Same record shape vote recovery reads (poll_id, identityHash, voter_pub_key, outcome).
    await logAttest({ timestamp, poll_id, voter_pub_key, identityHash, outcome: "signed", httpStatus: 200 });
    return res.json({ idv_attestation_sig: signature.toString("hex"), identity_hash: identityHash, voter_pub_key, poll_id });
  });
}

module.exports = { keyAttestationMessage, keyRequestMessage, ballotKeyRequestMessage, verifyEd25519, hmacHex, sealDocument, openDocument, installVoteShareRoutes };
