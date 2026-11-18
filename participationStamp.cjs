// "I voted" stamps: proof that someone was counted, without saying which
// ballot is theirs or how they voted.
//
// A ballot ID is public alongside its choices, so sharing one shares the
// vote. A participant entry (identity_hash) carries no choice, but it is a
// stable per-poll handle for the person; a stamp carries neither.
//
// POST /participation-stamp. The device proves its enrolled secret (HMAC, as
// for /attest) and presents its identity key. The enclave computes the
// poll's identity_hash in memory, reads the poll's ledger records, checks
// the records commitment and count-match, and checks that identity_hash is
// in the participant list. It then signs
//   shyware-participation-stamp-v1 \n poll_id \n height \n records_root \n nonce
// with a fresh random nonce. Nothing in the stamp is derived from the person
// or their ballot, so stamps from different people in one poll look alike.
// The issuance log records only the outcome, never the identity hash.
//
// Trust: the stamp says "this enclave checked". Anyone can check the
// signature with the enclave's public key; nobody can check who it was for.
const crypto = require("node:crypto");
const { identityHashOf } = require("./identityHash.cjs");
const { provenDevice, openDocument, UID, DEVICE_ID, MAC_HEX, PUB_HEX, MAX_SKEW_MS } = require("./voteShareGrants.cjs");

const POLL_ID = /^[0-9A-Fa-f-]{1,128}$/;
const HEX64 = /^[0-9a-f]{64}$/;

function stampRequestMessage(userId, deviceId, pollId, timestamp) {
  return ["shyware-participation-stamp-request-v1", userId, deviceId, pollId, timestamp].join("\n");
}

function stampMessage(pollId, height, recordsRoot, nonceHex) {
  return ["shyware-participation-stamp-v1", pollId, String(height), recordsRoot, nonceHex].join("\n");
}

/// Stamp wire form: base64url(height u64 BE || records_root 32 || nonce 16 || Ed25519 sig 64).
function encodeStamp({ height, recordsRoot, nonceHex, signatureHex }) {
  const h = Buffer.alloc(8);
  h.writeBigUInt64BE(BigInt(height));
  return Buffer.concat([h, Buffer.from(recordsRoot, "hex"), Buffer.from(nonceHex, "hex"), Buffer.from(signatureHex, "hex")]).toString("base64url");
}

function decodeStamp(token) {
  if (typeof token !== "string" || !/^[A-Za-z0-9_-]{160}$/.test(token)) return null;
  const bytes = Buffer.from(token, "base64url");
  if (bytes.length !== 120) return null;
  return { height: Number(bytes.readBigUInt64BE(0)), recordsRoot: bytes.subarray(8, 40).toString("hex"),
    nonceHex: bytes.subarray(40, 56).toString("hex"), signatureHex: bytes.subarray(56).toString("hex") };
}

const recordsRootOf = (pollId, records) => crypto.createHash("sha256").update(Buffer.from("shyvoting-state-v2:poll:" + pollId + "\0" + records, "utf8")).digest("hex");

/// Whether identityHash is a counted participant in a self-consistent snapshot.
function participantCounted(snapshot, pollId, identityHash) {
  if (typeof snapshot?.records !== "string" || !HEX64.test(String(snapshot.records_root || ""))) return false;
  if (recordsRootOf(pollId, snapshot.records) !== snapshot.records_root) return false;
  const records = JSON.parse(snapshot.records);
  if (records.contract !== "shyvoting-inspection-v1" || records.poll?.poll_id !== pollId) return false;
  const active = records.votes.filter((vote) => !vote.superseded);
  const participants = new Set(records.voters.map((voter) => voter.identity_hash));
  if (new Set(active.map((vote) => vote.ballot_id)).size !== active.length
      || participants.size !== records.voters.length || active.length !== participants.size) return false;
  return participants.has(identityHash);
}

function installParticipationStamp(app, { db, privateKey, readInspection, log = async () => {}, now = () => Date.now() }) {
  app.post("/participation-stamp", async (req, res) => {
    res.set("Cache-Control", "no-store");
    const { user_id, device_id, poll_id, timestamp, mac, identity_key } = req.body || {};
    if (typeof user_id !== "string" || !UID.test(user_id) || typeof device_id !== "string" || !DEVICE_ID.test(device_id)
        || typeof poll_id !== "string" || !POLL_ID.test(poll_id) || typeof mac !== "string" || !MAC_HEX.test(mac)
        || typeof identity_key !== "string" || !PUB_HEX.test(identity_key) || typeof timestamp !== "string") {
      return res.status(400).json({ error: "user_id, device_id, poll_id, timestamp, mac and identity_key are required" });
    }
    const at = Date.parse(timestamp);
    if (!Number.isFinite(at) || Math.abs(now() - at) > MAX_SKEW_MS) return res.status(400).json({ error: "The request is stale; sign it again" });
    const device = provenDevice(db, user_id, device_id, stampRequestMessage(user_id, device_id, poll_id, timestamp).split("\n"), mac);
    let documentKey = null;
    try { if (device?.document_ct) documentKey = openDocument(identity_key, device.document_ct); } catch { documentKey = null; }
    if (!documentKey) {
      await log({ timestamp: new Date(now()).toISOString(), outcome: "device_proof_failed" });
      return res.status(403).json({ error: "This device isn't enrolled for this account", code: "device_not_enrolled" });
    }
    const identityHash = identityHashOf(documentKey, poll_id);
    let snapshot;
    try { snapshot = await readInspection(poll_id); } catch { return res.status(503).json({ error: "Ledger unavailable" }); }
    let counted = false;
    try { counted = participantCounted(snapshot, poll_id, identityHash); } catch { counted = false; }
    if (!counted) {
      await log({ timestamp: new Date(now()).toISOString(), poll_id, outcome: "not_counted" });
      return res.status(404).json({ error: "No counted vote for this account in this poll", code: "not_counted" });
    }
    const height = Number(snapshot.height);
    const nonceHex = crypto.randomBytes(16).toString("hex");
    const signatureHex = crypto.sign(null, Buffer.from(stampMessage(poll_id, height, snapshot.records_root, nonceHex), "utf8"), privateKey).toString("hex");
    await log({ timestamp: new Date(now()).toISOString(), poll_id, outcome: "stamped" });
    return res.json({ stamp: encodeStamp({ height, recordsRoot: snapshot.records_root, nonceHex, signatureHex }), poll_id, height });
  });
}

module.exports = { installParticipationStamp, stampRequestMessage, stampMessage, encodeStamp, decodeStamp, participantCounted };
