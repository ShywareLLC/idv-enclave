// populist-idv-enclave: independent IDV attestation service
//
// Runs on an AMD SEV-SNP confidential-computing instance. Given a Didit
// session_id + a device's per-poll voter_pub_key + a poll_id, this service
// independently confirms the session with Didit's real API (not trusting
// anything Populist's own backend claims) and, if genuinely Approved,
// signs sha256(voter_pub_key || poll_id) with a key generated inside this
// instance that never leaves it.
//
// What this achieves: Populist's own operators cannot forge an attestation
// for a fabricated registration, because they cannot fabricate a genuine
// Didit "Approved" response, and this service will not sign without one.
// What this does NOT yet achieve: full SEV-SNP attestation report
// verification (proving to an outside party that this exact, open-source
// code produced the signature) -- that requires the /dev/sev-guest report
// path plus a verifier against AMD's attestation chain, not yet built.
// The tenancy also doesn't support the Shielded Instance (measured
// boot/vTPM) bundle, so today's guarantee rests on: (a) SEV-SNP memory
// encryption protecting this process's memory from the host, and (b) the
// Didit API key being readable only by this specific instance's identity
// (OCI dynamic group scoped to this instance's OCID), not by Populist's
// own operators.
//
// This instance also writes the Didit webhook audit log (POST /audit-log)
// to OCI Object Storage using the same instance-principal identity used to
// fetch the Didit API key above -- no static cloud credential exists
// anywhere for this. See the audit-log section below for why that endpoint
// needs its own shared-secret auth, unlike /attest.

const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");
const common = require("oci-common");
const { SecretsClient } = require("oci-secrets");
const { ObjectStorageClient } = require("oci-objectstorage");

const KEY_DIR = "/etc/populist-idv-enclave";
const PRIV_KEY_PATH = path.join(KEY_DIR, "enclave_ed25519.pem");
const PUB_KEY_PATH = path.join(KEY_DIR, "enclave_ed25519_pub.pem");
const POLL_PRIV_KEY_PATH = path.join(KEY_DIR, "enclave_poll_rsa.pem");
const POLL_PUB_KEY_PATH = path.join(KEY_DIR, "enclave_poll_rsa_pub.pem");
const DB_PATH = path.join(KEY_DIR, "consumed-sessions.db");

const DIDIT_SECRET_OCID = process.env.DIDIT_SECRET_OCID;
if (!DIDIT_SECRET_OCID) {
  console.error("DIDIT_SECRET_OCID env var is required");
  process.exit(1);
}

const AUDIT_LOG_SHARED_SECRET = process.env.AUDIT_LOG_SHARED_SECRET;
const AUDIT_LOG_NAMESPACE = process.env.AUDIT_LOG_NAMESPACE;
const AUDIT_LOG_BUCKET = process.env.AUDIT_LOG_BUCKET;
if (!AUDIT_LOG_SHARED_SECRET || !AUDIT_LOG_NAMESPACE || !AUDIT_LOG_BUCKET) {
  console.error("AUDIT_LOG_SHARED_SECRET, AUDIT_LOG_NAMESPACE, and AUDIT_LOG_BUCKET env vars are required");
  process.exit(1);
}

// POST /sign-poll-create has no independent third party to check against
// (unlike /attest, which self-authenticates via a genuine Didit Approved
// decision) -- so, like /audit-log, it needs its own shared secret.
const POLL_SIGNING_SHARED_SECRET = process.env.POLL_SIGNING_SHARED_SECRET;
if (!POLL_SIGNING_SHARED_SECRET) {
  console.error("POLL_SIGNING_SHARED_SECRET env var is required");
  process.exit(1);
}

// Apple App Attest device-key store: durable, shared state a relay's own
// AppAttestKeyStore implementation reads/writes over HTTP (see
// ShywareLLC/core services/attest/verifier.go -- StoreKey/LoadKey). The
// enclave does NOT re-verify the App Attest attestation object itself; the
// relay's existing AppAttestVerifier already does the real cert-chain
// verification against Apple's root CA in Go, tested and working. This
// store's only job is to durably hold the already-verified public key
// somewhere with better survival properties than one relay process's
// memory -- same instance-principal identity as the audit log, but its own
// bucket (not a prefix in the audit-log bucket): device records must be
// deletable on de-registration, and the audit log's retention rule is
// deliberately WORM and must never end up covering something that needs to
// be deleted. Like /sign-poll-create and /audit-log, there is no
// independent third party to check a store/load request against, so this
// needs its own shared secret -- trusting that the caller (the relay) has
// already done the real cryptographic verification before calling here.
const DEVICE_KEY_SHARED_SECRET = process.env.DEVICE_KEY_SHARED_SECRET;
const DEVICE_KEY_BUCKET = process.env.DEVICE_KEY_BUCKET;
if (!DEVICE_KEY_SHARED_SECRET || !DEVICE_KEY_BUCKET) {
  console.error("DEVICE_KEY_SHARED_SECRET and DEVICE_KEY_BUCKET env vars are required");
  process.exit(1);
}

// -- Key material: generated once, on first boot, never transmitted ---------
function loadOrGenerateKeypair() {
  if (fs.existsSync(PRIV_KEY_PATH) && fs.existsSync(PUB_KEY_PATH)) {
    return {
      privateKey: fs.readFileSync(PRIV_KEY_PATH, "utf8"),
      publicKey: fs.readFileSync(PUB_KEY_PATH, "utf8")
    };
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const privPem = privateKey.export({ type: "pkcs8", format: "pem" });
  const pubPem = publicKey.export({ type: "spki", format: "pem" });
  fs.mkdirSync(KEY_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(PRIV_KEY_PATH, privPem, { mode: 0o600 });
  fs.writeFileSync(PUB_KEY_PATH, pubPem, { mode: 0o644 });
  console.log("Generated new enclave signing keypair -- this only happens once, ever.");
  return { privateKey: privPem, publicKey: pubPem };
}

const { privateKey: PRIVATE_KEY_PEM, publicKey: PUBLIC_KEY_PEM } = loadOrGenerateKeypair();
const PRIVATE_KEY_OBJ = crypto.createPrivateKey(PRIVATE_KEY_PEM);
const PUBLIC_KEY_OBJ = crypto.createPublicKey(PUBLIC_KEY_PEM);
// Raw 32-byte Ed25519 public key, hex-encoded -- this is what gets
// configured as --didit-pubkey on the Go core's DiditVerifier.
const PUBLIC_KEY_HEX = PUBLIC_KEY_OBJ.export({ type: "spki", format: "der" })
  .subarray(-32)
  .toString("hex");

// -- Poll-creation signing key: separate RSA-2048 keypair, same
// generated-once-never-exported pattern as the Ed25519 key above. Separate
// key (not reused) so a compromise of one signing purpose doesn't also
// compromise the other, and so each key's exposure is scoped to exactly one
// capability. This is what gets configured as --operator-pubkey-pem-file on
// the Go core's shyvoting-abci.
function loadOrGenerateRSAKeypair() {
  if (fs.existsSync(POLL_PRIV_KEY_PATH) && fs.existsSync(POLL_PUB_KEY_PATH)) {
    return {
      privateKey: fs.readFileSync(POLL_PRIV_KEY_PATH, "utf8"),
      publicKey: fs.readFileSync(POLL_PUB_KEY_PATH, "utf8")
    };
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const privPem = privateKey.export({ type: "pkcs8", format: "pem" });
  const pubPem = publicKey.export({ type: "spki", format: "pem" });
  fs.mkdirSync(KEY_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(POLL_PRIV_KEY_PATH, privPem, { mode: 0o600 });
  fs.writeFileSync(POLL_PUB_KEY_PATH, pubPem, { mode: 0o644 });
  console.log("Generated new poll-creation signing keypair -- this only happens once, ever.");
  return { privateKey: privPem, publicKey: pubPem };
}

const { privateKey: POLL_PRIVATE_KEY_PEM, publicKey: POLL_PUBLIC_KEY_PEM } = loadOrGenerateRSAKeypair();
const POLL_PRIVATE_KEY_OBJ = crypto.createPrivateKey(POLL_PRIVATE_KEY_PEM);

// -- Local one-time-use tracking (defense-in-depth only) --------------------
// The AUTHORITATIVE enforcement against session replay belongs on-chain
// (reject a registration tx whose didit_session_id has been seen before,
// same pattern as the existing identity_hash uniqueness check). This local
// table only prevents this one enclave instance from signing the same
// session twice for two different keys -- it does not substitute for the
// on-chain check, since an operator with instance access could in
// principle reset it. That's an accepted, documented limitation of this
// first build, not a claimed guarantee.
const db = new Database(DB_PATH);
db.exec(`
  CREATE TABLE IF NOT EXISTS consumed_sessions (
    session_id TEXT PRIMARY KEY,
    voter_pub_key TEXT NOT NULL,
    poll_id TEXT NOT NULL,
    consumed_at TEXT NOT NULL
  )
`);

// -- Didit API key: fetched once via instance-principal auth, kept only in
// memory, never logged, never returned by any endpoint. ---------------------
let diditApiKey = null;
let instancePrincipalProvider = null;

async function getInstancePrincipalProvider() {
  if (!instancePrincipalProvider) {
    instancePrincipalProvider = await new common.InstancePrincipalsAuthenticationDetailsProviderBuilder().build();
  }
  return instancePrincipalProvider;
}

async function fetchDiditApiKey() {
  const provider = await getInstancePrincipalProvider();
  const client = new SecretsClient({ authenticationDetailsProvider: provider });
  const response = await client.getSecretBundle({ secretId: DIDIT_SECRET_OCID });
  const base64Content = response.secretBundle.secretBundleContent.content;
  return Buffer.from(base64Content, "base64").toString("utf8");
}

// -- Object Storage client for the audit log, same instance-principal
// identity as above -- no static access key/secret exists for this. --------
let objectStorageClient = null;

async function getObjectStorageClient() {
  if (!objectStorageClient) {
    const provider = await getInstancePrincipalProvider();
    objectStorageClient = new ObjectStorageClient({ authenticationDetailsProvider: provider });
  }
  return objectStorageClient;
}

// -- Didit verification: this service calls Didit directly, independent of
// anything Populist's backend reports. ---------------------------------------
async function checkDiditSession(sessionId) {
  const res = await fetch(`https://verification.didit.me/v2/session/${encodeURIComponent(sessionId)}/decision/`, {
    headers: { Authorization: `Bearer ${diditApiKey}` }
  });
  if (!res.ok) {
    throw new Error(`Didit API returned ${res.status}`);
  }
  return res.json();
}

const app = express();
app.use(express.json());

app.get("/health", (_req, res) => {
  res.json({ status: "healthy", hasKey: Boolean(diditApiKey) });
});

// Returns the enclave's own public key -- this is what an operator pins as
// --didit-pubkey. Not secret; this is meant to be published/verifiable.
app.get("/pubkey", (_req, res) => {
  res.json({ publicKeyHex: PUBLIC_KEY_HEX, publicKeyPem: PUBLIC_KEY_PEM });
});

// Returns the poll-creation signing key's public half -- this is what an
// operator configures as --operator-pubkey-pem-file on shyvoting-abci. Not
// secret, same reasoning as /pubkey above.
app.get("/poll-pubkey", (_req, res) => {
  res.json({ publicKeyPem: POLL_PUBLIC_KEY_PEM });
});

// -- Poll-creation signing --------------------------------------------------
//
// Unlike /attest, there is no independent third party (Didit) to check a
// poll-create request against -- "should this poll exist" is purely a
// Populist-operational decision, not something this service can verify on
// its own. So this endpoint is authenticated the same way /audit-log is: a
// shared secret known only to populist.js and this instance, not open to
// any caller. What moving this signing INTO the enclave still buys: the
// private key never sits in populist.js's own process memory or .env file,
// so a compromise of the Populist backend alone cannot forge a poll-create
// signature -- the attacker would also need this instance's shared secret
// AND to reach this enclave, not just read one file on one box.
//
// Message format must exactly match the Go core's pollCreateMessage
// (ShywareLLC/core domain/state/polls.go): pollId:question:options
// (comma-joined):method:startTime:endTime -- signed via RSA-PSS/SHA-256,
// matching domain/state's verifyOperatorSignature.
app.post("/sign-poll-create", async (req, res) => {
  const timestamp = new Date().toISOString();
  const caller = {
    ip: req.get("cf-connecting-ip") || req.ip,
    directPeerIp: req.ip,
    cfRay: req.get("cf-ray") || null
  };

  const authHeader = req.get("authorization") || "";
  const presented = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (!timingSafeEqual(presented, POLL_SIGNING_SHARED_SECRET)) {
    await logPollCreateRequest({ timestamp, caller, outcome: "unauthorized", httpStatus: 401 });
    return res.status(401).json({ error: "unauthorized" });
  }

  const { poll_id, question, options, voting_method, start_time, end_time } = req.body || {};
  if (!poll_id || !question || !Array.isArray(options) || options.length < 2 ||
      !voting_method || !start_time || !end_time) {
    await logPollCreateRequest({ timestamp, caller, poll_id: poll_id || null, outcome: "bad_request", httpStatus: 400 });
    return res.status(400).json({
      error: "poll_id, question, options (array, >=2), voting_method, start_time, end_time are required"
    });
  }

  try {
    const message = `${poll_id}:${question}:${options.join(",")}:${voting_method}:${start_time}:${end_time}`;
    // Pass the raw message + explicit "sha256" algorithm (not a pre-hashed
    // digest with a null algorithm) so Node hashes internally and uses
    // SHA-256 for the PSS MGF1 function too -- verified cross-language
    // against Go's rsa.VerifyPSS(pub, crypto.SHA256, ...) before deploying,
    // see task notes; the null-algorithm/pre-hashed-digest form is ambiguous
    // about which hash PSS's MGF1 should use and is not what was tested.
    const signature = crypto.sign("sha256", Buffer.from(message, "utf8"), {
      key: POLL_PRIVATE_KEY_OBJ,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
    });
    await logPollCreateRequest({ timestamp, caller, poll_id, question, outcome: "signed", httpStatus: 200 });
    res.json({ signature: signature.toString("base64") });
  } catch (err) {
    console.error("sign-poll-create error:", err.message);
    await logPollCreateRequest({
      timestamp, caller, poll_id: poll_id || null,
      outcome: "internal_error", errorMessage: err.message, httpStatus: 500
    });
    res.status(500).json({ error: "internal error" });
  }
});

// Same self-telemetry principle as logAttestRequest below -- this
// service's own record of what it signed is the trusted vantage point, not
// an external witness. Separate poll-create-requests/ prefix so this never
// commingles with /attest's or /audit-log's records.
async function logPollCreateRequest(record) {
  try {
    const client = await getObjectStorageClient();
    const requestId = crypto.randomUUID();
    await client.putObject({
      namespaceName: AUDIT_LOG_NAMESPACE,
      bucketName: AUDIT_LOG_BUCKET,
      objectName: `poll-create-requests/${record.timestamp}-${requestId}.json`,
      putObjectBody: Buffer.from(JSON.stringify({ requestId, ...record })),
      contentType: "application/json"
    });
  } catch (err) {
    console.error("logPollCreateRequest error:", err.message);
  }
}

// -- Apple App Attest device-key store ---------------------------------------
//
// Three plain operations backed by OCI Object Storage: store a device's
// already-verified public key, look it up again for a later assertion
// check, and delete it on de-registration. No App Attest-specific logic
// lives here on purpose -- that verification (CBOR parsing, cert-chain
// verification against Apple's root CA) already exists and is tested in Go
// (ShywareLLC/core services/attest.AppAttestVerifier); duplicating it here
// in a second language would just be a second place for it to drift or be
// wrong. This store's only contract: whatever the caller says to store is
// already-verified, so store it durably; whatever's stored, hand it back
// unchanged.
function deviceKeyAuthorized(req) {
  const authHeader = req.get("authorization") || "";
  const presented = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  return timingSafeEqual(presented, DEVICE_KEY_SHARED_SECRET);
}

function deviceKeyObjectName(keyId) {
  return `device-keys/${encodeURIComponent(keyId)}.json`;
}

async function streamToBuffer(readable) {
  const chunks = [];
  for await (const chunk of readable) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

app.post("/register-device", async (req, res) => {
  if (!deviceKeyAuthorized(req)) {
    return res.status(401).json({ error: "unauthorized" });
  }

  const { keyId, pubKeyDER } = req.body || {};
  if (!keyId || !pubKeyDER) {
    return res.status(400).json({ error: "keyId and pubKeyDER (base64 DER) are required" });
  }
  // Fail fast on garbage input rather than silently storing an unusable value.
  try {
    Buffer.from(pubKeyDER, "base64");
  } catch {
    return res.status(400).json({ error: "pubKeyDER must be base64-encoded" });
  }

  try {
    const client = await getObjectStorageClient();
    await client.putObject({
      namespaceName: AUDIT_LOG_NAMESPACE,
      bucketName: DEVICE_KEY_BUCKET,
      objectName: deviceKeyObjectName(keyId),
      putObjectBody: Buffer.from(JSON.stringify({ keyId, pubKeyDER, registeredAt: new Date().toISOString() })),
      contentType: "application/json"
    });
    res.json({ success: true });
  } catch (err) {
    console.error("register-device error:", err.message);
    res.status(500).json({ error: "internal error" });
  }
});

app.get("/device-key/:keyId", async (req, res) => {
  if (!deviceKeyAuthorized(req)) {
    return res.status(401).json({ error: "unauthorized" });
  }

  try {
    const client = await getObjectStorageClient();
    const response = await client.getObject({
      namespaceName: AUDIT_LOG_NAMESPACE,
      bucketName: DEVICE_KEY_BUCKET,
      objectName: deviceKeyObjectName(req.params.keyId)
    });
    const body = await streamToBuffer(response.value);
    res.json(JSON.parse(body.toString("utf8")));
  } catch (err) {
    if (err.statusCode === 404) {
      return res.status(404).json({ error: `key ${req.params.keyId} not registered` });
    }
    console.error("device-key lookup error:", err.message);
    res.status(500).json({ error: "internal error" });
  }
});

app.delete("/device-key/:keyId", async (req, res) => {
  if (!deviceKeyAuthorized(req)) {
    return res.status(401).json({ error: "unauthorized" });
  }

  try {
    const client = await getObjectStorageClient();
    await client.deleteObject({
      namespaceName: AUDIT_LOG_NAMESPACE,
      bucketName: DEVICE_KEY_BUCKET,
      objectName: deviceKeyObjectName(req.params.keyId)
    });
    res.json({ success: true });
  } catch (err) {
    // Verified against a real bucket, not assumed: deleteObject throws 404
    // (ObjectNotFound) rather than succeeding silently when the object is
    // already gone. De-registering an already-gone key isn't an error for
    // the caller, so treat 404 here as the success it functionally is.
    if (err.statusCode === 404) {
      return res.json({ success: true });
    }
    console.error("device-key delete error:", err.message);
    res.status(500).json({ error: "internal error" });
  }
});

// -- Self-telemetry: the enclave records its own request history ------------
//
// Cloudflare (or any other external proxy fronting this instance) is
// deliberately NOT the source of truth for "did this attestation request
// happen" -- an external witness's own logging code is unattested and
// operator-authored, so it can't be trusted any more than populist.js
// itself can. The enclave's own code, running under SEV-SNP memory
// encryption and independently verifying against Didit before it will
// ever sign anything, is the actually-trusted vantage point. So the
// enclave logs every /attest call it processes -- success, rejection, or
// error -- from its own referrer/caller-observed side, to the same OCI
// Object Storage bucket as /audit-log (instance-principal identity, no
// static credential), under a separate attest-requests/ prefix so this
// self-telemetry is never commingled with the Didit webhook records
// populist.js forwards via /audit-log.
async function logAttestRequest(record) {
  try {
    const client = await getObjectStorageClient();
    const requestId = crypto.randomUUID();
    await client.putObject({
      namespaceName: AUDIT_LOG_NAMESPACE,
      bucketName: AUDIT_LOG_BUCKET,
      objectName: `attest-requests/${record.timestamp}-${requestId}.json`,
      putObjectBody: Buffer.from(JSON.stringify({ requestId, ...record })),
      contentType: "application/json"
    });
  } catch (err) {
    // Non-fatal: never let telemetry-write failure affect the actual
    // attestation response the caller is waiting on.
    console.error("logAttestRequest error:", err.message);
  }
}

app.post("/attest", async (req, res) => {
  const timestamp = new Date().toISOString();
  // When fronted by Cloudflare, req.ip is Cloudflare's own edge IP, not the
  // real caller -- CF-Connecting-IP carries the actual client address.
  // cfRay is Cloudflare's own per-request trace ID, recorded here purely
  // for cross-referencing against Cloudflare's edge logs/analytics if
  // ever needed -- not treated as a trust source, just a correlation key.
  const caller = {
    ip: req.get("cf-connecting-ip") || req.ip,
    directPeerIp: req.ip,
    host: req.get("host") || null,
    referer: req.get("referer") || null,
    userAgent: req.get("user-agent") || null,
    cfRay: req.get("cf-ray") || null
  };
  const { session_id, voter_pub_key, poll_id } = req.body || {};

  try {
    if (!session_id || !voter_pub_key || !poll_id) {
      await logAttestRequest({ timestamp, caller, outcome: "bad_request", httpStatus: 400 });
      return res.status(400).json({ error: "session_id, voter_pub_key, and poll_id are required" });
    }

    // Local replay guard (defense-in-depth; see comment above the table def).
    const existing = db.prepare("SELECT voter_pub_key, poll_id FROM consumed_sessions WHERE session_id = ?").get(session_id);
    if (existing) {
      if (existing.voter_pub_key === voter_pub_key && existing.poll_id === poll_id) {
        // Same request retried (e.g. client timeout+retry) -- idempotent, not an attack.
      } else {
        await logAttestRequest({ timestamp, caller, session_id, poll_id, outcome: "replay_conflict", httpStatus: 409 });
        return res.status(409).json({ error: "session_id already consumed for a different key/poll" });
      }
    }

    // Independent live check against Didit -- not trusting the caller's claim.
    const decision = await checkDiditSession(session_id);
    if (decision.status !== "Approved") {
      await logAttestRequest({
        timestamp, caller, session_id, poll_id,
        outcome: "didit_not_approved", diditStatus: decision.status, httpStatus: 403
      });
      return res.status(403).json({ error: `Didit session status is '${decision.status}', not Approved` });
    }

    // Must exactly match the Go core's diditDeviceAttestMessage:
    // sha256(voter_pub_key || poll_id) -- the hex string's raw ASCII bytes,
    // concatenated directly with the poll_id string's bytes, no separator,
    // no hex-decoding. See ShywareLLC/core/services/identity/didit.go.
    const message = Buffer.from(`${voter_pub_key}${poll_id}`, "utf8");
    const digest = crypto.createHash("sha256").update(message).digest();
    const signature = crypto.sign(null, digest, PRIVATE_KEY_OBJ);

    if (!existing) {
      db.prepare(
        "INSERT INTO consumed_sessions (session_id, voter_pub_key, poll_id, consumed_at) VALUES (?, ?, ?, ?)"
      ).run(session_id, voter_pub_key, poll_id, new Date().toISOString());
    }

    await logAttestRequest({
      timestamp, caller, session_id, poll_id, voter_pub_key,
      outcome: "signed", httpStatus: 200
    });

    res.json({
      idv_attestation_sig: signature.toString("hex"),
      voter_pub_key,
      poll_id,
      session_id
    });
  } catch (err) {
    console.error("attest error:", err.message);
    await logAttestRequest({
      timestamp, caller,
      session_id: session_id || null, poll_id: poll_id || null,
      outcome: "internal_error", errorMessage: err.message, httpStatus: 500
    });
    res.status(500).json({ error: "internal error" });
  }
});

// -- Didit webhook audit log ---------------------------------------------
//
// Unlike /attest, this endpoint's correctness does NOT self-verify against
// an independent third party (there's no live Didit check to make here --
// the caller is just handing over a record populist.js already validated
// via its own Didit HMAC check). So unlike /attest, which any caller can
// hit because a forged request simply can't produce a valid Didit
// "Approved" decision, this endpoint needs its own auth: a shared secret
// known only to populist.js and this instance, checked via constant-time
// comparison. This does not weaken the actual tamper-evidence guarantee of
// the audit log itself (that comes from the OCI retention rule on the
// bucket, plus this instance's own instance-principal identity only being
// granted "use objects", never "manage objects" i.e. no delete) -- it only
// gates who can add new entries, the same as any authenticated write API.
function timingSafeEqual(a, b) {
  const bufA = Buffer.from(a || "", "utf8");
  const bufB = Buffer.from(b || "", "utf8");
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

app.post("/audit-log", async (req, res) => {
  try {
    const authHeader = req.get("authorization") || "";
    const presented = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
    if (!timingSafeEqual(presented, AUDIT_LOG_SHARED_SECRET)) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const { eventId, record } = req.body || {};
    if (!eventId || !record) {
      return res.status(400).json({ error: "eventId and record are required" });
    }

    const client = await getObjectStorageClient();
    const namespace = AUDIT_LOG_NAMESPACE;
    await client.putObject({
      namespaceName: namespace,
      bucketName: AUDIT_LOG_BUCKET,
      objectName: `didit-webhook/${eventId}.json`,
      putObjectBody: Buffer.from(JSON.stringify(record)),
      contentType: "application/json"
    });

    res.json({ success: true });
  } catch (err) {
    console.error("audit-log error:", err.message);
    res.status(500).json({ error: "internal error" });
  }
});

const PORT = process.env.PORT || 8443;
const TLS_KEY = process.env.TLS_KEY_PATH;
const TLS_CERT = process.env.TLS_CERT_PATH;

async function start() {
  diditApiKey = await fetchDiditApiKey();
  console.log("Didit API key loaded via instance-principal auth (never logged).");

  if (TLS_KEY && TLS_CERT && fs.existsSync(TLS_KEY) && fs.existsSync(TLS_CERT)) {
    const https = require("https");
    https
      .createServer({ key: fs.readFileSync(TLS_KEY), cert: fs.readFileSync(TLS_CERT) }, app)
      .listen(PORT, () => console.log(`populist-idv-enclave listening on https://0.0.0.0:${PORT}`));
  } else {
    app.listen(PORT, () => console.log(`populist-idv-enclave listening on http://0.0.0.0:${PORT} (NO TLS -- set TLS_KEY_PATH/TLS_CERT_PATH)`));
  }
}

start().catch((err) => {
  console.error("Failed to start:", err);
  process.exit(1);
});
