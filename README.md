# idv-enclave

Reference implementation of a Shyware **IDV attestation enclave**: a small,
independently-verifying service that closes the oracle-forgery gap in the
default `shyvoting-v1` identity flow (something has to hold the key that signs
`idv_attestation_sig`; this ensures it isn't the same operator whose backend
you're trying to keep honest).

Design and rationale are documented at
[docs.shyware.fyi/deployments/idv-attestation-enclave](https://docs.shyware.fyi/deployments/idv-attestation-enclave)
— read that first. In short: this runs inside a confidential-computing
instance (memory encrypted from the host — AMD SEV-SNP or equivalent),
generates its own Ed25519 and RSA-2048 signing keypairs once on first boot
(never exported, never leaves the instance), and independently re-verifies
every Didit session against Didit's real API before it will sign anything —
so the operator running the rest of the stack cannot forge an attestation
even with full access to their own backend.

## Why this is public

The whole point of an attestation service is that outsiders should be able to
read exactly what it does rather than trust a description of it. These files are the
actual, deployed service source (aside from environment-specific secrets,
which are never in code — see below). Nothing in here is specific to
Populist; the pattern applies to any `shyvoting-v1` deployment using Didit,
per the docs page above.

## What it does

- `POST /attest` — given `{session_id, voter_pub_key, poll_id}`, independently
  checks the session with Didit's real API and signs
  `sha256(voter_pub_key || poll_id || identity_hash)` only if genuinely `Approved`.
  Self-authenticating: no auth needed, since a forged request simply cannot
  produce a valid Didit `Approved` response.
- `POST /sign-poll-create` — signs an operator-authorized `TxTypePollCreate`
  transaction with a *separate* RSA-2048 key (so compromising one signing
  purpose doesn't compromise the other). No independent third party to check
  a poll-create request against, so this one needs a real shared-secret auth.
- `POST /audit-log` — forwards an already-HMAC-validated Didit webhook record
  to OCI Object Storage for durable, append-only storage. Shared-secret auth
  for the same reason as above.
- `POST /verification/attest` — independently checks the Didit session,
  verifies that Didit's `vendor_data.userId` matches the requested Firebase
  UID, and signs the approved result. Populist must verify this signature
  before persisting a verified profile.
- `POST /publication/admit` — privately verifies the original device/enrollment
  envelopes and a fresh ledger snapshot, then authorizes two independently
  sorted complete public lists. The returned transaction contains no device
  keys, verification sessions, nonces or per-entry identity/ballot pairs.
  The validator enforces a compare-and-swap prior-record root. This reuses the
  existing enrollment key; it does not require KMS or seal vote payloads.
- `GET /attestation?challenge=<64 lowercase hex characters>` — captures a fresh
  SNP report, binding the verifier's 32-byte challenge, service public key and
  source digest. The helper verifies the AMD certificate/signature chain and
  reports failure explicitly. The code digest in REPORT_DATA is a signed
  caller assertion, not measured-boot proof that Node executed only that file.
- `GET /pubkey`, `GET /poll-pubkey`, `GET /health` — public, unauthenticated;
  the two pubkey endpoints are meant to be published and pinned by consumers
  (`--didit-pubkey` / `--operator-pubkey-pem-file` on the Go core validator).
- `POST /register-device`, `GET /device-key/{keyId}`, `DELETE /device-key/{keyId}`
  — durable storage for Apple App Attest device keys, backed by its own OCI
  Object Storage bucket (deliberately separate from the audit-log bucket:
  device records must be deletable on de-registration, and the audit log's
  retention rule is WORM). This service does not itself verify App Attest
  attestations -- that real cryptographic work already exists and is tested
  in Go (`ShywareLLC/core`'s `services/attest.AppAttestVerifier`); these
  three endpoints exist purely so that verification's key store survives a
  relay process restarting, via `services/attest.EnclaveKeyStore`. Shared-secret
  gated, for the same reason as `/sign-poll-create`: there's no independent
  third party to check a store/load request against.

## Configuration (all via environment, nothing hardcoded)

| Variable | Purpose |
|---|---|
| `DIDIT_SECRET_OCID` | OCI Vault secret OCID holding the Didit API key (fetched via instance-principal auth, kept in memory only, never logged) |
| `AUDIT_LOG_SHARED_SECRET` | Bearer secret gating `POST /audit-log` |
| `AUDIT_LOG_NAMESPACE`, `AUDIT_LOG_BUCKET` | OCI Object Storage target for audit records |
| `POLL_SIGNING_SHARED_SECRET` | Bearer secret gating `POST /sign-poll-create` |
| `DEVICE_KEY_SHARED_SECRET` | Bearer secret gating the three `/register-device` / `/device-key` endpoints |
| `DEVICE_KEY_BUCKET` | OCI Object Storage bucket for device-key records (same namespace as `AUDIT_LOG_NAMESPACE`, separate bucket -- see above) |
| `PUBLICATION_ADMISSION_SECRET` | Dedicated bearer credential for the private relay-to-authority admission path; configured only for separated publication |
| `PORT` (default `8443`), `TLS_KEY_PATH`, `TLS_CERT_PATH` | Listen config; runs plain HTTP if TLS paths aren't set (put a TLS-terminating proxy in front in that case) |
| `RELAY_BASE_URL` | Optional. The relay's own base URL (e.g. `https://admin.yourdomain.com`), used by `/attest`'s replay-guard grace window to check whether a poll is still open before letting a different key take over an already-consumed `(session_id, poll_id)` slot. If unset, the grace window simply never opens -- a slot locks permanently on the first key it sees, same as before this feature existed. Not required for the service's core guarantee. |

### `/attest`'s local replay guard and grace window

`consumed_sessions` (SQLite, local to this instance) is defense-in-depth
only -- the real, authoritative "one Didit session, one vote, ever" rule is
enforced by the chain itself (`ShywareLLC/core`'s `s.consumedSessions`, keyed
by `session_id` alone, globally), not by this table. This table's job is
narrower: it's keyed by `(session_id, poll_id)` and exists so a retry with
the *same* key is idempotent rather than erroring.

A different key for an already-consumed `(session_id, poll_id)` pair is
normally rejected (`409`). If `RELAY_BASE_URL` is set, the handler checks the
poll's current status first and allows the reassignment when the poll is
still open (`"open"` or `"pending"`) -- a transient failure after the first
signature shouldn't permanently orphan the poll for that session. This is
deliberately anchored to poll lifecycle (something an operator already
controls, by closing the poll) rather than a fixed timer baked into this
service.

Signing keys and the local replay-tracking SQLite database live under
`/etc/populist-idv-enclave/` (path is currently hardcoded — parameterizing
this is a good first contribution if you're adapting this for another
deployment) and are generated on first run if not already present.

## Threat model note

This provides independent verification of approved Didit sessions and device
signatures before publication. Authorized provider processing remains inside
the regulated-ledger design; original paired inputs are not public ledger
transactions. It does **not** establish that arbitrary privileged guest code
cannot access the software signing key.

The AMD verifier is now implemented and deployed. A fresh report from the live
Oracle VM still fails its VCEK signature check, so hardware assurance remains
unverified. Instrumentation must not label that failure a successful attestation.
A verified hardware report would additionally need an accepted workload/boot
measurement policy before claiming proof of execution of this specific service.

## Attestation verification status

Reconfirmed with a fresh challenge-bound live capture on **2026-10-10** (the
initial investigation was 2026-10-06): `go-sev-guest`'s `verify.SnpAttestation` fails against
reports fetched from both OCI SEV-SNP hosts this repo runs on
(`populist-idv-enclave` and the now-terminated `zk-setup-ephemeral` ceremony
VM — see `ShywareLLC/core/zk-ceremony-2026-10-06/README.md`), with
`report signature verification error: x509: ECDSA verification failure`.

**Checks completed; these do not establish fault attribution:**
- Network/KDS reachability — confirmed live, both the AMD root cert chain and
  the chip's VCEK cert fetch successfully (`200`s) directly from
  `kdsintf.amd.com`.
- Wrong product line — report explicitly decodes as `Genoa`; forcing
  `SEV_PRODUCT_GENOA` in `Options` makes no difference (earlier finding,
  reconfirmed).
- VLEK/VCEK confusion — report's `SignerInfo` explicitly says `VCEK (0)`, not
  VLEK; the correct VCEK (by chip ID + `ReportedTcb`, using the library's own
  URL builder, not a hand-rolled one) is what gets fetched.
- Shyware/Go-specific collection or signature handling — a native C collector
  using the VM's installed Linux UAPI headers obtains a fresh report with
  status 0, size 1184 and matching challenge. Independent Python extraction
  and OpenSSL verification still reject its signature. Official VirTEE
  `snpguest v0.10.0` independently collects another fresh report, fetches AMD
  certificates, verifies their chain and matches firmware patch levels, then
  fails its report-signature check. This reproduces the failure without our
  implementation; it does not prove that every configuration prerequisite is
  satisfied or identify the responsible provider/component.
- A one-off bad capture — reproduced identically on a second, independent,
  currently-live host (`populist-idv-enclave`, fetched fresh), not just the
  terminated ceremony VM's one report.

**Current conclusion:** report-signature failure is independently reproducible.
Its cause remains unresolved; configuration/collection prerequisites, platform
firmware and AMD endorsement provisioning remain investigation areas. The
historical GCP positive control uses **Milan**, while this Oracle VM uses
**Genoa**, so it is not a positive test of the Genoa-specific path. Do not
describe the result as a proven Oracle or AMD defect. Oracle technical support **SR 4-0004016476** is submitted and confirmed ACTIVE.
It requests the matching AMD endorsement or diagnosis of the signing-key/TCB
mismatch and prohibits VM alteration without a controlled handover. See
[submission evidence](../../patent/mainhub/dpia/shyware-protocol-conformance/oracle-support-submitted-20261010.json).

**Until this closes, the live OCI enrollment report and `core/zk-ceremony-2026-10-06` must not
be described as independently, cryptographically verified** — the report was
captured and is internally self-consistent (chip ID and TCB values parse and
resolve to a real AMD-issued cert), but its signature does not yet verify
against that cert by any method tried.

## Independent verification

The shared verifier is in `internal/reportverify`; both capture and the standalone
command use it. Supply the 64-byte expected REPORT_DATA from an independently
chosen challenge, pinned service key and expected source digest, rather than
copying a binding claimed by an untrusted response:

```bash
go run ./cmd/verify-attestation report.json <expected-128-character-report-data-hex>
```

For raw SEV-SNP reports, the signed region is `[0x000:0x2A0)` (672 bytes),
hashed with SHA-384. The full signature field is `[0x2A0:0x4A0)` (512 bytes).
R occupies `[0x2A0:0x2E8)` and S occupies `[0x2E8:0x330)`; each is a
72-byte little-endian integer. For P-384, the first 48 bytes contain the
scalar and the trailing 24 bytes must be zero before they can be discarded.
Reverse the 48-byte scalar for big-endian integer APIs and encode R/S as
ASN.1 DER for OpenSSL. The existing Go ABI implementation already handles
the little-endian conversion; do not reverse its output again.

On the existing Oracle VM, the installed VirTEE `snpguest v0.10.0` checks
the saved reference report with:

```sh
SNP_AUDIT_BIN=/home/ubuntu/oracle-audit-snpguest-v0.10.0
SNP_AUDIT_DIR=/home/ubuntu/oracle-virtee-audit-20261010
"$SNP_AUDIT_BIN" verify certs "$SNP_AUDIT_DIR/certs"
"$SNP_AUDIT_BIN" verify attestation "$SNP_AUDIT_DIR/certs" "$SNP_AUDIT_DIR/report.bin" --processor-model genoa --tcb
"$SNP_AUDIT_BIN" verify attestation "$SNP_AUDIT_DIR/certs" "$SNP_AUDIT_DIR/report.bin" --processor-model genoa --signature
```

Oracle uses native `/dev/sev-guest` collection. In current VirTEE source,
`--openhcl` belongs to report collection for Hyper-V/OpenHCL environments;
it is not a verification option and is not needed for this Oracle capture.
The [padding and endianness check](../../patent/mainhub/dpia/shyware-protocol-conformance/oracle-signature-padding-check-20261010/README.md)
records identical DER before and after the proposed conversion: Oracle still
fails verification, while the saved GCP Milan report passes.

The binding is `code_sha256 || SHA256("shyware-enrollment-attestation-v1\0" ||
raw_public_key || raw_challenge)`. Verification checks report signature/certificate
chain, exact binding, VMPL 0 and non-debug policy. The separate GCP ceremony is a
positive report-verification control, not evidence about the live Oracle service.
The selected remediation path is Oracle certificate/firmware repair; persistent
GCP enrollment hosting was declined on 2026-10-10 because of its operating cost.
The verifier consumes the extended ioctl's separately returned certificate table
when present and rejects truncated tables. This correction is deployed on Oracle
and focused tests pass. Current Oracle captures return an empty table, so the
correction does not by itself resolve their signature failure. An explicit
certificate-selection check confirms the VCEK's chip ID, product family and TCB
match the report; current, committed and launch TCB versions also agree. See
[the follow-up evidence](../../patent/mainhub/dpia/shyware-protocol-conformance/oracle-enrollment-certificate-followup-20261010.md).

## License

TODO: pick and add a license before treating this as usable by others.
