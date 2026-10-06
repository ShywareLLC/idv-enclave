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
read exactly what it does rather than trust a description of it. This is the
actual, complete, deployed source (aside from environment-specific secrets,
which are never in code — see below). Nothing in here is specific to
Populist; the pattern applies to any `shyvoting-v1` deployment using Didit,
per the docs page above.

## What it does

- `POST /attest` — given `{session_id, voter_pub_key, poll_id}`, independently
  checks the session with Didit's real API and signs
  `sha256(voter_pub_key || poll_id)` only if genuinely `Approved`.
  Self-authenticating: no auth needed, since a forged request simply cannot
  produce a valid Didit `Approved` response.
- `POST /sign-poll-create` — signs an operator-authorized `TxTypePollCreate`
  transaction with a *separate* RSA-2048 key (so compromising one signing
  purpose doesn't compromise the other). No independent third party to check
  a poll-create request against, so this one needs a real shared-secret auth.
- `POST /audit-log` — forwards an already-HMAC-validated Didit webhook record
  to OCI Object Storage for durable, append-only storage. Shared-secret auth
  for the same reason as above.
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

This achieves independent, oracle-resistant signing. It does **not** yet
achieve full SEV-SNP attestation *report* verification (proving to an outside
party that this exact code, and no other, produced a given signature) — see
the docs page for what today's guarantee actually rests on, and what's
still open.

## Attestation verification status

As of 2026-10-06, `go-sev-guest`'s `verify.SnpAttestation` fails against
reports fetched from both OCI SEV-SNP hosts this repo runs on
(`populist-idv-enclave` and the now-terminated `zk-setup-ephemeral` ceremony
VM — see `ShywareLLC/core/zk-ceremony-2026-10-06/README.md`), with
`report signature verification error: x509: ECDSA verification failure`.

**What's been ruled out, concretely, not assumed:**
- Network/KDS reachability — confirmed live, both the AMD root cert chain and
  the chip's VCEK cert fetch successfully (`200`s) directly from
  `kdsintf.amd.com`.
- Wrong product line — report explicitly decodes as `Genoa`; forcing
  `SEV_PRODUCT_GENOA` in `Options` makes no difference (earlier finding,
  reconfirmed).
- VLEK/VCEK confusion — report's `SignerInfo` explicitly says `VCEK (0)`, not
  VLEK; the correct VCEK (by chip ID + `ReportedTcb`, using the library's own
  URL builder, not a hand-rolled one) is what gets fetched.
- A bug in `go-sev-guest`'s own verify code — reproduced the exact same
  `false` result via a fully independent manual check (`crypto/ecdsa.Verify`
  directly against the fetched VCEK's parsed public key, SHA-384 over the
  signed report region, R/S extracted per AMD's own byte layout) outside the
  library entirely. Same answer both ways.
- A one-off bad capture — reproduced identically on a second, independent,
  currently-live host (`populist-idv-enclave`, fetched fresh), not just the
  terminated ceremony VM's one report.

**What this narrows it to:** either a genuine AMD KDS-side bug specific to
this Genoa/OCI shape — there is real, acknowledged precedent for exactly this
class of problem (`google/go-sev-guest` issue
[#103](https://github.com/google/go-sev-guest/issues/103), Genoa-specific,
closed as a duplicate of
[#115](https://github.com/google/go-sev-guest/issues/115), where AMD
confirmed a KDS bug directly to the library's maintainer — though #115's
specific symptom, a stepping/productName mismatch, is not a confirmed match
for *this* symptom, a clean VCEK fetch whose signature then fails) — or
something in how this host's SEV firmware produces the report that neither
`go-sev-guest` nor a from-scratch manual check can account for. Resolving
further likely requires the same path #103 took: filing a new issue with
`go-sev-guest`'s maintainers with the exact chip ID and TCB version, since
they have a working escalation path directly to AMD's KDS team.

**Until this closes, nothing here or in `core/zk-ceremony-2026-10-06` should
be described as independently, cryptographically verified** — the report was
captured and is internally self-consistent (chip ID and TCB values parse and
resolve to a real AMD-issued cert), but its signature does not yet verify
against that cert by any method tried.

## License

TODO: pick and add a license before treating this as usable by others.
