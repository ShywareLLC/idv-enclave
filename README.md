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

## Configuration (all via environment, nothing hardcoded)

| Variable | Purpose |
|---|---|
| `DIDIT_SECRET_OCID` | OCI Vault secret OCID holding the Didit API key (fetched via instance-principal auth, kept in memory only, never logged) |
| `AUDIT_LOG_SHARED_SECRET` | Bearer secret gating `POST /audit-log` |
| `AUDIT_LOG_NAMESPACE`, `AUDIT_LOG_BUCKET` | OCI Object Storage target for audit records |
| `POLL_SIGNING_SHARED_SECRET` | Bearer secret gating `POST /sign-poll-create` |
| `PORT` (default `8443`), `TLS_KEY_PATH`, `TLS_CERT_PATH` | Listen config; runs plain HTTP if TLS paths aren't set (put a TLS-terminating proxy in front in that case) |

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

## License

TODO: pick and add a license before treating this as usable by others.
