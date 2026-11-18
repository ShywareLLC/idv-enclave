// Didit v3 decisions list each feature as an array (id_verifications,
// poa_verifications, liveness_checks, face_matches, nfc_verifications), one
// item per workflow node; v2 had single objects (id_verification, poa, ...).
// This keeps the v3 payload and adds the singular names the rest of the code
// reads, taking the last approved item (else the last item). A v2-shaped
// decision passes through unchanged. Mirrored in POP-U-LIST/diditDecision.cjs.

const STATUSES = ["Approved", "Declined", "In Review", "In Progress", "Not Started", "Expired",
  "Abandoned", "Kyc Expired", "KYC Expired", "Resubmitted", "Awaiting User"];

/// Didit's docs show both "Approved" and "APPROVED"; compare in one casing.
function normalizeDiditStatus(status) {
  if (typeof status !== "string") return status;
  return STATUSES.find(s => s.toLowerCase() === status.trim().toLowerCase()) || status;
}

function pick(items) {
  if (!Array.isArray(items) || !items.length) return undefined;
  for (let i = items.length - 1; i >= 0; i--) {
    if (normalizeDiditStatus(items[i]?.status) === "Approved") return items[i];
  }
  return items[items.length - 1];
}

function normalizeDiditDecision(decision) {
  if (!decision || typeof decision !== "object" || Array.isArray(decision)) return decision;
  const out = {...decision};
  const map = {id_verification: "id_verifications", poa: "poa_verifications", liveness: "liveness_checks",
    face_match: "face_matches", nfc: "nfc_verifications", aml: "aml_screenings"};
  for (const [single, plural] of Object.entries(map)) {
    if (out[single] == null) {
      const item = pick(out[plural]);
      if (item !== undefined) out[single] = item;
    }
  }
  if (out.status) out.status = normalizeDiditStatus(out.status);
  return out;
}

module.exports = {normalizeDiditDecision, normalizeDiditStatus};
