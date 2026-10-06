// fetch-attestation is a small, standalone Go helper the enclave's Node.js
// server (server.js) shells out to for GET /attestation. It exists as a
// separate binary rather than Node code because fetching a real AMD SEV-SNP
// report requires calling SNP_GET_REPORT on /dev/sev-guest -- no Node native
// module for that exists, and this wraps Google's go-sev-guest client
// library (the same one used by GCE's own confidential-VM attestation
// tooling), rather than hand-rolling the ioctl and AMD ABI struct layout.
//
// Takes a 32-byte hex-encoded code-measurement hash on stdin (sha256 of the
// currently-running server.js, computed by the caller -- this binary has no
// opinion on what's being attested to, only on how to get a hardware report
// that commits to it) and writes a JSON object to stdout:
//
//	{"report_b64": "<raw 1184-byte SEV-SNP report, base64>",
//	 "cert_chain_b64": "<raw extended-report cert blob, base64 -- empty string if the platform didn't embed one, which is normal on several cloud providers including OCI; see README>",
//	 "report_data_hex": "<the 64-byte REPORT_DATA field actually embedded, hex>"}
//
// Deliberately does NOT verify the report against AMD's certificate chain
// here -- see README's "Attestation verification status" section (now
// written; it previously didn't exist despite this comment pointing at it)
// for why. As of 2026-10-06: ruled out, with concrete independent checks, not
// assumed -- KDS reachability, product-line misdetection, VLEK/VCEK
// confusion, a go-sev-guest-specific verify bug (reproduced identically via a
// from-scratch manual crypto/ecdsa check), and a one-off bad capture
// (reproduced identically on a second, independent live host). Narrowed to
// either a genuine AMD KDS bug specific to this Genoa/OCI shape (real,
// acknowledged precedent exists -- google/go-sev-guest#103/#115 -- though not
// confirmed as the identical symptom) or something in this host's SEV
// firmware's report production that no method tried so far can account for.
// Shipping only the report-fetch half, which IS confirmed working end-to-end
// against the real device, rather than a verification step that might be silently
// wrong. A relying party wanting full cryptographic assurance today must
// independently verify report_b64 against AMD's KDS themselves.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-sev-guest/client"
)

type output struct {
	ReportB64     string `json:"report_b64"`
	CertChainB64  string `json:"cert_chain_b64"`
	ReportDataHex string `json:"report_data_hex"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		fmt.Fprintln(os.Stderr, "fetch-attestation: expected a 32-byte hex code-measurement hash on stdin")
		os.Exit(1)
	}
	measurementHex := scanner.Text()
	measurement, err := hex.DecodeString(measurementHex)
	if err != nil || len(measurement) != 32 {
		fmt.Fprintf(os.Stderr, "fetch-attestation: stdin must be exactly 32 bytes of hex (sha256), got %d bytes: %v\n", len(measurement), err)
		os.Exit(1)
	}

	// REPORT_DATA is 64 bytes; the 32-byte code-measurement hash occupies
	// the first half, the rest stays zero. This is what lets anyone who
	// later inspects the raw report independently confirm "this specific
	// hardware-signed report commits to this specific server.js hash" --
	// the entire point of calling this at all.
	var reportData [64]byte
	copy(reportData[:], measurement)

	d, err := client.OpenDevice()
	if err != nil {
		fmt.Fprintln(os.Stderr, "fetch-attestation: open /dev/sev-guest:", err)
		os.Exit(1)
	}
	defer d.Close()

	rawReport, rawCerts, err := client.GetRawExtendedReport(d, reportData)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fetch-attestation: get extended report:", err)
		os.Exit(1)
	}

	out := output{
		ReportB64:     base64.StdEncoding.EncodeToString(rawReport),
		CertChainB64:  base64.StdEncoding.EncodeToString(rawCerts),
		ReportDataHex: hex.EncodeToString(reportData[:]),
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "fetch-attestation: encode output:", err)
		os.Exit(1)
	}
}
