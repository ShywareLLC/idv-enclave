// fetch-attestation captures a fresh SNP report for the caller's 64-byte
// challenge/key/code binding and verifies its signature against AMD's roots.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/ShywareLLC/idv-enclave/internal/reportverify"
	"github.com/google/go-sev-guest/client"
)

type output struct {
	ReportB64     string               `json:"report_b64"`
	CertChainB64  string               `json:"cert_chain_b64"`
	ReportDataHex string               `json:"report_data_hex"`
	Verdict       reportverify.Verdict `json:"verification"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		fmt.Fprintln(os.Stderr, "fetch-attestation: expected a 64-byte hex report-data binding on stdin")
		os.Exit(1)
	}
	measurementHex := scanner.Text()
	measurement, err := hex.DecodeString(measurementHex)
	if err != nil || len(measurement) != 64 {
		fmt.Fprintf(os.Stderr, "fetch-attestation: stdin must be exactly 64 bytes of hex, got %d bytes: %v\n", len(measurement), err)
		os.Exit(1)
	}

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

	verdict, verifyErr := reportverify.VerifyWithCertificates(rawReport, rawCerts, reportData[:])
	if verifyErr != nil {
		verdict.VerificationError = verifyErr.Error()
	}
	out := output{
		Verdict:       verdict,
		ReportB64:     base64.StdEncoding.EncodeToString(rawReport),
		CertChainB64:  base64.StdEncoding.EncodeToString(rawCerts),
		ReportDataHex: hex.EncodeToString(reportData[:]),
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "fetch-attestation: encode output:", err)
		os.Exit(1)
	}
}
