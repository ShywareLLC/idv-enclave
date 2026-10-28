// verify-attestation independently verifies a saved report with a verifier-supplied binding.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ShywareLLC/idv-enclave/internal/reportverify"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: verify-attestation report.json expected-report-data-hex")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var input struct {
		Report       string `json:"report_b64"`
		Certificates string `json:"cert_chain_b64"`
	}
	if err = json.Unmarshal(data, &input); err != nil {
		panic(err)
	}
	raw, err := base64.StdEncoding.DecodeString(input.Report)
	if err != nil {
		panic(err)
	}
	expected, err := hex.DecodeString(os.Args[2])
	certificates, certificateErr := base64.StdEncoding.DecodeString(input.Certificates)
	if certificateErr != nil {
		panic(certificateErr)
	}
	if err != nil {
		panic(err)
	}
	verdict, err := reportverify.VerifyWithCertificates(raw, certificates, expected)
	if err != nil {
		verdict.VerificationError = err.Error()
	}
	json.NewEncoder(os.Stdout).Encode(verdict)
	if err != nil {
		os.Exit(1)
	}
}
