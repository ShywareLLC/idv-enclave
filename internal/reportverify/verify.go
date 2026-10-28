package reportverify

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/verify"
)

type Verdict struct {
	HardwareVerified  bool   `json:"hardware_verified"`
	ReportDataBound   bool   `json:"report_data_bound"`
	LaunchMeasurement string `json:"launch_measurement"`
	VMPL              uint32 `json:"vmpl"`
	Debug             bool   `json:"debug"`
	VerificationError string `json:"verification_error,omitempty"`
}

// Verify uses AMD's independently trusted certificate chain, not a server's
// claim that its own report verified. Expected data comes from the verifier.
func Verify(raw, expected []byte) (Verdict, error) {
	return VerifyWithCertificates(raw, nil, expected)
}

// Extended SNP ioctls return the certificate table separately from the report.
func VerifyWithCertificates(raw, certificates, expected []byte) (Verdict, error) {
	var verdict Verdict
	if len(expected) != 64 {
		return verdict, fmt.Errorf("expected report data must be 64 bytes")
	}
	if len(certificates) > 0 {
		if len(raw) != abi.ReportSize {
			return verdict, fmt.Errorf("separate certificate table requires an unbundled %d-byte report", abi.ReportSize)
		}
		if len(certificates) < 24 {
			return verdict, fmt.Errorf("truncated certificate table header")
		}
	}
	evidence := append(append([]byte(nil), raw...), certificates...)
	attestation, err := abi.ReportCertsToProto(evidence)
	if err != nil {
		return verdict, err
	}
	report := attestation.Report
	verdict.LaunchMeasurement = hex.EncodeToString(report.Measurement)
	verdict.VMPL = report.Vmpl
	policy, err := abi.ParseSnpPolicy(report.Policy)
	if err != nil {
		return verdict, err
	}
	verdict.Debug = policy.Debug
	if !bytes.Equal(report.ReportData, expected) {
		return verdict, fmt.Errorf("challenge/key/code binding mismatch")
	}
	verdict.ReportDataBound = true
	if report.Vmpl != 0 || policy.Debug {
		return verdict, fmt.Errorf("unacceptable VMPL or debug policy")
	}
	if err := verify.SnpAttestation(attestation, verify.DefaultOptions()); err != nil {
		return verdict, err
	}
	verdict.HardwareVerified = true
	return verdict, nil
}
