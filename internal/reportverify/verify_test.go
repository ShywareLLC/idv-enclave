package reportverify

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/google/go-sev-guest/abi"
	sevtesting "github.com/google/go-sev-guest/testing"
)

func TestMalformedSeparateCertificateTableIsRejected(t *testing.T) {
	var binding [64]byte
	raw := sevtesting.TestRawReport(binding)
	certificates := make([]byte, 48)
	certificates[0] = 1
	binary.LittleEndian.PutUint32(certificates[16:20], 48)
	binary.LittleEndian.PutUint32(certificates[20:24], 100)
	verdict, err := VerifyWithCertificates(raw[:abi.ReportSize], certificates, binding[:])
	if err == nil || verdict.HardwareVerified || verdict.ReportDataBound {
		t.Fatalf("malformed certificate table accepted: %+v, %v", verdict, err)
	}
}

func TestTruncatedSeparateCertificateTableIsRejected(t *testing.T) {
	var binding [64]byte
	raw := sevtesting.TestRawReport(binding)
	verdict, err := VerifyWithCertificates(raw[:abi.ReportSize], []byte{1}, binding[:])
	if err == nil || !strings.Contains(err.Error(), "truncated certificate table") || verdict.HardwareVerified || verdict.ReportDataBound {
		t.Fatalf("truncated certificate table accepted: %+v, %v", verdict, err)
	}
}

func TestChallengeMismatchFailsBeforeCertificateFetching(t *testing.T) {
	var binding [64]byte
	raw := sevtesting.TestRawReport(binding)
	binding[0] = 1
	verdict, err := Verify(raw[:abi.ReportSize], binding[:])
	if err == nil || !strings.Contains(err.Error(), "binding mismatch") || verdict.HardwareVerified || verdict.ReportDataBound {
		t.Fatalf("challenge mismatch accepted: %+v, %v", verdict, err)
	}
}
