//go:build linux && cgo

// Integration tests that drive the mock through go-sev-guest, the same way a
// real client would. They need root (to create the CUSE device) and the keys
// installed in /etc/sev-guest by ./configure.
package test

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	sevguest "github.com/Daviiap/sev-guest_device_mock/src"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
)

const (
	keysDir      = "/etc/sev-guest"
	devicePath   = "/dev/sev-guest"
	flagsOffset  = 0x48
	reportDataAt = 0x50
)

func TestMain(m *testing.M) {
	if os.Geteuid() != 0 {
		fmt.Println("skipping: integration tests must run as root")
		os.Exit(0)
	}
	if _, err := os.Stat(filepath.Join(keysDir, "vcek", "private.pem")); err != nil {
		fmt.Printf("skipping: keys not installed in %s (run ./configure)\n", keysDir)
		os.Exit(0)
	}

	kds := httptest.NewServer(sevguest.KDSHandler(keysDir))
	kdsURL = kds.URL

	device := sevguest.New()
	device.Start()
	code := m.Run()
	device.Stop()
	kds.Close()

	if _, err := os.Stat(devicePath); err == nil {
		fmt.Printf("%s still exists after Stop\n", devicePath)
		code = 1
	}
	os.Exit(code)
}

// kdsURL is the address of the mock KDS started by TestMain.
var kdsURL string

// kdsGetter sends the requests go-sev-guest makes to the KDS (the real one or
// the CRL distribution points in the certificates) to the mock.
type kdsGetter struct{}

func (kdsGetter) Get(rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	resp, err := http.Get(kdsURL + u.RequestURI())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", rawURL, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// verifyOptions trusts the mock ARK, ASK and ASVK, parsed from the KDS
// cert_chain files the same way go-sev-guest parses the real ones, and checks
// revocation against the mock KDS.
func verifyOptions(t *testing.T) *verify.Options {
	t.Helper()
	certs := &trust.ProductCerts{}
	for _, ek := range []string{"vcek", "vlek"} {
		data, err := os.ReadFile(filepath.Join(keysDir, ek, "cert_chain.pem"))
		if err != nil {
			t.Fatal(err)
		}
		if err := certs.FromKDSCertBytes(data); err != nil {
			t.Fatalf("parsing %s cert_chain.pem: %v", ek, err)
		}
	}
	root := &trust.AMDRootCerts{Product: "Milan", ProductLine: "Milan", ProductCerts: certs}
	return &verify.Options{
		TrustedRoots:     map[string][]*trust.AMDRootCerts{"Milan": {root}},
		Getter:           kdsGetter{},
		CheckRevocations: true,
	}
}

func openDevice(t *testing.T) client.Device {
	t.Helper()
	d, err := client.OpenDevice()
	if err != nil {
		t.Fatalf("OpenDevice: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func reportData() [64]byte {
	var data [64]byte
	for i := range data {
		data[i] = byte(i)
	}
	return data
}

// signerType returns "vcek" or "vlek" from the SIGNING_KEY field of the report.
func signerType(t *testing.T, report []byte) string {
	t.Helper()
	switch (report[flagsOffset] >> 2) & 0x7 {
	case 0:
		return "vcek"
	case 1:
		return "vlek"
	}
	t.Fatalf("unexpected SIGNING_KEY in flags 0x%x", report[flagsOffset])
	return ""
}

func readPEMCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s: no PEM block", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func checkReport(t *testing.T, report []byte, cert *x509.Certificate) {
	t.Helper()
	data := reportData()
	if !bytes.Equal(report[reportDataAt:reportDataAt+64], data[:]) {
		t.Errorf("report_data does not match the request")
	}
	if err := verify.SnpReportSignature(report, cert); err != nil {
		t.Errorf("report signature: %v", err)
	}
}

func TestGetReport(t *testing.T) {
	d := openDevice(t)
	report, err := client.GetRawReport(d, reportData())
	if err != nil {
		t.Fatalf("GetRawReport: %v", err)
	}
	ek := signerType(t, report)
	checkReport(t, report, readPEMCert(t, filepath.Join(keysDir, ek, "public.pem")))
}

func TestGetExtendedReport(t *testing.T) {
	d := openDevice(t)
	report, certs, err := client.GetRawExtendedReport(d, reportData())
	if err != nil {
		t.Fatalf("GetRawExtendedReport: %v", err)
	}

	table := new(abi.CertTable)
	if err := table.Unmarshal(certs); err != nil {
		t.Fatalf("parsing cert table: %v", err)
	}

	ekGUID := abi.VcekGUID
	if signerType(t, report) == "vlek" {
		ekGUID = abi.VlekGUID
	}
	parse := func(guid string) *x509.Certificate {
		raw, err := table.GetByGUIDString(guid)
		if err != nil {
			t.Fatalf("cert %s not in table: %v", guid, err)
		}
		// Hosts provide DER, so a plain DER parse must work.
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			t.Fatalf("cert %s is not DER: %v", guid, err)
		}
		return cert
	}
	ek, ask, ark := parse(ekGUID), parse(abi.AskGUID), parse(abi.ArkGUID)

	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(ark)
	intermediates.AddCert(ask)
	if _, err := ek.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates}); err != nil {
		t.Errorf("endorsement key chain: %v", err)
	}

	checkReport(t, report, ek)
}

func TestInvalidVmplIsRejected(t *testing.T) {
	d := openDevice(t)
	if _, err := client.GetRawReportAtVmpl(d, reportData(), 4); err == nil {
		t.Fatal("expected an error for vmpl 4")
	}
}

// TestVerifyExtendedReport runs the full go-sev-guest verification on an
// extended report: certificate schema, chain, CRL and report signature.
func TestVerifyExtendedReport(t *testing.T) {
	d := openDevice(t)
	report, certs, err := client.GetRawExtendedReport(d, reportData())
	if err != nil {
		t.Fatalf("GetRawExtendedReport: %v", err)
	}
	attestation, err := abi.ReportCertsToProto(append(report, certs...))
	if err != nil {
		t.Fatalf("ReportCertsToProto: %v", err)
	}
	opts := verifyOptions(t)
	opts.DisableCertFetching = true
	if err := verify.SnpAttestation(attestation, opts); err != nil {
		t.Fatalf("SnpAttestation: %v", err)
	}
}

// TestVerifyReportWithVcekFromKDS verifies a plain report, letting go-sev-guest
// fetch the VCEK from the mock KDS as it does with the real one.
func TestVerifyReportWithVcekFromKDS(t *testing.T) {
	d := openDevice(t)
	raw, err := client.GetRawReport(d, reportData())
	if err != nil {
		t.Fatalf("GetRawReport: %v", err)
	}
	if signerType(t, raw) != "vcek" {
		t.Skip("report signed by the VLEK, which the KDS does not serve")
	}
	report, err := abi.ReportToProto(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify.SnpReport(report, verifyOptions(t)); err != nil {
		t.Fatalf("SnpReport: %v", err)
	}
}
