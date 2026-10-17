package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	reportSize = 1184
	// reported_tcb starts at offset 0x180 and chip_id at 0x1A0. Since report
	// version 3, CPUID family, model and stepping are at 0x188, 0x189, 0x18A.
	reportedTcbOffset = 0x180
	cpuidOffset       = 0x188
	chipIdOffset      = 0x1A0
	chipIdSize        = 64

	milanFamily = 0x19
	milanModel  = 0x01

	// Validity periods of the real certificates.
	rootValidityYears = 25 // ARK, ASK and ASVK
	ekValidityYears   = 7  // VCEK and VLEK
)

// defaultReportPaths is the search order for report.bin, the same one the
// device mock uses, so the generated certificates match the served reports.
var defaultReportPaths = []string{"/etc/sev-guest/report.bin", "report.bin"}

type Config struct {
	KdsPort int `json:"kds_port"`
}

var appConfig = Config{KdsPort: 8080}

// loadConfig reads the config file. A missing file is only an error when its
// path was given explicitly.
func loadConfig(path string, explicit bool) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) && !explicit {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}
	if err := json.Unmarshal(data, &appConfig); err != nil {
		return fmt.Errorf("parsing config %s: %w", path, err)
	}
	return nil
}

// amdName returns the DER distinguished name in the layout of the real AMD
// certificates: UTF8String values in the order OU, C, L, ST, O, CN. pkix.Name
// cannot express it, as it uses its own order and PrintableString.
func amdName(commonName string) []byte {
	attrs := []struct {
		oid   asn1.ObjectIdentifier
		value string
	}{
		{asn1.ObjectIdentifier{2, 5, 4, 11}, "Engineering"},
		{asn1.ObjectIdentifier{2, 5, 4, 6}, "US"},
		{asn1.ObjectIdentifier{2, 5, 4, 7}, "Santa Clara"},
		{asn1.ObjectIdentifier{2, 5, 4, 8}, "CA"},
		{asn1.ObjectIdentifier{2, 5, 4, 10}, "Advanced Micro Devices"},
		{asn1.ObjectIdentifier{2, 5, 4, 3}, commonName},
	}
	var rdns pkix.RDNSequence
	for _, a := range attrs {
		value := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String, Bytes: []byte(a.value)}
		rdns = append(rdns, pkix.RelativeDistinguishedNameSET{{Type: a.oid, Value: value}})
	}
	der, err := asn1.Marshal(rdns)
	if err != nil {
		panic(err) // only fixed, well-formed values are marshaled here
	}
	return der
}

// validity returns the validity period of a certificate issued now.
func validity(years int) (time.Time, time.Time) {
	notBefore := time.Now().UTC().Truncate(time.Second)
	return notBefore, notBefore.AddDate(years, 0, 0)
}

func crlURL(ekType string) string {
	return fmt.Sprintf("http://localhost:%d/%s/v1/Milan/crl", appConfig.KdsPort, ekType)
}

func generatePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 4096)
}

func createCertificate(template, parent *x509.Certificate, pub, priv any) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func generateARK() (*x509.Certificate, *rsa.PrivateKey, error) {
	caPrivateKey, err := generatePrivateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("generating ARK private key: %w", err)
	}

	notBefore, notAfter := validity(rootValidityYears)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(65536),
		RawSubject:            amdName("ARK-Milan"),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SignatureAlgorithm:    x509.SHA384WithRSAPSS,
		BasicConstraintsValid: true,
		IsCA:                  true,
		CRLDistributionPoints: []string{crlURL("vcek")},
	}

	cert, err := createCertificate(caTemplate, caTemplate, caPrivateKey.Public(), caPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("generating ARK certificate: %w", err)
	}
	return cert, caPrivateKey, nil
}

func generateASK(caCert *x509.Certificate, caPrivateKey *rsa.PrivateKey, ekType string) (*x509.Certificate, *rsa.PrivateKey, error) {
	commonName := "SEV-Milan"
	serialNumber := int64(65537)
	if ekType == "vlek" {
		commonName = "SEV-VLEK-Milan"
		serialNumber = 65793
	}

	askPrivateKey, err := generatePrivateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("generating %s ASK private key: %w", ekType, err)
	}

	notBefore, notAfter := validity(rootValidityYears)
	askTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(serialNumber),
		SignatureAlgorithm:    x509.SHA384WithRSAPSS,
		RawSubject:            amdName(commonName),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		CRLDistributionPoints: []string{crlURL(ekType)},
	}

	cert, err := createCertificate(askTemplate, caCert, askPrivateKey.Public(), caPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("generating %s ASK certificate: %w", ekType, err)
	}
	return cert, askPrivateKey, nil
}

type ReportInfo struct {
	BootLoader uint8
	TEE        uint8
	SNP        uint8
	Microcode  uint8
	ChipId     []byte
	// ProductName is the VCEK productName extension, e.g. Milan-B0.
	ProductName string
}

// readReport returns report.bin from path or, when path is empty, from the
// default search paths. It returns nil if no report was found in the defaults.
func readReport(path string) ([]byte, string, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		return data, path, err
	}
	for _, p := range defaultReportPaths {
		data, err := os.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		return data, p, err
	}
	return nil, "", nil
}

func getReportInfo(reportPath string) (ReportInfo, error) {
	info := ReportInfo{
		BootLoader:  0x03,
		TEE:         0x00,
		SNP:         0x08,
		Microcode:   0x73,
		ChipId:      make([]byte, chipIdSize),
		ProductName: "Milan-B0",
	}

	data, path, err := readReport(reportPath)
	if err != nil {
		return info, fmt.Errorf("reading report: %w", err)
	}
	if data == nil {
		log.Printf("report.bin not found, using default values: BootLoader=%d, TEE=%d, SNP=%d, Microcode=%d",
			info.BootLoader, info.TEE, info.SNP, info.Microcode)
		return info, nil
	}
	if len(data) < reportSize {
		return info, fmt.Errorf("%s has %d bytes, expected %d", path, len(data), reportSize)
	}

	// TCB_VERSION: boot_loader, tee, 4 reserved bytes, snp, microcode
	info.BootLoader = data[reportedTcbOffset]
	info.TEE = data[reportedTcbOffset+1]
	info.SNP = data[reportedTcbOffset+6]
	info.Microcode = data[reportedTcbOffset+7]
	copy(info.ChipId, data[chipIdOffset:chipIdOffset+chipIdSize])

	// The stepping is only in the report since version 3; older ones keep B0.
	version := binary.LittleEndian.Uint32(data[0:4])
	family, model, stepping := data[cpuidOffset], data[cpuidOffset+1], data[cpuidOffset+2]
	if version >= 3 {
		if family != milanFamily || model != milanModel {
			return info, fmt.Errorf("%s is from CPU family 0x%x model 0x%x, only Milan (0x%x/0x%x) is supported",
				path, family, model, milanFamily, milanModel)
		}
		info.ProductName = fmt.Sprintf("Milan-B%d", stepping)
	}

	log.Printf("Loaded values from %s: Product=%s, BootLoader=%d, TEE=%d, SNP=%d, Microcode=%d, ChipId=%x...",
		path, info.ProductName, info.BootLoader, info.TEE, info.SNP, info.Microcode, info.ChipId[:8])
	return info, nil
}

func generateChipKey(askCert *x509.Certificate, askPrivateKey *rsa.PrivateKey, ekType string, info ReportInfo) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating %s key pair: %w", ekType, err)
	}

	// Like the real VCEK: serial 0 and no extensions besides AMD's, so no
	// CRL distribution point nor authority key identifier.
	notBefore, notAfter := validity(ekValidityYears)
	template := &x509.Certificate{
		SerialNumber:       big.NewInt(0),
		SignatureAlgorithm: x509.SHA384WithRSAPSS,
		RawSubject:         amdName("SEV-" + strings.ToUpper(ekType)),
		NotBefore:          notBefore,
		NotAfter:           notAfter,
	}

	mustMarshal := func(v any, params string) []byte {
		b, err := asn1.MarshalWithParams(v, params)
		if err != nil {
			panic(err) // only fixed, well-formed values are marshaled here
		}
		return b
	}
	oid := func(arcs ...int) asn1.ObjectIdentifier {
		return append(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1}, arcs...)
	}
	asn1Zero := mustMarshal(0, "")

	// VLEK productName has no stepping.
	productName := info.ProductName
	if ekType == "vlek" {
		productName = "Milan"
	}

	// Same extensions, in the same order, as the real VCEK.
	template.ExtraExtensions = []pkix.Extension{
		{Id: oid(1), Value: asn1Zero},
		{Id: oid(2), Value: mustMarshal(productName, "ia5")},
		{Id: oid(3, 1), Value: mustMarshal(int(info.BootLoader), "")},
		{Id: oid(3, 2), Value: mustMarshal(int(info.TEE), "")},
		{Id: oid(3, 4), Value: asn1Zero},
		{Id: oid(3, 5), Value: asn1Zero},
		{Id: oid(3, 6), Value: asn1Zero},
		{Id: oid(3, 7), Value: asn1Zero},
		{Id: oid(3, 3), Value: mustMarshal(int(info.SNP), "")},
		{Id: oid(3, 8), Value: mustMarshal(int(info.Microcode), "")},
	}
	if ekType == "vlek" {
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: oid(5), Value: mustMarshal("go-sev-guest", "ia5")})
	} else {
		// The KDS puts the raw chip ID in the HWID extension, without the
		// OCTET STRING tag.
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: oid(4), Value: info.ChipId})
	}

	// Go adds an authority key identifier whenever the parent has a subject
	// key identifier, so sign with a copy of the ASK without one.
	parent := *askCert
	parent.SubjectKeyId = nil

	cert, err := createCertificate(template, &parent, key.Public(), askPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("generating %s certificate: %w", ekType, err)
	}
	return cert, key, nil
}

func generateCRL(arkCert *x509.Certificate, arkKey *rsa.PrivateKey) (*x509.RevocationList, error) {
	crlTemplate := x509.RevocationList{
		Number:             big.NewInt(4),
		SignatureAlgorithm: x509.SHA384WithRSAPSS,
		Issuer:             arkCert.Issuer,
		RawIssuer:          arkCert.RawIssuer,
		AuthorityKeyId:     arkCert.AuthorityKeyId,
		ThisUpdate:         time.Now().UTC().Truncate(time.Second),
		NextUpdate:         time.Now().UTC().Add(1000 * 24 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, arkCert, arkKey)
	if err != nil {
		return nil, fmt.Errorf("generating CRL: %w", err)
	}
	return x509.ParseRevocationList(crlDER)
}

func pemBytes(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func writeFile(path string, data []byte, perm os.FileMode) error {
	if err := os.WriteFile(path, data, perm); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

func generateKeys(outDir string, arkCert *x509.Certificate, arkKey *rsa.PrivateKey, ekType string, info ReportInfo) error {
	askCert, askKey, err := generateASK(arkCert, arkKey, ekType)
	if err != nil {
		return err
	}
	askCRL, err := generateCRL(arkCert, arkKey)
	if err != nil {
		return err
	}
	ekCert, ekKey, err := generateChipKey(askCert, askKey, ekType, info)
	if err != nil {
		return err
	}

	if err := askCRL.CheckSignatureFrom(arkCert); err != nil {
		return fmt.Errorf("verifying %s CRL: %w", ekType, err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(arkCert)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(askCert)
	if _, err := ekCert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates}); err != nil {
		return fmt.Errorf("verifying %s certificate: %w", ekType, err)
	}

	ekKeyBytes, err := x509.MarshalECPrivateKey(ekKey)
	if err != nil {
		return fmt.Errorf("marshaling %s key: %w", ekType, err)
	}

	dir := filepath.Join(outDir, ekType)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Same order as the KDS cert_chain: ASK (or ASVK) first, then ARK.
	certChain := append(pemBytes("CERTIFICATE", askCert.Raw), pemBytes("CERTIFICATE", arkCert.Raw)...)
	files := []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{"ask.pem", pemBytes("CERTIFICATE", askCert.Raw), 0644},
		{"ask.key", pemBytes("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(askKey)), 0600},
		{"crl.der", askCRL.Raw, 0644},
		{"cert_chain.pem", certChain, 0644},
		{ekType + ".pem", pemBytes("CERTIFICATE", ekCert.Raw), 0644},
		{ekType + ".key", pemBytes("EC PRIVATE KEY", ekKeyBytes), 0600},
	}
	for _, f := range files {
		if err := writeFile(filepath.Join(dir, f.name), f.data, f.perm); err != nil {
			return err
		}
	}
	return nil
}

func run() error {
	configPath := flag.String("config", "config.json", "Path to the configuration JSON file")
	reportPath := flag.String("report", "", "Path to report.bin (default: "+strings.Join(defaultReportPaths, ", then ")+")")
	outDir := flag.String("out", "keys", "Output directory for the generated keys")
	flag.Parse()

	configExplicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "config" {
			configExplicit = true
		}
	})
	if err := loadConfig(*configPath, configExplicit); err != nil {
		return err
	}

	info, err := getReportInfo(*reportPath)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return err
	}

	arkCert, arkKey, err := generateARK()
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(*outDir, "ark.pem"), pemBytes("CERTIFICATE", arkCert.Raw), 0644); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(*outDir, "ark.key"), pemBytes("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(arkKey)), 0600); err != nil {
		return err
	}

	for _, ekType := range []string{"vcek", "vlek"} {
		if err := generateKeys(*outDir, arkCert, arkKey, ekType, info); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
