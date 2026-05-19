package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

type Config struct {
	KdsPort int `json:"kds_port"`
}

var appConfig Config

func init() {
	appConfig.KdsPort = 8080 // default
	data, err := os.ReadFile("config.json")
	if err != nil {
		data, err = os.ReadFile("../config.json")
	}
	if err == nil {
		json.Unmarshal(data, &appConfig)
	}
}

func generatePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 4096)
}

func generateARK() (*x509.Certificate, *rsa.PrivateKey) {
	caPrivateKey, err := generatePrivateKey()
	if err != nil {
		fmt.Printf("Failed to generate CA private key: %v", err)
		return nil, nil
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(65536),
		Subject: pkix.Name{
			OrganizationalUnit: []string{"Engineering"},
			Country:            []string{"US"},
			Locality:           []string{"Santa Clara"},
			Province:           []string{"CA"},
			Organization:       []string{"Advanced Micro Devices"},
			CommonName:         "ARK-Milan",
		},
		Issuer: pkix.Name{
			OrganizationalUnit: []string{"Engineering"},
			Country:            []string{"US"},
			Locality:           []string{"Santa Clara"},
			Province:           []string{"CA"},
			Organization:       []string{"Advanced Micro Devices"},
			CommonName:         "ARK-Milan",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SignatureAlgorithm:    x509.SHA384WithRSAPSS,
		BasicConstraintsValid: true,
		IsCA:                  true,
		CRLDistributionPoints: []string{fmt.Sprintf("http://localhost:%d/vcek/v1/Milan/crl", appConfig.KdsPort)},
	}

	caCertificate, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPrivateKey.Public(), caPrivateKey)
	if err != nil {
		fmt.Printf("Failed to generate CA certificate: %v", err)
		return nil, nil
	}

	cert, err := x509.ParseCertificate(caCertificate)
	if err != nil {
		fmt.Printf("Failed to generate CA certificate: %v", err)
		return nil, nil
	}

	return cert, caPrivateKey
}

func generateASK(caTemplate *x509.Certificate, caPrivateKey *rsa.PrivateKey, ekType string) (*x509.Certificate, *rsa.PrivateKey) {
	var commonName string
	var crlUrl string
	var serialNumber int64
	if ekType == "vlek" {
		commonName = "SEV-VLEK-Milan"
		crlUrl = fmt.Sprintf("http://localhost:%d/vlek/v1/Milan/crl", appConfig.KdsPort)
		serialNumber = 65793
	} else {
		commonName = "SEV-Milan"
		crlUrl = fmt.Sprintf("http://localhost:%d/vcek/v1/Milan/crl", appConfig.KdsPort)
		serialNumber = 65537
	}
	askPrivateKey, err := generatePrivateKey()
	if err != nil {
		fmt.Printf("Failed to generate ask CA private key: %v", err)
		return nil, nil
	}

	askTemplate := &x509.Certificate{
		SerialNumber:       big.NewInt(serialNumber),
		SignatureAlgorithm: x509.SHA384WithRSAPSS,
		Subject: pkix.Name{
			OrganizationalUnit: []string{"Engineering"},
			Country:            []string{"US"},
			Locality:           []string{"Santa Clara"},
			Province:           []string{"CA"},
			Organization:       []string{"Advanced Micro Devices"},
			CommonName:         commonName,
		},
		Issuer: pkix.Name{
			OrganizationalUnit: []string{"Engineering"},
			Country:            []string{"US"},
			Locality:           []string{"Santa Clara"},
			Province:           []string{"CA"},
			Organization:       []string{"Advanced Micro Devices"},
			CommonName:         "ARK-Milan",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		CRLDistributionPoints: []string{crlUrl},
	}

	askCertificate, err := x509.CreateCertificate(rand.Reader, askTemplate, caTemplate, askPrivateKey.Public(), caPrivateKey)
	if err != nil {
		fmt.Printf("Failed to generate ask CA certificate: %v", err)
		return nil, nil
	}

	cert, err := x509.ParseCertificate(askCertificate)
	if err != nil {
		fmt.Printf("Failed to generate ask CA certificate: %v", err)
		return nil, nil
	}

	return cert, askPrivateKey
}

type ReportInfo struct {
	BootLoader uint8
	TEE        uint8
	SNP        uint8
	Microcode  uint8
	ChipId     []byte
}

func getReportInfo() ReportInfo {
	info := ReportInfo{
		BootLoader: 0x03,
		TEE:        0x00,
		SNP:        0x08,
		Microcode:  0x73,
		ChipId:     make([]byte, 64),
	}

	data, err := os.ReadFile("report.bin")
	if err != nil {
		data, err = os.ReadFile("../report.bin")
	}

	if err == nil && len(data) >= 1184 {
		// reported_tcb starts at offset 384
		info.BootLoader = data[384]
		info.TEE = data[385]
		info.SNP = data[390]
		info.Microcode = data[391]

		// chip_id is 64 bytes starting at offset 416
		info.ChipId = make([]byte, 64)
		copy(info.ChipId, data[416:480])

		fmt.Printf("Loaded values from report.bin: BootLoader=%d, TEE=%d, SNP=%d, Microcode=%d, ChipId=%x...\n",
			info.BootLoader, info.TEE, info.SNP, info.Microcode, info.ChipId[:8])
	} else {
		fmt.Printf("Using default values: BootLoader=%d, TEE=%d, SNP=%d, Microcode=%d\n",
			info.BootLoader, info.TEE, info.SNP, info.Microcode)
	}

	return info
}

func generateChipKey(askCert *x509.Certificate, askPrivateKey *rsa.PrivateKey, ekType string) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate ECDSA key pair: %v", err)
		return nil, nil
	}

	var crlUrl string
	if ekType == "vlek" {
		crlUrl = fmt.Sprintf("http://localhost:%d/vlek/v1/Milan/crl", appConfig.KdsPort)
	} else {
		crlUrl = fmt.Sprintf("http://localhost:%d/vcek/v1/Milan/crl", appConfig.KdsPort)
	}

	template := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		SignatureAlgorithm: x509.SHA384WithRSAPSS,
		Subject: pkix.Name{
			OrganizationalUnit: []string{"Engineering"},
			Country:            []string{"US"},
			Locality:           []string{"Santa Clara"},
			Province:           []string{"CA"},
			Organization:       []string{"Advanced Micro Devices"},
			CommonName:         "SEV-" + strings.ToUpper(ekType),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		CRLDistributionPoints: []string{crlUrl},
	}

	asn1Zero, _ := asn1.Marshal(0)
	productNameAsn1, _ := asn1.MarshalWithParams("Milan", "ia5")

	info := getReportInfo()
	bootLoaderAsn1, _ := asn1.Marshal(int(info.BootLoader))
	teeAsn1, _ := asn1.Marshal(int(info.TEE))
	snpAsn1, _ := asn1.Marshal(int(info.SNP))
	microcodeAsn1, _ := asn1.Marshal(int(info.Microcode))

	template.ExtraExtensions = []pkix.Extension{
		{Id: asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 1}), Value: asn1Zero},
		{Id: asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 2}), Value: productNameAsn1},
		{Id: asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 1}), Value: bootLoaderAsn1},
		{Id: asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 2}), Value: teeAsn1},
		{Id: asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 3}), Value: snpAsn1},
		{Id: asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 4}), Value: asn1Zero},
		{Id: asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 5}), Value: asn1Zero},
		{Id: asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 6}), Value: asn1Zero},
		{Id: asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 7}), Value: asn1Zero},
		{Id: asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 8}), Value: microcodeAsn1},
	}
	if ekType == "vlek" {
		cspidAsn1, _ := asn1.MarshalWithParams("go-sev-guest", "ia5")
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 5}), Value: cspidAsn1})
	} else {
		hwidAsn1, _ := asn1.Marshal(info.ChipId)
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 4}), Value: hwidAsn1})
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, askCert, key.Public(), askPrivateKey)
	if err != nil {
		fmt.Printf("Failed to generate certificate: %v", err)
		return nil, nil
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		fmt.Printf("Failed to generate certificate: %v", err)
		return nil, nil
	}

	return cert, key
}

func generateCRL(arkCert *x509.Certificate, arkKey *rsa.PrivateKey) *x509.RevocationList {
	crlTemplate := x509.RevocationList{
		Number:             big.NewInt(4),
		SignatureAlgorithm: x509.SHA384WithRSAPSS,
		Issuer:             arkCert.Issuer,
		RawIssuer:          arkCert.RawIssuer,
		AuthorityKeyId:     arkCert.AuthorityKeyId,
		NextUpdate:         time.Now().Add(1000 * 24 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, arkCert, arkKey)
	if err != nil {
		return nil
	}

	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return nil
	}

	return crl
}

func buildCertChain(arkCert, askCert *x509.Certificate) *x509.CertPool {
	certChain := x509.NewCertPool()
	certChain.AddCert(arkCert)
	certChain.AddCert(askCert)

	return certChain
}

func validateEKSignature(cert *x509.Certificate, certChain *x509.CertPool) bool {
	opts := x509.VerifyOptions{
		Roots: certChain,
	}

	_, err := cert.Verify(opts)

	return err == nil
}

func validateCRLSignature(crl *x509.RevocationList, parent *x509.Certificate) bool {
	return crl.CheckSignatureFrom(parent) == nil
}

func store(path, keyType string, bytes []byte) {
	pemBlock := &pem.Block{
		Type:  keyType,
		Bytes: bytes,
	}

	pemData := pem.EncodeToMemory(pemBlock)
	os.WriteFile(path, pemData, 0644)
}

func generateKeys(arkCert *x509.Certificate, arkKey *rsa.PrivateKey, ekType string) {
	askCert, askKey := generateASK(arkCert, arkKey, ekType)
	askCRL := generateCRL(arkCert, arkKey)

	cert_chain := buildCertChain(arkCert, askCert)

	ekCert, ekKey := generateChipKey(askCert, askKey, ekType)

	valid := validateCRLSignature(askCRL, arkCert)
	if !valid {
		panic("Error generating CRL")
	}
	valid = validateEKSignature(ekCert, cert_chain)
	if !valid {
		panic("Error generating EK")
	}

	os.Mkdir("./keys/"+ekType, 0777)

	store("./keys/"+ekType+"/ask.pem", "CERTIFICATE", askCert.Raw)
	store("./keys/"+ekType+"/ask.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(askKey))

	os.WriteFile("./keys/"+ekType+"/crl.der", askCRL.Raw, 0644)

	certChain := []*x509.Certificate{arkCert, askCert}

	chainPEM := []byte{}
	for _, cert := range certChain {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}

	os.WriteFile("./keys/"+ekType+"/cert_chain.pem", chainPEM, 0644)

	store("./keys/"+ekType+"/"+ekType+".pem", "CERTIFICATE", ekCert.Raw)
	ekKeyBytes, _ := x509.MarshalECPrivateKey(ekKey)
	store("./keys/"+ekType+"/"+ekType+".key", "EC PRIVATE KEY", ekKeyBytes)
}

func main() {
	arkCert, arkKey := generateARK()
	store("./keys/ark.pem", "CERTIFICATE", arkCert.Raw)
	store("./keys/ark.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(arkKey))

	generateKeys(arkCert, arkKey, "vcek")
	generateKeys(arkCert, arkKey, "vlek")
}
