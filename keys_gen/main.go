package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

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
		NotAfter:              time.Now().AddDate(100, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SignatureAlgorithm:    x509.SHA384WithRSAPSS,
		BasicConstraintsValid: true,
		IsCA:                  true,
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

func generateASK(caTemplate *x509.Certificate, caPrivateKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	askPrivateKey, err := generatePrivateKey()
	if err != nil {
		fmt.Printf("Failed to generate ask CA private key: %v", err)
		return nil, nil
	}

	askTemplate := &x509.Certificate{
		SerialNumber:       big.NewInt(65793),
		SignatureAlgorithm: x509.SHA384WithRSAPSS,
		Subject: pkix.Name{
			OrganizationalUnit: []string{"Engineering"},
			Country:            []string{"US"},
			Locality:           []string{"Santa Clara"},
			Province:           []string{"CA"},
			Organization:       []string{"Advanced Micro Devices"},
			CommonName:         "SEV-Milan",
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
		NotAfter:              time.Now().AddDate(100, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
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

func generateChipKey(askCert *x509.Certificate, askPrivateKey *rsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate ECDSA key pair: %v", err)
		return nil, nil
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			OrganizationalUnit: []string{"Engineering"},
			Country:            []string{"US"},
			Locality:           []string{"Santa Clara"},
			Province:           []string{"CA"},
			Organization:       []string{"Advanced Micro Devices"},
			CommonName:         "SEV-Milan",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(100, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
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

func generateCRL(askCert *x509.Certificate, askKey *rsa.PrivateKey) *x509.RevocationList {
	crlTemplate := x509.RevocationList{
		Number:             big.NewInt(4),
		SignatureAlgorithm: x509.SHA384WithRSAPSS,
		Issuer:             askCert.Issuer,
		RawIssuer:          askCert.RawIssuer,
		AuthorityKeyId:     askCert.AuthorityKeyId,
		NextUpdate:         time.Now().Add(1000 * 24 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, askCert, askKey)
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
	askCert, askKey := generateASK(arkCert, arkKey)
	askCRL := generateCRL(askCert, askKey)

	cert_chain := buildCertChain(arkCert, askCert)

	ekCert, ekKey := generateChipKey(askCert, askKey)

	valid := validateCRLSignature(askCRL, askCert)
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

	store("./keys/"+ekType+"/ek.pem", "CERTIFICATE", arkCert.Raw)
	ekKeyBytes, _ := x509.MarshalECPrivateKey(ekKey)
	store("./keys/"+ekType+"/ek.key", "EC PRIVATE KEY", ekKeyBytes)
}

func main() {
	arkCert, arkKey := generateARK()
	store("./keys/ark.pem", "CERTIFICATE", arkCert.Raw)
	store("./keys/ark.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(arkKey))

	generateKeys(arkCert, arkKey, "vcek")
	generateKeys(arkCert, arkKey, "vlek")
}
