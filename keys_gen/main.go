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
	"io/ioutil"
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
		SerialNumber: big.NewInt(1),
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
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertificate, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPrivateKey.Public(), caPrivateKey)
	if err != nil {
		fmt.Printf("Failed to generate CA certificate: %v", err)
		return nil, nil
	}

	caKeyFile, err := os.Create("./certs/ark.key")
	if err != nil {
		fmt.Printf("Failed to create CA private key file: %v", err)
		return nil, nil
	}
	defer caKeyFile.Close()
	if err := pem.Encode(caKeyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPrivateKey)}); err != nil {
		fmt.Printf("Failed to write CA private key to file: %v", err)
		return nil, nil
	}

	caCertFile, err := os.Create("./certs/ark.crt")
	if err != nil {
		fmt.Printf("Failed to create CA certificate file: %v", err)
		return nil, nil
	}
	defer caCertFile.Close()
	if err := pem.Encode(caCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: caCertificate}); err != nil {
		fmt.Printf("Failed to write CA certificate to file: %v", err)
		return nil, nil
	}

	fmt.Println("Self-signed CA certificate and private key generated successfully.")
	return caTemplate, caPrivateKey
}

func generateASK(caTemplate *x509.Certificate, caPrivateKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	askPrivateKey, err := generatePrivateKey()
	if err != nil {
		fmt.Printf("Failed to generate ask CA private key: %v", err)
		return nil, nil
	}

	askTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
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

	askKeyFile, err := os.Create("./certs/ask.key")
	if err != nil {
		fmt.Printf("Failed to create ask CA private key file: %v", err)
		return nil, nil
	}
	defer askKeyFile.Close()
	if err := pem.Encode(askKeyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(askPrivateKey)}); err != nil {
		fmt.Printf("Failed to write ask CA private key to file: %v", err)
		return nil, nil
	}

	askCertFile, err := os.Create("./certs/ask.crt")
	if err != nil {
		fmt.Printf("Failed to create ask CA certificate file: %v", err)
		return nil, nil
	}
	defer askCertFile.Close()
	if err := pem.Encode(askCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: askCertificate}); err != nil {
		fmt.Printf("Failed to write ask CA certificate to file: %v", err)
		return nil, nil
	}

	fmt.Println("Intermediate CA certificate and private key generated successfully.")
	return askTemplate, askPrivateKey
}

func generateChipKey(name string, askCert *x509.Certificate, askPrivateKey *rsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate ECDSA key pair: %v", err)
		return
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
		return
	}

	keyFile, err := os.Create("./certs/" + name + ".key")
	if err != nil {
		fmt.Printf("Failed to create private key file: %v", err)
		return
	}
	defer keyFile.Close()
	keyMarshaled, _ := x509.MarshalECPrivateKey(key)
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyMarshaled}); err != nil {
		fmt.Printf("Failed to write private key to file: %v", err)
		return
	}

	certFile, err := os.Create("./certs/" + name + ".crt")
	if err != nil {
		fmt.Printf("Failed to create certificate file: %v", err)
		return
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		fmt.Printf("Failed to write certificate to file: %v", err)
		return
	}

	fmt.Println("ECDSA key pair and certificate generated successfully.")
}

func buildCertChain(cert1File, cert2File, outputFile string) error {
	cert1Bytes, err := ioutil.ReadFile(cert1File)
	if err != nil {
		return err
	}

	cert2Bytes, err := ioutil.ReadFile(cert2File)
	if err != nil {
		return err
	}

	cert1Block, _ := pem.Decode(cert1Bytes)
	cert2Block, _ := pem.Decode(cert2Bytes)

	cert1, err := x509.ParseCertificate(cert1Block.Bytes)
	if err != nil {
		return err
	}

	cert2, err := x509.ParseCertificate(cert2Block.Bytes)
	if err != nil {
		return err
	}

	certChain := []*x509.Certificate{cert1, cert2}

	chainPEM := []byte{}
	for _, cert := range certChain {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}

	err = ioutil.WriteFile(outputFile, chainPEM, 0644)
	if err != nil {
		return err
	}

	return nil
}

func validateCertChain(vcekPath string, rootPath string) (bool, error) {
	vcekBin, err := os.ReadFile(vcekPath)
	if err != nil {
		return false, err
	}

	rootPEM, err := os.ReadFile(rootPath)
	if err != nil {
		return false, err
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		return false, err
	}

	block, _ := pem.Decode([]byte(vcekBin))
	if block == nil {
		return false, err
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: x509.NewCertPool(),
	}

	if _, err := cert.Verify(opts); err != nil {
		return false, err
	}

	return true, nil
}

func main() {
	arkCert, arkKey := generateARK()
	askCert, askPrivateKey := generateASK(arkCert, arkKey)
	buildCertChain("./certs/ark.crt", "./certs/ask.crt", "./certs/cert_chain.pem")
	generateChipKey("vcek", askCert, askPrivateKey)
	generateChipKey("vlek", askCert, askPrivateKey)
	valid, _ := validateCertChain("./certs/vcek.crt", "./certs/cert_chain.pem")
	fmt.Println("VCEK valid: ", valid)
	valid, _ = validateCertChain("./certs/vlek.crt", "./certs/cert_chain.pem")
	fmt.Println("VLEK valid: ", valid)
}
