package sevguest

import (
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// DefaultKeysDir is where ./configure installs the keys and certificates.
const DefaultKeysDir = "/etc/sev-guest"

// serveDERCert serves a PEM certificate file as DER, as the KDS does for VCEKs.
func serveDERCert(w http.ResponseWriter, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "certificate not found", http.StatusNotFound)
		return
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		http.Error(w, "invalid certificate", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-cert")
	w.Write(block.Bytes)
}

// KDSHandler mocks the AMD Key Distribution Service endpoints of the Milan
// product line, serving the certificates installed in keysDir.
func KDSHandler(keysDir string) http.Handler {
	mux := http.NewServeMux()
	for _, ekType := range []string{"vcek", "vlek"} {
		dir := filepath.Join(keysDir, ekType)
		prefix := "/" + ekType + "/v1/Milan/"
		isVcek := ekType == "vcek"
		mux.HandleFunc(prefix, func(w http.ResponseWriter, r *http.Request) {
			switch name := strings.TrimPrefix(r.URL.Path, prefix); {
			case name == "cert_chain":
				http.ServeFile(w, r, filepath.Join(dir, "cert_chain.pem"))
			case name == "crl":
				http.ServeFile(w, r, filepath.Join(dir, "crl.der"))
			case isVcek && name != "" && !strings.Contains(name, "/"):
				// /vcek/v1/Milan/{hwid}?blSPL=..: the mock has a single chip.
				serveDERCert(w, filepath.Join(dir, "public.pem"))
			default:
				http.NotFound(w, r)
			}
		})
	}
	return mux
}
