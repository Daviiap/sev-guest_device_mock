package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	sevguest "github.com/Daviiap/sev-guest_device_mock/src"
)

type Config struct {
	KdsPort int `json:"kds_port"`
}

func main() {
	var appConfig Config
	appConfig.KdsPort = 8080 // default
	if data, err := os.ReadFile("config.json"); err == nil {
		json.Unmarshal(data, &appConfig)
	}

	device_mock := sevguest.New()
	device_mock.Start()
	defer device_mock.Stop()

	// VCEK routes
	http.HandleFunc("/vcek/v1/Milan/cert_chain", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join("keys_gen", "keys", "vcek", "cert_chain.pem"))
	})
	http.HandleFunc("/vcek/v1/Milan/crl", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join("keys_gen", "keys", "vcek", "crl.der"))
	})

	// VLEK routes
	http.HandleFunc("/vlek/v1/Milan/cert_chain", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join("keys_gen", "keys", "vlek", "cert_chain.pem"))
	})
	http.HandleFunc("/vlek/v1/Milan/crl", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join("keys_gen", "keys", "vlek", "crl.der"))
	})

	go func() {
		addr := fmt.Sprintf(":%d", appConfig.KdsPort)
		fmt.Printf("Starting mock KDS HTTP server on %s\n", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			fmt.Printf("HTTP server failed: %v\n", err)
		}
	}()

	for device_mock.IsRunning() {
	}
}
