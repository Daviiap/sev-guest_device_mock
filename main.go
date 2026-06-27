package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	sevguest "github.com/Daviiap/sev-guest_device_mock/src"
)

type Config struct {
	KdsPort int `json:"kds_port"`
}

type ReportConfig struct {
	Measurement string  `json:"measurement"`
	Policy      *uint64 `json:"policy"`
}

func main() {
	reportPath := flag.String("report", "report.json", "Path to the report configuration JSON file")
	flag.Parse()

	var appConfig Config
	appConfig.KdsPort = 8080 // default
	if data, err := os.ReadFile("config.json"); err == nil {
		json.Unmarshal(data, &appConfig)
	}

	device_mock := sevguest.New()

	if data, err := os.ReadFile(*reportPath); err == nil {
		var reportCfg ReportConfig
		if err := json.Unmarshal(data, &reportCfg); err == nil {
			if reportCfg.Measurement != "" {
				measurementBytes, err := hex.DecodeString(reportCfg.Measurement)
				if err != nil {
					fmt.Printf("Error decoding measurement hex from report.json: %v\n", err)
				} else if len(measurementBytes) != 48 {
					fmt.Printf("Error: measurement in report.json must be 48 bytes (96 hex chars)\n")
				} else {
					device_mock.SetMeasurement(measurementBytes)
					fmt.Printf("Successfully loaded custom measurement from report.json\n")
				}
			}
			if reportCfg.Policy != nil {
				device_mock.SetPolicy(*reportCfg.Policy)
				fmt.Printf("Successfully loaded custom policy from report.json\n")
			}
		}
	}

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
