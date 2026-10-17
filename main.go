package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	sevguest "github.com/Daviiap/sev-guest_device_mock/src"
)

const (
	defaultConfigPath = "config.json"
	defaultReportPath = "report.json"
	defaultKdsPort    = 8080
)

type Config struct {
	KdsPort int `json:"kds_port"`
	// ReportPath and KeysDir are resolved relative to the config file.
	ReportPath string `json:"custom_report_path"`
	KeysDir    string `json:"keys_dir"`
}

type ReportConfig struct {
	Measurement string  `json:"measurement"`
	Policy      *uint64 `json:"policy"`
}

// loadConfig reads the config file. A missing file is only an error when its
// path was given explicitly.
func loadConfig(path string, explicit bool) (Config, string, error) {
	cfg := Config{KdsPort: defaultKdsPort, KeysDir: sevguest.DefaultKeysDir}
	baseDir := filepath.Dir(path)

	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) && !explicit {
		return cfg, baseDir, nil
	}
	if err != nil {
		return cfg, baseDir, fmt.Errorf("reading config: %w", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, baseDir, fmt.Errorf("parsing config %s: %w", path, err)
	}
	return cfg, baseDir, nil
}

func resolvePath(baseDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

type reportOverrider interface {
	SetMeasurement([]byte)
	SetPolicy(uint64)
}

// applyReportConfig applies the overrides from the report config file. A
// missing file is only an error when its path was configured explicitly.
func applyReportConfig(device reportOverrider, path string, explicit bool) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) && !explicit {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading report config: %w", err)
	}

	var reportCfg ReportConfig
	if err := json.Unmarshal(data, &reportCfg); err != nil {
		return fmt.Errorf("parsing report config %s: %w", path, err)
	}

	if reportCfg.Measurement != "" {
		measurement, err := hex.DecodeString(reportCfg.Measurement)
		if err != nil {
			return fmt.Errorf("decoding measurement hex from %s: %w", path, err)
		}
		if len(measurement) != 48 {
			return fmt.Errorf("measurement in %s must be 48 bytes (96 hex chars), got %d bytes", path, len(measurement))
		}
		device.SetMeasurement(measurement)
		log.Printf("Loaded custom measurement from %s", path)
	}
	if reportCfg.Policy != nil {
		device.SetPolicy(*reportCfg.Policy)
		log.Printf("Loaded custom policy from %s", path)
	}
	return nil
}

func main() {
	configPath := flag.String("config", defaultConfigPath, "Path to the configuration JSON file")
	flag.Parse()

	configExplicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "config" {
			configExplicit = true
		}
	})

	appConfig, baseDir, err := loadConfig(*configPath, configExplicit)
	if err != nil {
		log.Fatal(err)
	}

	reportPath := resolvePath(baseDir, defaultReportPath)
	if appConfig.ReportPath != "" {
		reportPath = resolvePath(baseDir, appConfig.ReportPath)
	}
	keysDir := resolvePath(baseDir, appConfig.KeysDir)

	deviceMock := sevguest.New()
	if err := applyReportConfig(deviceMock, reportPath, appConfig.ReportPath != ""); err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	deviceMock.Start()
	defer deviceMock.Stop()

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", appConfig.KdsPort),
		Handler: sevguest.KDSHandler(keysDir),
	}
	serverErr := make(chan error, 1)
	go func() {
		log.Printf("Starting mock KDS HTTP server on %s (serving %s)", server.Addr, keysDir)
		serverErr <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		log.Print("Shutting down")
	case <-deviceMock.Done():
		log.Print("sev-guest device stopped unexpectedly")
	case err := <-serverErr:
		log.Printf("HTTP server failed: %v", err)
	}
	server.Close()
}
