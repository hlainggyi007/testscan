package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config represents the loaded configuration for CrowScout
type Config struct {
	CriticalPorts    map[string]string `json:"critical_ports"`
	NucleiSeverities []string          `json:"nuclei_severities"`
}

// LoadConfig reads the JSON configuration file from disk
func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config: %w", err)
	}
	defer file.Close()

	var cfg Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	return &cfg, nil
}
