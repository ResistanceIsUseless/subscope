package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func Load(configPath string) (*Config, error) {
	config := &Config{}
	
	// Set defaults
	config.RateLimit.Global = 10
	config.RateLimit.Jitter = true
	config.Subfinder.Timeout = 30
	config.Output.Format = "json"
	config.Output.File = "results.json"
	config.AlterX.EnableEnrichment = true
	config.AlterX.MaxPermutations = 10000
	
	// Stealth defaults
	config.Stealth.UserAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
	}
	config.Stealth.RandomDelay = 100
	config.Stealth.RequestJitter = true
	
	if configPath == "" {
		return config, nil
	}
	
	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", configPath)
	}
	
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	
	return config, nil
}

func CreateDefault() error {
	configDir := filepath.Join(os.Getenv("HOME"), ".config", "subscope")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	
	configPath := filepath.Join(configDir, "config.yaml")
	
	// Check if config already exists
	if _, err := os.Stat(configPath); err == nil {
		return nil // Config already exists
	}
	
	defaultConfig := `version: "1.0"
target:
  domain: ""
  scope:
    - "*.example.com"
  exclusions: []

subfinder:
  config_path: "$HOME/.config/subfinder/provider-config.yaml"
  providers: []  # Empty means use all available sources
  timeout: 30

rate_limit:
  global: 10
  jitter: true

stealth:
  user_agents:
    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    - "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    - "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
  random_delay_ms: 100
  request_jitter: true

output:
  format: "json"
  file: "results.json"
`
	
	if err := os.WriteFile(configPath, []byte(defaultConfig), 0644); err != nil {
		return fmt.Errorf("failed to write default config: %w", err)
	}
	
	fmt.Printf("Default configuration created at: %s\n", configPath)
	return nil
}

// LoadProfile loads a rate limit profile and merges it with the base config
func LoadProfile(profileName string, baseConfig *Config) (*Config, error) {
	if profileName == "" {
		return baseConfig, nil
	}
	
	// Try to find profile in profiles directory
	profilePath := fmt.Sprintf("profiles/%s.yaml", profileName)
	
	// Check if profile exists
	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("profile '%s' not found at %s", profileName, profilePath)
	}
	
	// Load profile config
	profileConfig, err := Load(profilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load profile '%s': %w", profileName, err)
	}
	
	// Merge profile settings into base config
	mergedConfig := *baseConfig // Copy base config
	
	// Override rate limit settings
	if profileConfig.RateLimit.Global > 0 {
		mergedConfig.RateLimit.Global = profileConfig.RateLimit.Global
	}
	if profileConfig.RateLimit.Jitter != baseConfig.RateLimit.Jitter {
		mergedConfig.RateLimit.Jitter = profileConfig.RateLimit.Jitter
	}
	
	// Override stealth settings
	if profileConfig.Stealth.RandomDelay > 0 {
		mergedConfig.Stealth.RandomDelay = profileConfig.Stealth.RandomDelay
	}
	if len(profileConfig.Stealth.UserAgents) > 0 {
		mergedConfig.Stealth.UserAgents = profileConfig.Stealth.UserAgents
	}
	
	// Override AlterX settings if present
	if profileConfig.AlterX.MaxPermutations > 0 {
		mergedConfig.AlterX.MaxPermutations = profileConfig.AlterX.MaxPermutations
	}
	
	return &mergedConfig, nil
}