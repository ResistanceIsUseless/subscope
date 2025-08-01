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
	setDefaults(config)
	
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

// setDefaults sets default values for the configuration
func setDefaults(config *Config) {
	// Basic defaults
	config.RateLimit.Global = 10
	config.RateLimit.Jitter = true
	config.Subfinder.Timeout = 30
	config.Output.Format = "json"
	config.Output.File = "results.json"
	config.AlterX.EnableEnrichment = true
	config.AlterX.MaxPermutations = 10000
	
	// Default feature flags (conservative set)
	config.Features.Passive = true
	config.Features.ZoneTransfer = true
	config.Features.HTTPAnalysis = true
	config.Features.RDNS = true
	config.Features.DNSBruteForce = false // Disabled by default (high volume)
	config.Features.GeoDNS = false       // Disabled by default (requires API calls)
	config.Features.CertificateTransparency = false // Disabled by default
	config.Features.ARINLookup = false    // Disabled by default
	config.Features.Persistence = false   // Disabled by default
	
	// Default stealth settings
	defaultUserAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
	}
	
	config.Stealth.UserAgents = defaultUserAgents
	config.Stealth.RandomDelay = 100
	config.Stealth.RequestJitter = true
	
	// Set profile defaults
	setProfileDefaults(config)
}

// setProfileDefaults sets default values for all profiles
func setProfileDefaults(config *Config) {
	defaultUserAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	}
	
	// Stealth profile - low rate limits, high delays
	config.Profiles.Stealth.RateLimit.Global = 5
	config.Profiles.Stealth.RateLimit.Jitter = true
	config.Profiles.Stealth.Stealth.UserAgents = defaultUserAgents
	config.Profiles.Stealth.Stealth.RandomDelay = 1000
	config.Profiles.Stealth.Stealth.RequestJitter = true
	
	// Normal profile - balanced settings
	config.Profiles.Normal.RateLimit.Global = 20
	config.Profiles.Normal.RateLimit.Jitter = true
	config.Profiles.Normal.Stealth.UserAgents = defaultUserAgents
	config.Profiles.Normal.Stealth.RandomDelay = 250
	config.Profiles.Normal.Stealth.RequestJitter = true
	
	// Aggressive profile - high rate limits, minimal delays
	config.Profiles.Aggressive.RateLimit.Global = 100
	config.Profiles.Aggressive.RateLimit.Jitter = false
	config.Profiles.Aggressive.Stealth.UserAgents = defaultUserAgents
	config.Profiles.Aggressive.Stealth.RandomDelay = 50
	config.Profiles.Aggressive.Stealth.RequestJitter = false
}

// ApplyProfile applies a specific profile to the config
func (c *Config) ApplyProfile(profileName string) error {
	switch profileName {
	case "stealth":
		c.RateLimit = c.Profiles.Stealth.RateLimit
		c.Stealth = c.Profiles.Stealth.Stealth
		c.ActiveProfile = "stealth"
	case "normal":
		c.RateLimit = c.Profiles.Normal.RateLimit
		c.Stealth = c.Profiles.Normal.Stealth
		c.ActiveProfile = "normal"
	case "aggressive":
		c.RateLimit = c.Profiles.Aggressive.RateLimit
		c.Stealth = c.Profiles.Aggressive.Stealth
		c.ActiveProfile = "aggressive"
	default:
		return fmt.Errorf("unknown profile: %s", profileName)
	}
	return nil
}

// OverrideFeatures allows CLI flags to override config file feature settings
func (c *Config) OverrideFeatures(features map[string]bool) {
	for feature, enabled := range features {
		switch feature {
		case "passive":
			c.Features.Passive = enabled
		case "zone_transfer":
			c.Features.ZoneTransfer = enabled
		case "http_analysis":
			c.Features.HTTPAnalysis = enabled
		case "dns_brute_force":
			c.Features.DNSBruteForce = enabled
		case "geo_dns":
			c.Features.GeoDNS = enabled
		case "rdns":
			c.Features.RDNS = enabled
		case "certificate_transparency":
			c.Features.CertificateTransparency = enabled
		case "arin_lookup":
			c.Features.ARINLookup = enabled
		case "persistence":
			c.Features.Persistence = enabled
		}
	}
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

# Feature flags - control which modules are enabled
features:
  passive: true               # subfinder passive enumeration  
  zone_transfer: true         # DNS zone transfer attempts
  http_analysis: true         # httpx analysis
  dns_brute_force: false      # alterx wordlist generation (high volume)
  geo_dns: false              # geographic DNS analysis (API calls)
  rdns: true                  # reverse DNS lookups
  certificate_transparency: false # CT log analysis
  arin_lookup: false          # ARIN organization data
  persistence: false          # domain history tracking

# Rate limiting profiles (use --profile flag to activate)
profiles:
  stealth:
    rate_limit:
      global: 5
      jitter: true
    stealth:
      user_agents:
        - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        - "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
      random_delay_ms: 1000
      request_jitter: true
  
  normal:
    rate_limit:
      global: 20
      jitter: true
    stealth:
      user_agents:
        - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        - "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
      random_delay_ms: 250
      request_jitter: true
  
  aggressive:
    rate_limit:
      global: 100
      jitter: false
    stealth:
      user_agents:
        - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
      random_delay_ms: 50
      request_jitter: false

subfinder:
  config_path: ""
  providers: []  # Empty means use all available sources
  timeout: 30
  api_keys:
    censys:
      id: ""
      secret: ""
    certspotter: ""
    shodan: ""
    hunter_io: ""

alterx:
  enable_enrichment: true
  max_permutations: 10000

# Default rate limits and stealth settings (overridden by profiles)
rate_limit:
  global: 10
  jitter: true

stealth:
  user_agents:
    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    - "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
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

