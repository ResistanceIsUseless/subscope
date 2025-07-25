package config

type Config struct {
	Target struct {
		Domain string `yaml:"domain"`
	} `yaml:"target"`
	
	Subfinder struct {
		ConfigPath string   `yaml:"config_path"`
		Providers  []string `yaml:"providers"`
		Timeout    int      `yaml:"timeout"`
	} `yaml:"subfinder"`
	
	AlterX struct {
		ConfigPath      string              `yaml:"config_path"`
		EnableEnrichment bool               `yaml:"enable_enrichment"`
		MaxPermutations int                `yaml:"max_permutations"`
		Patterns        []string           `yaml:"patterns"`
		CustomPayloads  map[string][]string `yaml:"custom_payloads"`
	} `yaml:"alterx"`
	
	Output struct {
		Format string `yaml:"format"`
		File   string `yaml:"file"`
	} `yaml:"output"`
	
	RateLimit struct {
		Global int  `yaml:"global"`
		Jitter bool `yaml:"jitter"`
	} `yaml:"rate_limit"`
	
	Stealth struct {
		UserAgents    []string `yaml:"user_agents"`
		RandomDelay   int      `yaml:"random_delay_ms"`
		RequestJitter bool     `yaml:"request_jitter"`
	} `yaml:"stealth"`
	
	// Runtime configuration (not from YAML)
	Verbose bool
}