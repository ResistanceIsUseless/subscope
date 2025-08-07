package config

type Config struct {
	Target struct {
		Domain string `yaml:"domain"`
	} `yaml:"target"`
	
	// Feature flags to control which modules are enabled
	Features struct {
		Passive       bool `yaml:"passive"`        // subfinder passive enumeration
		ZoneTransfer  bool `yaml:"zone_transfer"`  // DNS zone transfer attempts
		HTTPAnalysis  bool `yaml:"http_analysis"`  // httpx analysis
		DNSBruteForce bool `yaml:"dns_brute_force"` // alterx wordlist generation
		GeoDNS        bool `yaml:"geo_dns"`        // geographic DNS analysis
		RDNS          bool `yaml:"rdns"`           // reverse DNS lookups
		CertificateTransparency bool `yaml:"certificate_transparency"` // CT log analysis
		ARINLookup    bool `yaml:"arin_lookup"`    // ARIN organization data
		Persistence   bool `yaml:"persistence"`    // domain history tracking
	} `yaml:"features"`
	
	// Rate limiting profiles
	Profiles struct {
		Stealth struct {
			RateLimit struct {
				Global int  `yaml:"global"`
				Jitter bool `yaml:"jitter"`
			} `yaml:"rate_limit"`
			Stealth struct {
				UserAgents    []string `yaml:"user_agents"`
				RandomDelay   int      `yaml:"random_delay_ms"`
				RequestJitter bool     `yaml:"request_jitter"`
			} `yaml:"stealth"`
		} `yaml:"stealth"`
		
		Normal struct {
			RateLimit struct {
				Global int  `yaml:"global"`
				Jitter bool `yaml:"jitter"`
			} `yaml:"rate_limit"`
			Stealth struct {
				UserAgents    []string `yaml:"user_agents"`
				RandomDelay   int      `yaml:"random_delay_ms"`
				RequestJitter bool     `yaml:"request_jitter"`
			} `yaml:"stealth"`
		} `yaml:"normal"`
		
		Aggressive struct {
			RateLimit struct {
				Global int  `yaml:"global"`
				Jitter bool `yaml:"jitter"`
			} `yaml:"rate_limit"`
			Stealth struct {
				UserAgents    []string `yaml:"user_agents"`
				RandomDelay   int      `yaml:"random_delay_ms"`
				RequestJitter bool     `yaml:"request_jitter"`
			} `yaml:"stealth"`
		} `yaml:"aggressive"`
	} `yaml:"profiles"`
	
	Subfinder struct {
		ConfigPath string   `yaml:"config_path"`
		Providers  []string `yaml:"providers"`
		Timeout    int      `yaml:"timeout"`
		APIKeys    APIKeys  `yaml:"api_keys"`
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
	ActiveProfile string // Which profile is currently active
	
	// Integration mode configuration
	Integration struct {
		Mode      string `yaml:"mode"`       // library, exec, auto
		Subfinder string `yaml:"subfinder"`  // library, exec, auto
		HTTPX     string `yaml:"httpx"`      // library, exec, auto  
		AlterX    string `yaml:"alterx"`    // library, exec, auto
		ShuffleDNS string `yaml:"shuffledns"` // library, exec, auto
	} `yaml:"integration"`
	
	// Exec mode arguments (from command line)
	ExecMode struct {
		Enabled        bool
		SubfinderArgs  string
		HTTPXArgs      string
		AlterXArgs     string
		ShuffleDNSArgs string
	}
}

// APIKeys holds API keys for various subfinder data sources
type APIKeys struct {
	Censys struct {
		ID     string `yaml:"id"`
		Secret string `yaml:"secret"`
	} `yaml:"censys"`
	Certspotter    string `yaml:"certspotter"`
	Shodan         string `yaml:"shodan"`
	HunterIO       string `yaml:"hunter_io"`
	SecurityTrails string `yaml:"securitytrails"`
	VirusTotal     string `yaml:"virustotal"`
	Fofa           string `yaml:"fofa"`
	Quake          string `yaml:"quake"`
}