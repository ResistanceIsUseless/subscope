package main

import (
	"flag"
	"fmt"
	"os"
)

// Define custom flag types for better organization
type Flags struct {
	// Required
	Domain string
	
	// Input/Output
	Config       string
	Output       string
	Format       string
	InputDomains string
	MergeDomains bool
	
	// Feature Selection
	Passive              bool
	ZoneTransfer         bool
	HTTPAnalysis         bool
	DNSBruteForce        bool
	GeoDNS               bool
	RDNS                 bool
	CertTransparency     bool
	ARINLookup           bool
	Persistence          bool
	
	// ProxyHawk Integration
	ProxyHawkURL         string
	ProxyHawkRegions     string
	ProxyHawkRealTime    bool
	ProxyHawkForce       bool
	
	// Control Options
	All          bool
	Profile      string
	Verbose      bool
	Progress     bool
	
	// Exec Mode Options
	ExecMode      bool
	SubfinderArgs string
	HTTPXArgs     string
	AlterXArgs    string
	ShuffleDNSArgs string
	
	// Utility
	CreateConfig bool
	ShowStats    bool
	NewSince     string
	ShowVersion  bool
}

// ShowUsage displays the usage information
func ShowUsage() {
	flag.Usage()
}

func parseFlags() *Flags {
	f := &Flags{}
	
	// Custom usage function
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `SubScope - Advanced Subdomain Enumeration Tool
Version: %s

Usage:
  subscope [flags]

Examples:
  subscope -d example.com
  subscope -d example.com --passive --geo  
  subscope -d example.com --all
  subscope -d example.com --profile stealth -o results.json

Flags:`, GetVersionInfo())
		fmt.Fprintf(os.Stderr, `
TARGET:
   -d, --domain string    target domain to enumerate (required)

INPUT:
   -c, --config string    configuration file path
   -i, --input string     file containing additional domains to scan
   -m, --merge            merge input domains with discovered domains

OUTPUT:
   -o, --output string    output file path (default "results.json", use "-" for stdout) 
   -f, --format string    output format (json,csv,massdns,dnsx,aquatone,eyewitness) (default "json")

ENUMERATION:
   -p, --passive          passive enumeration via subfinder
   -z, --zone             DNS zone transfer attempts  
   -h, --http             HTTP/HTTPS analysis via httpx
   -b, --brute            DNS brute force via alterx
   -g, --geo              geographic DNS analysis
   -r, --rdns             reverse DNS lookups
   --ct                   certificate transparency logs
   --arin                 ARIN/RDAP organization data
   --persist              domain history tracking

PROXYHAWK INTEGRATION:
   --proxyhawk-url        ProxyHawk WebSocket URL (e.g., ws://localhost:8888/ws)
   --proxyhawk-regions    comma-separated list of regions (us-west,us-east,eu-west)
   --proxyhawk-realtime   enable real-time domain monitoring
   --proxyhawk-force      force ProxyHawk usage even if traditional methods available

CONTROL:
   -a, --all              enable all enumeration features
   --profile string       rate limit profile (stealth,normal,aggressive)
   -v, --verbose          verbose output
   --progress             show progress bars

EXEC MODE:
   --exec-mode            use external executables instead of libraries (future)
   --subfinder-args       custom arguments for subfinder executable
   --httpx-args           custom arguments for httpx executable  
   --alterx-args          custom arguments for alterx executable
   --shuffledns-args      custom arguments for shuffledns executable

UTILITY:
   --init                 create default config file
   -s, --stats            show domain statistics  
   -n, --new string       show new domains since date (YYYY-MM-DD)
   --version              show version information

FEATURE SELECTION:
  Default features (when no flags specified): passive, zone, http, rdns
  Explicit features: when any feature flag is used, ONLY those features run
  Override: --all enables everything regardless of other flags

OUTPUT FORMATS:
  json       detailed JSON with DNS records and metadata (default)
  csv        simple CSV format (domain,ip,source,cloud,dns)
  aquatone   URLs for aquatone screenshots
  massdns    format for massdns input
  dnsx       format for dnsx input  
  eyewitness format for eyewitness input

RATE LIMIT PROFILES:
  stealth     low rate limits (5 req/s), high delays
  normal      balanced settings (20 req/s) [default]
  aggressive  maximum speed (100 req/s), no delays

`)
	}
	
	// Target flags
	flag.StringVar(&f.Domain, "d", "", "")
	flag.StringVar(&f.Domain, "domain", "", "")
	
	// Input flags  
	flag.StringVar(&f.Config, "c", "", "")
	flag.StringVar(&f.Config, "config", "", "")
	flag.StringVar(&f.InputDomains, "i", "", "")
	flag.StringVar(&f.InputDomains, "input", "", "")
	flag.BoolVar(&f.MergeDomains, "m", false, "")
	flag.BoolVar(&f.MergeDomains, "merge", false, "")
	
	// Output flags
	flag.StringVar(&f.Output, "o", "results.json", "")
	flag.StringVar(&f.Output, "output", "results.json", "")
	flag.StringVar(&f.Format, "f", "json", "")
	flag.StringVar(&f.Format, "format", "json", "")
	
	// Enumeration feature flags
	flag.BoolVar(&f.Passive, "p", false, "")
	flag.BoolVar(&f.Passive, "passive", false, "")
	flag.BoolVar(&f.ZoneTransfer, "z", false, "")
	flag.BoolVar(&f.ZoneTransfer, "zone", false, "")
	flag.BoolVar(&f.HTTPAnalysis, "h", false, "")
	flag.BoolVar(&f.HTTPAnalysis, "http", false, "")
	flag.BoolVar(&f.DNSBruteForce, "b", false, "")
	flag.BoolVar(&f.DNSBruteForce, "brute", false, "")
	flag.BoolVar(&f.GeoDNS, "g", false, "")
	flag.BoolVar(&f.GeoDNS, "geo", false, "")
	flag.BoolVar(&f.RDNS, "r", false, "")
	flag.BoolVar(&f.RDNS, "rdns", false, "")
	flag.BoolVar(&f.CertTransparency, "ct", false, "")
	flag.BoolVar(&f.ARINLookup, "arin", false, "")
	flag.BoolVar(&f.Persistence, "persist", false, "")
	
	// ProxyHawk integration flags
	flag.StringVar(&f.ProxyHawkURL, "proxyhawk-url", "", "")
	flag.StringVar(&f.ProxyHawkRegions, "proxyhawk-regions", "", "")
	flag.BoolVar(&f.ProxyHawkRealTime, "proxyhawk-realtime", false, "")
	flag.BoolVar(&f.ProxyHawkForce, "proxyhawk-force", false, "")
	
	// Control flags
	flag.BoolVar(&f.All, "a", false, "")
	flag.BoolVar(&f.All, "all", false, "")
	flag.StringVar(&f.Profile, "profile", "", "")
	flag.BoolVar(&f.Verbose, "v", false, "")
	flag.BoolVar(&f.Verbose, "verbose", false, "")
	flag.BoolVar(&f.Progress, "progress", false, "")
	
	// Exec mode flags
	flag.BoolVar(&f.ExecMode, "exec-mode", false, "")
	flag.StringVar(&f.SubfinderArgs, "subfinder-args", "", "")
	flag.StringVar(&f.HTTPXArgs, "httpx-args", "", "")
	flag.StringVar(&f.AlterXArgs, "alterx-args", "", "")
	flag.StringVar(&f.ShuffleDNSArgs, "shuffledns-args", "", "")
	
	// Utility flags
	flag.BoolVar(&f.CreateConfig, "init", false, "")
	flag.BoolVar(&f.ShowStats, "s", false, "")
	flag.BoolVar(&f.ShowStats, "stats", false, "")
	flag.StringVar(&f.NewSince, "n", "", "")
	flag.StringVar(&f.NewSince, "new", "", "")
	flag.BoolVar(&f.ShowVersion, "version", false, "")
	
	flag.Parse()
	
	return f
}

// hasExplicitFeatures checks if any feature flags were explicitly set
func (f *Flags) hasExplicitFeatures() bool {
	return f.Passive || f.ZoneTransfer || f.HTTPAnalysis || 
		f.DNSBruteForce || f.GeoDNS || f.RDNS || 
		f.CertTransparency || f.ARINLookup || f.Persistence
}

// getFeatureMap returns a map of feature overrides for the config
func (f *Flags) getFeatureMap() map[string]bool {
	features := make(map[string]bool)
	
	if f.All {
		// Enable all features
		features["passive"] = true
		features["zone_transfer"] = true
		features["http_analysis"] = true
		features["dns_brute_force"] = true
		features["geo_dns"] = true
		features["rdns"] = true
		features["certificate_transparency"] = true
		features["arin_lookup"] = true
		features["persistence"] = true
	} else if f.hasExplicitFeatures() {
		// Only enable explicitly requested features
		features["passive"] = f.Passive
		features["zone_transfer"] = f.ZoneTransfer
		features["http_analysis"] = f.HTTPAnalysis
		features["dns_brute_force"] = f.DNSBruteForce
		features["geo_dns"] = f.GeoDNS
		features["rdns"] = f.RDNS
		features["certificate_transparency"] = f.CertTransparency
		features["arin_lookup"] = f.ARINLookup
		features["persistence"] = f.Persistence
	}
	// If no features specified, config defaults will be used
	
	return features
}