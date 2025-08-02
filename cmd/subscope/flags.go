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
	
	// Control Options
	All          bool
	Profile      string
	Verbose      bool
	Progress     bool
	
	// Utility
	CreateConfig bool
	ShowStats    bool
	NewSince     string
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

Usage:
  subscope -d <domain> [options]

Examples:
  # Default scan (passive + zone-transfer + http + rdns)
  subscope -d example.com

  # Specific features only
  subscope -d example.com --passive --geo
  
  # All features enabled
  subscope -d example.com --all
  
  # Stealth mode with custom output
  subscope -d example.com --profile stealth -o results.json

Options:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Feature Selection:
  When no feature flags are specified, the default set is used:
  passive, zone-transfer, http, and rdns.
  
  When any feature flags are specified, ONLY those features run.
  The --all flag overrides this and enables everything.

Output Formats:
  json       Detailed JSON with DNS records and metadata (default)
  csv        Simple CSV format (domain,ip,source,cloud,dns)
  aquatone   URLs for Aquatone screenshots
  massdns    Format for massdns input
  dnsx       Format for dnsx input
  eyewitness Format for EyeWitness input

Profiles:
  stealth     Low rate limits (5 req/s), high delays
  normal      Balanced settings (20 req/s) [default]
  aggressive  Maximum speed (100 req/s), no delays
`)
	}
	
	// Required flags
	flag.StringVar(&f.Domain, "d", "", "Target domain to enumerate (required)")
	
	// Input/Output flags
	flag.StringVar(&f.Config, "c", "", "Configuration file path")
	flag.StringVar(&f.Output, "o", "results.json", "Output file path (use '-' for stdout)")
	flag.StringVar(&f.Format, "f", "json", "Output format")
	flag.StringVar(&f.InputDomains, "input", "", "File containing additional domains")
	flag.BoolVar(&f.MergeDomains, "merge", false, "Merge input domains with discovered")
	
	// Feature flags
	flag.BoolVar(&f.Passive, "passive", false, "Passive enumeration via subfinder")
	flag.BoolVar(&f.ZoneTransfer, "zone", false, "DNS zone transfer attempts")
	flag.BoolVar(&f.HTTPAnalysis, "http", false, "HTTP/HTTPS analysis via httpx")
	flag.BoolVar(&f.DNSBruteForce, "brute", false, "DNS brute force via alterx")
	flag.BoolVar(&f.GeoDNS, "geo", false, "Geographic DNS analysis")
	flag.BoolVar(&f.RDNS, "rdns", false, "Reverse DNS lookups")
	flag.BoolVar(&f.CertTransparency, "ct", false, "Certificate transparency logs")
	flag.BoolVar(&f.ARINLookup, "arin", false, "ARIN/RDAP organization data")
	flag.BoolVar(&f.Persistence, "persist", false, "Domain history tracking")
	
	// Control flags
	flag.BoolVar(&f.All, "all", false, "Enable all enumeration features")
	flag.StringVar(&f.Profile, "profile", "", "Rate limit profile")
	flag.BoolVar(&f.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&f.Progress, "progress", false, "Show progress bars")
	
	// Utility flags
	flag.BoolVar(&f.CreateConfig, "init", false, "Create default config file")
	flag.BoolVar(&f.ShowStats, "stats", false, "Show domain statistics")
	flag.StringVar(&f.NewSince, "new", "", "Show new domains since date (YYYY-MM-DD)")
	
	// Legacy compatibility flags (hidden from help)
	var legacyAll bool
	var legacyGeo bool
	flag.BoolVar(&legacyAll, "a", false, "")
	flag.BoolVar(&legacyGeo, "g", false, "")
	
	flag.Parse()
	
	// Handle legacy flags
	if legacyAll {
		f.All = true
	}
	if legacyGeo {
		f.GeoDNS = true
	}
	
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