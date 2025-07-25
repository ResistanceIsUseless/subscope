package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/resistanceisuseless/subscope/internal/alterx"
	"github.com/resistanceisuseless/subscope/internal/arin"
	"github.com/resistanceisuseless/subscope/internal/config"
	// "github.com/resistanceisuseless/subscope/internal/ct" // TEMPORARILY DISABLED
	"github.com/resistanceisuseless/subscope/internal/dns"
	"github.com/resistanceisuseless/subscope/internal/enumeration"
	"github.com/resistanceisuseless/subscope/internal/http"
	"github.com/resistanceisuseless/subscope/internal/output"
	"github.com/resistanceisuseless/subscope/internal/persistence"
	"github.com/resistanceisuseless/subscope/internal/rdns"
	"github.com/resistanceisuseless/subscope/internal/shuffledns"
	"github.com/resistanceisuseless/subscope/internal/summary"
	"github.com/resistanceisuseless/subscope/internal/wildcard"
)

type SubScope struct {
	config *config.Config
}

func NewSubScope(cfg *config.Config) *SubScope {
	return &SubScope{
		config: cfg,
	}
}

func (s *SubScope) Run(ctx context.Context, domain string, allPhases bool, geoAnalysis bool) error {
	fmt.Printf("Starting SubScope enumeration for domain: %s\n", domain)
	
	enumerator := enumeration.New(s.config)
	
	// Phase 0: Wildcard detection
	fmt.Println("Phase 0: Wildcard detection...")
	wildcardDetector := wildcard.New(s.config)
	if err := wildcardDetector.DetectWildcards(ctx, domain); err != nil {
		fmt.Printf("Warning: Wildcard detection failed: %v\n", err)
	}
	
	// Phase 1: Passive enumeration
	fmt.Println("Phase 1: Passive enumeration...")
	domains, err := enumerator.RunPassiveEnumeration(ctx, domain)
	if err != nil {
		return fmt.Errorf("passive enumeration failed: %w", err)
	}
	
	// Process discovered domains
	results := enumerator.ProcessDomains(domains)
	
	// Phase 1.1: Zone transfer attempt (early in the process)
	fmt.Println("Phase 1.1: Zone transfer (AXFR) attempt...")
	resolver := dns.New(s.config)
	zoneTransferDomains, err := resolver.AttemptZoneTransfer(ctx, domain)
	if err != nil {
		if s.config.Verbose {
			fmt.Printf("Zone transfer attempt failed: %v\n", err)
		}
	} else if len(zoneTransferDomains) > 0 {
		// Add zone transfer domains to results
		zoneResults := enumerator.ProcessZoneTransferDomains(zoneTransferDomains)
		results = append(results, zoneResults...)
		fmt.Printf("Zone transfer found %d domains\n", len(zoneTransferDomains))
	}
	
	// Phase 1.7: HTTP/HTTPS analysis with httpx (headers, SSL certs, redirects)
	fmt.Println("Phase 1.7: HTTP/HTTPS analysis with httpx...")
	httpAnalyzer := http.New(s.config)
	// Analyze up to 500 domains to find additional subdomains via HTTP headers, SSL certs, and redirects
	sampleSize := len(domains)
	if sampleSize > 500 {
		sampleSize = 500
	}
	var httpDomains []string
	if sampleSize > 0 {
		httpDomains, err = httpAnalyzer.AnalyzeDomains(ctx, domains[:sampleSize], domain)
		if err != nil {
			fmt.Printf("Warning: httpx analysis failed: %v\n", err)
		} else if len(httpDomains) > 0 {
			// Add HTTP-discovered domains to results
			httpResults := enumerator.ProcessHTTPDomains(httpDomains)
			results = append(results, httpResults...)
			fmt.Printf("Added %d httpx-discovered domains to enumeration results\n", len(httpDomains))
		}
	}

	// Optional phases (run only with --all flag)
	var ctDomains []string
	if allPhases {
		// Phase 1.5: Certificate Transparency log analysis - TEMPORARILY DISABLED
		// fmt.Println("Phase 1.5: Certificate Transparency log analysis...")
		// ctAnalyzer := ct.New(s.config)
		// ctDomains, err = ctAnalyzer.QueryCertificates(ctx, domain)
		// if err != nil {
		// 	fmt.Printf("Warning: Certificate Transparency query failed: %v\n", err)
		// } else if len(ctDomains) > 0 {
		// 	// Add CT domains to results
		// 	ctResults := enumerator.ProcessCTDomains(ctDomains)
		// 	results = append(results, ctResults...)
		// 	fmt.Printf("Added %d CT domains to enumeration results\n", len(ctDomains))
		// }
		fmt.Println("Phase 1.5: Certificate Transparency log analysis - TEMPORARILY DISABLED")

		// Phase 1.6: Dynamic wordlist generation with AlterX (after HTTP to include new findings)
		fmt.Println("Phase 1.6: Dynamic wordlist generation...")
		alterxIntegration := alterx.New(s.config)
		// Combine subfinder, CT, and HTTP domains for permutation
		allDiscovered := append(domains, ctDomains...)
		allDiscovered = append(allDiscovered, httpDomains...)
		permutations, err := alterxIntegration.GenerateDynamicWordlist(ctx, allDiscovered)
		if err != nil {
			fmt.Printf("Warning: AlterX permutation failed: %v\n", err)
		} else if len(permutations) > 0 {
			// Add permutations to results
			permutationResults := enumerator.ProcessPermutations(permutations)
			results = append(results, permutationResults...)
			fmt.Printf("Added %d permutations to enumeration results\n", len(permutations))
		}
	}

	// Phase 2: DNS resolution
	fmt.Println("Phase 2: DNS resolution...")
	
	// Try to use shuffledns for faster resolution
	if _, err := exec.LookPath("shuffledns"); err == nil {
		shuffleResolver := shuffledns.New(s.config)
		if resolvedResults, err := shuffleResolver.ResolveDomains(ctx, results); err != nil {
			fmt.Printf("Warning: shuffledns failed, falling back to built-in resolver: %v\n", err)
			results = resolver.ResolveDomains(ctx, results)
		} else {
			// Use built-in resolver to get IP addresses for resolved domains
			results = resolver.ResolveDomains(ctx, resolvedResults)
		}
	} else {
		// Fall back to built-in resolver
		results = resolver.ResolveDomains(ctx, results)
	}
	
	// Phase 2.5: RDNS analysis on resolved IPs
	fmt.Println("Phase 2.5: RDNS analysis...")
	rdnsAnalyzer := rdns.New(s.config)
	rdnsDomains, err := rdnsAnalyzer.AnalyzeIPs(ctx, results, domain)
	if err != nil {
		fmt.Printf("Warning: RDNS analysis failed: %v\n", err)
	} else if len(rdnsDomains) > 0 {
		// Add RDNS-discovered domains to results
		rdnsResults := enumerator.ProcessRDNSDomains(rdnsDomains)
		results = append(results, rdnsResults...)
		fmt.Printf("Added %d RDNS-discovered domains to enumeration results\n", len(rdnsDomains))
	}
	
	// Phase 2.6: Enhanced RDNS - IP range scanning (similar to dnsrecon)
	if allPhases {
		fmt.Println("Phase 2.6: RDNS IP range scanning...")
		rdnsRangeDomains, err := rdnsAnalyzer.ScanIPRangesFromSubnets(ctx, results, domain)
		if err != nil {
			fmt.Printf("Warning: RDNS range scanning failed: %v\n", err)
		} else if len(rdnsRangeDomains) > 0 {
			// Add RDNS range-discovered domains to results
			rdnsRangeResults := enumerator.ProcessRDNSRangeDomains(rdnsRangeDomains)
			results = append(results, rdnsRangeResults...)
			fmt.Printf("Added %d RDNS range-discovered domains to enumeration results\n", len(rdnsRangeDomains))
		}
		
	}
	
	// Phase 2.8: Geographic DNS analysis (can run independently or with -all)
	if allPhases || geoAnalysis {
		fmt.Println("Phase 2.8: Geographic DNS analysis...")
		geoDNS := dns.NewGeoDNSResolver(s.config)
		geoResults, err := geoDNS.QueryFromAllRegions(ctx, domain)
		if err != nil {
			fmt.Printf("Warning: Geographic DNS analysis failed: %v\n", err)
		} else {
			// Analyze geographic differences
			analysis := geoDNS.AnalyzeGeographicDifferences(geoResults)
			
			// Add unique geographic domains to results
			var geoDomains []string
			for geoDomain := range analysis.UniqueDomains {
				geoDomains = append(geoDomains, geoDomain)
			}
			
			if len(geoDomains) > 0 {
				geoEnumResults := enumerator.ProcessGeoDNSDomains(geoDomains)
				results = append(results, geoEnumResults...)
				fmt.Printf("Added %d geographically-specific domains to enumeration results\n", len(geoDomains))
			}
			
			// Print geographic analysis
			if s.config.Verbose || len(analysis.UniqueDomains) > 0 {
				analysis.PrintAnalysis()
			}
		}
	}
	
	// Phase 2.7: Wildcard filtering
	fmt.Println("Phase 2.7: Wildcard filtering...")
	results = wildcardDetector.FilterWildcardResults(results, domain)
	
	// Optional phases (run only with --all flag)
	var orgData []arin.OrganizationInfo
	if allPhases {
		// Phase 2.8: Organization data from RDAP (ARIN, RIPE, etc.)
		fmt.Println("Phase 2.8: Organization analysis via RDAP...")
		arinAnalyzer := arin.New(s.config)
		orgData, err = arinAnalyzer.AnalyzeIPs(ctx, results)
		if err != nil {
			fmt.Printf("Warning: RDAP analysis failed: %v\n", err)
		} else if len(orgData) > 0 {
			fmt.Printf("Retrieved organization data for %d IP addresses\n", len(orgData))
		}
		
		// Phase 2.9: Domain tracking and new domain flagging
		fmt.Println("Phase 2.9: Domain history tracking...")
		tracker := persistence.New(s.config)
		results, err = tracker.TrackDomains(domain, results)
		if err != nil {
			fmt.Printf("Warning: Domain tracking failed: %v\n", err)
		}
	}
	
	// Phase 3: Output results
	fmt.Println("Phase 3: Output results...")
	writer := output.New(s.config)
	if err := writer.WriteResults(results); err != nil {
		return fmt.Errorf("failed to write results: %w", err)
	}
	
	// Phase 4: Display summary
	summaryData := summary.Analyze(results, orgData)
	summaryData.Print()
	
	return nil
}

func main() {
	var (
		domain       = flag.String("d", "", "Target domain to enumerate")
		domainLong   = flag.String("domain", "", "Target domain to enumerate")
		configPath   = flag.String("c", "", "Configuration file path")
		configLong   = flag.String("config", "", "Configuration file path")
		output       = flag.String("o", "results.json", "Output file path")
		outputLong   = flag.String("output", "results.json", "Output file path")
		format       = flag.String("f", "json", "Output format (json, csv, massdns, dnsx)")
		formatLong   = flag.String("format", "json", "Output format (json, csv, massdns, dnsx)")
		interactive  = flag.Bool("i", false, "Run in interactive TUI mode")
		interactiveLong = flag.Bool("interactive", false, "Run in interactive TUI mode")
		createConfig = flag.Bool("create-config", false, "Create default configuration file")
		showStats    = flag.Bool("s", false, "Show domain history statistics")
		showStatsLong = flag.Bool("stats", false, "Show domain history statistics")
		showNew      = flag.String("new-since", "", "Show new domains since date (YYYY-MM-DD)")
		allPhases    = flag.Bool("a", false, "Run all phases including CT, AlterX, RDAP, and persistence")
		allPhasesLong = flag.Bool("all", false, "Run all phases including CT, AlterX, RDAP, and persistence")
		geoAnalysis  = flag.Bool("g", false, "Enable geographic DNS analysis")
		geoLong      = flag.Bool("geo", false, "Enable geographic DNS analysis")
		verbose      = flag.Bool("v", false, "Enable verbose logging")
		verboseLong  = flag.Bool("verbose", false, "Enable verbose logging")
	)
	flag.Parse()

	// Merge short and long flag values (long takes precedence if both are set)
	targetDomain := *domain
	if *domainLong != "" {
		targetDomain = *domainLong
	}
	
	targetConfig := *configPath
	if *configLong != "" {
		targetConfig = *configLong
	}
	
	targetOutput := *output
	if *outputLong != "" {
		targetOutput = *outputLong
	}
	
	targetFormat := *format
	if *formatLong != "" {
		targetFormat = *formatLong
	}
	
	targetInteractive := *interactive || *interactiveLong
	targetStats := *showStats || *showStatsLong
	targetAllPhases := *allPhases || *allPhasesLong
	targetGeoAnalysis := *geoAnalysis || *geoLong
	targetVerbose := *verbose || *verboseLong

	// Handle config creation
	if *createConfig {
		if err := config.CreateDefault(); err != nil {
			log.Fatalf("Failed to create default config: %v", err)
		}
		os.Exit(0)
	}

	// Handle statistics display
	if targetStats && targetDomain != "" {
		cfg, _ := config.Load(targetConfig)
		tracker := persistence.New(cfg)
		stats, err := tracker.GetDomainStats(targetDomain)
		if err != nil {
			log.Fatalf("Failed to get domain stats: %v", err)
		}
		fmt.Printf("Domain History for %s:\n", targetDomain)
		fmt.Printf("Total domains tracked: %d\n", len(stats.Domains))
		fmt.Printf("Last updated: %s\n", stats.LastUpdated.Format("2006-01-02 15:04:05"))
		os.Exit(0)
	}

	// Handle new domains display
	if *showNew != "" && targetDomain != "" {
		cfg, _ := config.Load(targetConfig)
		tracker := persistence.New(cfg)
		since, err := time.Parse("2006-01-02", *showNew)
		if err != nil {
			log.Fatalf("Invalid date format. Use YYYY-MM-DD: %v", err)
		}
		newDomains, err := tracker.GetNewDomains(targetDomain, since)
		if err != nil {
			log.Fatalf("Failed to get new domains: %v", err)
		}
		fmt.Printf("New domains for %s since %s:\n", targetDomain, *showNew)
		for _, domain := range newDomains {
			fmt.Printf("  %s (first seen: %s, sources: %v)\n", 
				domain.Domain, 
				domain.FirstSeen.Format("2006-01-02 15:04:05"),
				domain.Sources)
		}
		os.Exit(0)
	}

	if targetDomain == "" {
		fmt.Println("Usage: subscope -d example.com")
		fmt.Println("       subscope --domain example.com")
		fmt.Println("       subscope -d example.com -a (run all phases)")
		fmt.Println("       subscope -d example.com -g (geographic DNS analysis)")
		fmt.Println("       subscope -d example.com -s (show statistics)")
		fmt.Println("       subscope -d example.com --new-since 2024-01-01")
		fmt.Println("\nDefault phases: Wildcard detection, Passive enumeration, HTTP analysis, RDNS")
		fmt.Println("All phases (-a/--all): Adds Certificate Transparency, AlterX, RDAP, and persistence tracking")
		fmt.Println("Geographic DNS (-g/--geo): Queries from multiple global regions for geo-specific subdomains")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.Load(targetConfig)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	
	// Override config with command line flags
	cfg.Target.Domain = targetDomain
	cfg.Output.Format = targetFormat
	cfg.Output.File = targetOutput
	cfg.Verbose = targetVerbose

	if targetInteractive {
		fmt.Println("Interactive TUI mode not yet implemented")
		os.Exit(1)
	}

	subscope := NewSubScope(cfg)
	
	ctx := context.Background()
	if err := subscope.Run(ctx, targetDomain, targetAllPhases, targetGeoAnalysis); err != nil {
		log.Fatalf("Enumeration failed: %v", err)
	}

	fmt.Println("Enumeration completed successfully")
}