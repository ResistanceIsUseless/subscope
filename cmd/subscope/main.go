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
	"github.com/resistanceisuseless/subscope/internal/ct"
	"github.com/resistanceisuseless/subscope/internal/dns"
	"github.com/resistanceisuseless/subscope/internal/enumeration"
	"github.com/resistanceisuseless/subscope/internal/http"
	"github.com/resistanceisuseless/subscope/internal/output"
	"github.com/resistanceisuseless/subscope/internal/persistence"
	"github.com/resistanceisuseless/subscope/internal/progress"
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

func (s *SubScope) Run(ctx context.Context, domain string, inputDomainsPath string, mergeMode bool, enableProgress bool) error {
	// Initialize progress tracker (disabled in verbose mode to avoid conflicts)
	progressTracker := progress.New(enableProgress && !s.config.Verbose)
	
	progressTracker.Info("Starting SubScope enumeration for domain: %s", domain)
	
	enumerator := enumeration.New(s.config)
	
	// Phase 0: Wildcard detection
	progressTracker.StartPhase("Wildcard detection", 1)
	wildcardDetector := wildcard.New(s.config)
	if err := wildcardDetector.DetectWildcards(ctx, domain); err != nil {
		progressTracker.Info("Warning: Wildcard detection failed: %v", err)
	}
	progressTracker.Complete()
	
	// Phase 0.5: Load input domains (if provided)
	var inputDomainList []string
	var err error
	if inputDomainsPath != "" {
		progressTracker.StartPhase("Loading input domains", 1)
		inputDomainList, err = enumerator.LoadInputDomains(inputDomainsPath)
		if err != nil {
			return fmt.Errorf("failed to load input domains: %w", err)
		}
		progressTracker.Complete()
	}
	
	// Phase 1: Passive enumeration  
	var domains []string
	if s.config.Features.Passive {
		progressTracker.StartPhase("Passive enumeration", 0) // Unknown total
		passiveDomains, err := enumerator.RunPassiveEnumeration(ctx, domain)
		if err != nil {
			return fmt.Errorf("passive enumeration failed: %w", err)
		}
		domains = append(domains, passiveDomains...)
		progressTracker.Update(len(domains))
		progressTracker.Complete()
	} else {
		progressTracker.Info("Passive enumeration disabled")
	}
	
	// Merge input domains with discovered domains if merge flag is set
	if len(inputDomainList) > 0 {
		if mergeMode {
			progressTracker.Info("Merging %d input domains with %d discovered domains", len(inputDomainList), len(domains))
			// Create a map to avoid duplicates
			domainMap := make(map[string]bool)
			for _, d := range domains {
				domainMap[d] = true
			}
			for _, d := range inputDomainList {
				if !domainMap[d] {
					domains = append(domains, d)
					domainMap[d] = true
				}
			}
			progressTracker.Info("Total unique domains after merge: %d", len(domains))
		} else {
			// Replace discovered domains with input domains
			progressTracker.Info("Using %d input domains instead of discovered domains", len(inputDomainList))
			domains = inputDomainList
		}
	}
	
	// Process discovered domains
	results := enumerator.ProcessDomains(domains)
	
	// Add input domains to results if they exist
	if len(inputDomainList) > 0 && !mergeMode {
		inputResults := enumerator.ProcessInputDomains(inputDomainList)
		// Only add input results if we're not merging (to avoid duplicates)
		if len(inputDomainList) != len(domains) {
			results = append(results, inputResults...)
		}
	}
	
	// Phase 1.1: Zone transfer attempt  
	resolver := dns.New(s.config)
	if s.config.Features.ZoneTransfer {
		progressTracker.StartPhase("Zone transfer (AXFR)", 1)
		zoneTransferDomains, err := resolver.AttemptZoneTransfer(ctx, domain)
		if err != nil {
			if s.config.Verbose {
				progressTracker.Info("Zone transfer attempt failed: %v", err)
			}
		} else if len(zoneTransferDomains) > 0 {
			// Add zone transfer domains to results
			zoneResults := enumerator.ProcessZoneTransferDomains(zoneTransferDomains)
			results = append(results, zoneResults...)
			progressTracker.Info("Zone transfer found %d domains", len(zoneTransferDomains))
		}
		progressTracker.Complete()
	} else {
		progressTracker.Info("Zone transfer disabled")
	}
	
	// Phase 1.7: HTTP/HTTPS analysis with httpx (headers, SSL certs, redirects)
	var httpDomains []string
	if s.config.Features.HTTPAnalysis && len(domains) > 0 {
		httpAnalyzer := http.New(s.config)
		// Analyze up to 500 domains to find additional subdomains via HTTP headers, SSL certs, and redirects
		sampleSize := len(domains)
		if sampleSize > 500 {
			sampleSize = 500
		}
		progressTracker.StartPhase("HTTP/HTTPS analysis", sampleSize)
		httpDomains, err = httpAnalyzer.AnalyzeDomains(ctx, domains[:sampleSize], domain)
		if err != nil {
			progressTracker.Info("Warning: httpx analysis failed: %v", err)
		} else if len(httpDomains) > 0 {
			// Add HTTP-discovered domains to results
			httpResults := enumerator.ProcessHTTPDomains(httpDomains)
			results = append(results, httpResults...)
			progressTracker.Info("Added %d httpx-discovered domains to enumeration results", len(httpDomains))
		}
		progressTracker.Complete()
	} else if !s.config.Features.HTTPAnalysis {
		progressTracker.Info("HTTP analysis disabled")
	}

	// Phase 1.5: Certificate Transparency log analysis
	var ctDomains []string
	if s.config.Features.CertificateTransparency {
		fmt.Fprintln(os.Stderr, "Phase 1.5: Certificate Transparency log analysis...")
		ctAnalyzer := ct.New(s.config)
		ctDomains, err = ctAnalyzer.QueryCertificates(ctx, domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Certificate Transparency query failed: %v\n", err)
		} else if len(ctDomains) > 0 {
			// Add CT domains to results
			ctResults := enumerator.ProcessCTDomains(ctDomains)
			results = append(results, ctResults...)
			fmt.Fprintf(os.Stderr, "Added %d CT domains to enumeration results\n", len(ctDomains))
		}
	} else {
		progressTracker.Info("Certificate Transparency analysis disabled")
	}

	// Phase 1.6: Dynamic wordlist generation with AlterX (after HTTP to include new findings)
	if s.config.Features.DNSBruteForce {
		fmt.Fprintln(os.Stderr, "Phase 1.6: Dynamic wordlist generation...")
		alterxIntegration := alterx.New(s.config)
		// Combine subfinder, CT, and HTTP domains for permutation
		allDiscovered := append(domains, ctDomains...)
		allDiscovered = append(allDiscovered, httpDomains...)
		permutations, err := alterxIntegration.GenerateDynamicWordlist(ctx, allDiscovered)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: AlterX permutation failed: %v\n", err)
		} else if len(permutations) > 0 {
			// Add permutations to results
			permutationResults := enumerator.ProcessPermutations(permutations)
			results = append(results, permutationResults...)
			fmt.Fprintf(os.Stderr, "Added %d permutations to enumeration results\n", len(permutations))
		}
	} else {
		progressTracker.Info("DNS brute force disabled")
	}

	// Phase 2: DNS resolution
	progressTracker.StartPhase("DNS resolution", len(results))
	
	// Try to use shuffledns for faster resolution
	if _, err := exec.LookPath("shuffledns"); err == nil {
		shuffleResolver := shuffledns.New(s.config)
		if resolvedResults, err := shuffleResolver.ResolveDomains(ctx, results); err != nil {
			progressTracker.Info("Warning: shuffledns failed, falling back to built-in resolver: %v", err)
			results = resolver.ResolveDomains(ctx, results)
		} else {
			// Use built-in resolver to get IP addresses for resolved domains
			results = resolver.ResolveDomains(ctx, resolvedResults)
		}
	} else {
		// Fall back to built-in resolver
		results = resolver.ResolveDomains(ctx, results)
	}
	progressTracker.Complete()
	
	// Phase 2.5: RDNS analysis on resolved IPs
	if s.config.Features.RDNS {
		fmt.Fprintln(os.Stderr, "Phase 2.5: RDNS analysis...")
		rdnsAnalyzer := rdns.New(s.config)
		rdnsDomains, err := rdnsAnalyzer.AnalyzeIPs(ctx, results, domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: RDNS analysis failed: %v\n", err)
		} else if len(rdnsDomains) > 0 {
			// Add RDNS-discovered domains to results
			rdnsResults := enumerator.ProcessRDNSDomains(rdnsDomains)
			results = append(results, rdnsResults...)
			fmt.Fprintf(os.Stderr, "Added %d RDNS-discovered domains to enumeration results\n", len(rdnsDomains))
		}
		
		// Phase 2.6: Enhanced RDNS - IP range scanning (similar to dnsrecon)
		fmt.Fprintln(os.Stderr, "Phase 2.6: RDNS IP range scanning...")
		rdnsRangeDomains, err := rdnsAnalyzer.ScanIPRangesFromSubnets(ctx, results, domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: RDNS range scanning failed: %v\n", err)
		} else if len(rdnsRangeDomains) > 0 {
			// Add RDNS range-discovered domains to results
			rdnsRangeResults := enumerator.ProcessRDNSRangeDomains(rdnsRangeDomains)
			results = append(results, rdnsRangeResults...)
			fmt.Fprintf(os.Stderr, "Added %d RDNS range-discovered domains to enumeration results\n", len(rdnsRangeDomains))
		}
	} else {
		progressTracker.Info("RDNS analysis disabled")
	}
	
	// Phase 2.8: Geographic DNS analysis
	if s.config.Features.GeoDNS {
		fmt.Fprintln(os.Stderr, "Phase 2.8: Geographic DNS analysis...")
		geoDNS := dns.NewGeoDNSResolver(s.config)
		
		// Get domains to test (both the target domain and resolved domains)
		var domainsToTest []string
		domainsToTest = append(domainsToTest, domain)
		
		// Add common apex domain variations for comprehensive testing
		commonSubdomains := []string{"www", "api", "cdn", "mail", "ftp"}
		domainSet := make(map[string]bool)
		domainSet[domain] = true
		
		for _, subdomain := range commonSubdomains {
			testDomain := subdomain + "." + domain
			if !domainSet[testDomain] {
				domainsToTest = append(domainsToTest, testDomain)
				domainSet[testDomain] = true
			}
		}
		
		// Also test resolved domains for geographic differences
		for _, result := range results {
			if result.Status == "resolved" && !domainSet[result.Domain] {
				domainsToTest = append(domainsToTest, result.Domain)
				domainSet[result.Domain] = true
			}
		}
		
		// Query all domains from all regions with enhanced details
		geoResults, err := geoDNS.QueryDomainsFromAllRegions(ctx, domainsToTest)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Geographic DNS analysis failed: %v\n", err)
		} else {
			// Add geo-enriched results to main results
			results = append(results, geoResults...)
			
			// Also run legacy analysis for summary display
			legacyGeoResults, _ := geoDNS.QueryFromAllRegions(ctx, domain)
			if len(legacyGeoResults) > 0 {
				analysis := geoDNS.AnalyzeGeographicDifferences(legacyGeoResults)
				
				// Print geographic analysis
				if s.config.Verbose || len(analysis.UniqueDomains) > 0 {
					analysis.PrintAnalysis()
				}
			}
			
			fmt.Fprintf(os.Stderr, "Added %d geographically-specific domains to enumeration results\n", len(geoResults))
		}
	} else {
		progressTracker.Info("Geographic DNS analysis disabled")
	}
	
	// Phase 2.7: Wildcard filtering
	fmt.Fprintln(os.Stderr, "Phase 2.7: Wildcard filtering...")
	results = wildcardDetector.FilterWildcardResults(results, domain)
	
	// Phase 2.8: Organization data from RDAP (ARIN, RIPE, etc.)
	var orgData []arin.OrganizationInfo
	if s.config.Features.ARINLookup {
		fmt.Fprintln(os.Stderr, "Phase 2.8: Organization analysis via RDAP...")
		arinAnalyzer := arin.New(s.config)
		orgData, err = arinAnalyzer.AnalyzeIPs(ctx, results)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: RDAP analysis failed: %v\n", err)
		} else if len(orgData) > 0 {
			fmt.Fprintf(os.Stderr, "Retrieved organization data for %d IP addresses\n", len(orgData))
		}
	} else {
		progressTracker.Info("ARIN lookup disabled")
	}
	
	// Phase 2.9: Domain tracking and new domain flagging
	if s.config.Features.Persistence {
		fmt.Fprintln(os.Stderr, "Phase 2.9: Domain history tracking...")
		tracker := persistence.New(s.config)
		results, err = tracker.TrackDomains(domain, results)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Domain tracking failed: %v\n", err)
		}
	} else {
		progressTracker.Info("Persistence tracking disabled")
	}
	
	// Phase 3: Output results
	fmt.Fprintln(os.Stderr, "Phase 3: Output results...")
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
		// Basic flags
		domain       = flag.String("d", "", "Target domain to enumerate")
		domainLong   = flag.String("domain", "", "Target domain to enumerate")
		configPath   = flag.String("c", "", "Configuration file path")
		configLong   = flag.String("config", "", "Configuration file path")
		output       = flag.String("o", "results.json", "Output file path")
		outputLong   = flag.String("output", "results.json", "Output file path")
		format       = flag.String("f", "json", "Output format (json, csv, massdns, dnsx, aquatone, eyewitness)")
		formatLong   = flag.String("format", "json", "Output format (json, csv, massdns, dnsx, aquatone, eyewitness)")
		
		// Feature flags - modular control
		passive        = flag.Bool("passive", false, "Enable passive enumeration (subfinder)")
		zoneTransfer   = flag.Bool("zone-transfer", false, "Enable DNS zone transfer attempts")
		httpAnalysis   = flag.Bool("http-analysis", false, "Enable HTTP/HTTPS analysis (httpx)")
		dnsBruteForce  = flag.Bool("dns-brute-force", false, "Enable DNS brute forcing (alterx)")
		geoDNS         = flag.Bool("geo-dns", false, "Enable geographic DNS analysis")
		rdns           = flag.Bool("rdns", false, "Enable reverse DNS lookups")
		certTransparency = flag.Bool("cert-transparency", false, "Enable certificate transparency analysis")
		arinLookup     = flag.Bool("arin-lookup", false, "Enable ARIN organization data lookup")
		persistenceFlag = flag.Bool("persistence", false, "Enable domain history tracking")
		
		// Legacy flags for compatibility
		allPhases    = flag.Bool("a", false, "Run all phases including CT, AlterX, RDAP, and persistence")
		allPhasesLong = flag.Bool("all", false, "Run all phases including CT, AlterX, RDAP, and persistence")
		geoAnalysis  = flag.Bool("g", false, "Enable geographic DNS analysis (legacy)")
		geoLong      = flag.Bool("geo", false, "Enable geographic DNS analysis (legacy)")
		
		// Other flags
		interactive  = flag.Bool("i", false, "Run in interactive TUI mode")
		interactiveLong = flag.Bool("interactive", false, "Run in interactive TUI mode")
		createConfig = flag.Bool("create-config", false, "Create default configuration file")
		showStats    = flag.Bool("s", false, "Show domain history statistics")
		showStatsLong = flag.Bool("stats", false, "Show domain history statistics")
		showNew      = flag.String("new-since", "", "Show new domains since date (YYYY-MM-DD)")
		inputDomains = flag.String("input-domains", "", "Path to file containing additional domains to scan")
		mergeDomains = flag.Bool("merge", false, "Merge input domains with discovered domains")
		showProgress = flag.Bool("progress", false, "Show progress indicators")
		profile      = flag.String("profile", "", "Rate limit profile (stealth, normal, aggressive)")
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
		fmt.Fprintf(os.Stderr, "Domain History for %s:\n", targetDomain)
		fmt.Fprintf(os.Stderr, "Total domains tracked: %d\n", len(stats.Domains))
		fmt.Fprintf(os.Stderr, "Last updated: %s\n", stats.LastUpdated.Format("2006-01-02 15:04:05"))
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
		fmt.Fprintf(os.Stderr, "New domains for %s since %s:\n", targetDomain, *showNew)
		for _, domain := range newDomains {
			fmt.Fprintf(os.Stderr, "  %s (first seen: %s, sources: %v)\n", 
				domain.Domain, 
				domain.FirstSeen.Format("2006-01-02 15:04:05"),
				domain.Sources)
		}
		os.Exit(0)
	}

	if targetDomain == "" {
		fmt.Println("Usage: subscope -d example.com")
		fmt.Println("       subscope --domain example.com")
		fmt.Println("\nModular Feature Control:")
		fmt.Println("       subscope -d example.com --passive                    (passive enumeration only)")
		fmt.Println("       subscope -d example.com --passive --http-analysis    (passive + HTTP analysis)")
		fmt.Println("       subscope -d example.com --geo-dns                    (geographic DNS only)")
		fmt.Println("       subscope -d example.com --dns-brute-force            (DNS brute forcing only)")
		fmt.Println("       subscope -d example.com --passive --rdns --geo-dns   (multiple features)")
		fmt.Println("\nLegacy Modes (for compatibility):")
		fmt.Println("       subscope -d example.com -a                          (all phases)")
		fmt.Println("       subscope -d example.com -g                          (geographic DNS)")
		fmt.Println("\nOther Usage:")
		fmt.Println("       subscope -d example.com --input-domains domains.txt")
		fmt.Println("       subscope -d example.com --input-domains domains.txt --merge")
		fmt.Println("       subscope -d example.com -s                          (show statistics)")
		fmt.Println("       subscope -d example.com --new-since 2024-01-01")
		fmt.Println("\nFeature Flags:")
		fmt.Println("  --passive              Enable passive enumeration (subfinder)")
		fmt.Println("  --zone-transfer        Enable DNS zone transfer attempts")
		fmt.Println("  --http-analysis        Enable HTTP/HTTPS analysis (httpx)")
		fmt.Println("  --dns-brute-force      Enable DNS brute forcing (alterx)")
		fmt.Println("  --geo-dns              Enable geographic DNS analysis")
		fmt.Println("  --rdns                 Enable reverse DNS lookups")
		fmt.Println("  --cert-transparency    Enable certificate transparency analysis")
		fmt.Println("  --arin-lookup          Enable ARIN organization data lookup")
		fmt.Println("  --persistence          Enable domain history tracking")
		fmt.Println("\nProfiles:")
		fmt.Println("  --profile stealth      Low rate limits, high delays (5 req/s)")
		fmt.Println("  --profile normal       Balanced settings (20 req/s)")
		fmt.Println("  --profile aggressive   High speed, minimal delays (100 req/s)")
		fmt.Println("\nNOTE: If no feature flags are specified, default features are used from config.")
		fmt.Println("      Default features: passive, zone-transfer, http-analysis, rdns")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.Load(targetConfig)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	
	// Apply profile if specified
	if *profile != "" {
		err = cfg.ApplyProfile(*profile)
		if err != nil {
			log.Fatalf("Failed to apply profile: %v", err)
		}
		fmt.Fprintf(os.Stderr, "Applied profile: %s\n", *profile)
	}
	
	// Handle feature flags - collect CLI overrides
	featureOverrides := make(map[string]bool)
	
	// Check if any specific feature flags were set
	if *passive {
		featureOverrides["passive"] = true
	}
	if *zoneTransfer {
		featureOverrides["zone_transfer"] = true
	}
	if *httpAnalysis {
		featureOverrides["http_analysis"] = true
	}
	if *dnsBruteForce {
		featureOverrides["dns_brute_force"] = true
	}
	if *geoDNS || *geoAnalysis || *geoLong {
		featureOverrides["geo_dns"] = true
	}
	if *rdns {
		featureOverrides["rdns"] = true
	}
	if *certTransparency {
		featureOverrides["certificate_transparency"] = true
	}
	if *arinLookup {
		featureOverrides["arin_lookup"] = true
	}
	if *persistenceFlag {
		featureOverrides["persistence"] = true
	}
	
	// Handle legacy --all flag
	if targetAllPhases {
		featureOverrides["passive"] = true
		featureOverrides["zone_transfer"] = true
		featureOverrides["http_analysis"] = true
		featureOverrides["dns_brute_force"] = true
		featureOverrides["geo_dns"] = true
		featureOverrides["rdns"] = true
		featureOverrides["certificate_transparency"] = true
		featureOverrides["arin_lookup"] = true
		featureOverrides["persistence"] = true
	}
	
	// If specific feature flags were provided, disable all default features first
	// then enable only the specified ones
	if len(featureOverrides) > 0 && !targetAllPhases {
		// Disable all features first
		cfg.Features.Passive = false
		cfg.Features.ZoneTransfer = false
		cfg.Features.HTTPAnalysis = false
		cfg.Features.DNSBruteForce = false
		cfg.Features.GeoDNS = false
		cfg.Features.RDNS = false
		cfg.Features.CertificateTransparency = false
		cfg.Features.ARINLookup = false
		cfg.Features.Persistence = false
	}
	
	// Apply feature overrides
	cfg.OverrideFeatures(featureOverrides)
	
	// Override config with command line flags
	cfg.Target.Domain = targetDomain
	cfg.Output.Format = targetFormat
	cfg.Output.File = targetOutput
	cfg.Verbose = targetVerbose

	if targetInteractive {
		fmt.Fprintln(os.Stderr, "Interactive TUI mode not yet implemented")
		os.Exit(1)
	}

	subscope := NewSubScope(cfg)
	
	ctx := context.Background()
	if err := subscope.Run(ctx, targetDomain, *inputDomains, *mergeDomains, *showProgress); err != nil {
		log.Fatalf("Enumeration failed: %v", err)
	}

	fmt.Fprintln(os.Stderr, "Enumeration completed successfully")
}