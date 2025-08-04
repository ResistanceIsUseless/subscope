package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/resistanceisuseless/subscope/internal/config"
	"github.com/resistanceisuseless/subscope/internal/enumeration"
)

// GeoDNSResolver handles DNS queries from different geographic perspectives
type GeoDNSResolver struct {
	config     *config.Config
	httpClient *http.Client
	regions    []GeoDNSRegion
}

// GeoDNSRegion represents a geographic region for DNS queries
type GeoDNSRegion struct {
	Name        string
	ClientIP    string // IP to simulate requests from this region
	Description string
}

// GoogleDNSResponse represents Google DNS API response
type GoogleDNSResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// CloudflareDNSResponse represents Cloudflare DNS API response
type CloudflareDNSResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// NewGeoDNSResolver creates a new geographic DNS resolver
func NewGeoDNSResolver(config *config.Config) *GeoDNSResolver {
	regions := []GeoDNSRegion{
		{
			Name:        "US-West",
			ClientIP:    "8.8.8.8",
			Description: "US West Coast (California)",
		},
		{
			Name:        "US-East",
			ClientIP:    "4.2.2.2",
			Description: "US East Coast (New York)",
		},
		{
			Name:        "Europe-West",
			ClientIP:    "85.10.10.10",
			Description: "Western Europe (Amsterdam)",
		},
		{
			Name:        "Europe-East",
			ClientIP:    "195.46.39.39",
			Description: "Eastern Europe (Warsaw)",
		},
		{
			Name:        "Asia-Pacific",
			ClientIP:    "180.76.76.76",
			Description: "Asia Pacific (Singapore)",
		},
		{
			Name:        "Asia-East",
			ClientIP:    "114.114.114.114",
			Description: "East Asia (Hong Kong)",
		},
	}

	return &GeoDNSResolver{
		config: config,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		regions: regions,
	}
}

// QueryFromAllRegions queries a domain from all configured regions
func (g *GeoDNSResolver) QueryFromAllRegions(ctx context.Context, domain string) (map[string][]enumeration.DomainResult, error) {
	results := make(map[string][]enumeration.DomainResult)
	
	for _, region := range g.regions {
		if g.config.Verbose {
			fmt.Printf("Querying %s from %s (%s)...\n", domain, region.Name, region.Description)
		}
		
		regionResults, err := g.queryFromRegion(ctx, domain, region)
		if err != nil {
			if g.config.Verbose {
				fmt.Printf("Failed to query from %s: %v\n", region.Name, err)
			}
			continue
		}
		
		if len(regionResults) > 0 {
			results[region.Name] = regionResults
		}
	}
	
	return results, nil
}

// QueryDomainsFromAllRegionsEnhanced performs enhanced geographic analysis with round-robin detection
func (g *GeoDNSResolver) QueryDomainsFromAllRegionsEnhanced(ctx context.Context, domains []string) ([]enumeration.DomainResult, error) {
	if len(domains) == 0 {
		return []enumeration.DomainResult{}, nil
	}
	
	var finalResults []enumeration.DomainResult
	
	for _, domain := range domains {
		if g.config.Verbose {
			fmt.Printf("Processing %s with enhanced GeoDNS analysis...\n", domain)
		}
		
		// Step 1: Establish round-robin baseline
		baseline, err := g.detectRoundRobin(ctx, domain)
		if err != nil {
			if g.config.Verbose {
				fmt.Printf("Failed to establish baseline for %s: %v\n", domain, err)
			}
			continue
		}
		
		// Step 2: Query from all geographic regions
		regionResults, err := g.QueryFromAllRegions(ctx, domain)
		if err != nil {
			continue
		}
		
		// Step 3: Analyze with baseline filtering
		analysis := g.analyzeWithBaseline(domain, regionResults, baseline)
		
		// Only include results that have meaningful geographic differences or useful data
		if analysis.HasMeaningfulResults() {
			result := enumeration.DomainResult{
				Domain:     domain,
				Status:     "resolved",
				Source:     "geodns",
				Timestamp:  time.Now(),
				DNSRecords: make(map[string]string),
				GeoDNS:     analysis.ToGeoDNSDetails(),
			}
			
			finalResults = append(finalResults, result)
		}
	}
	
	return finalResults, nil
}

// QueryDomainsFromAllRegions queries multiple domains and returns enriched results with GeoDNS details (legacy method)
func (g *GeoDNSResolver) QueryDomainsFromAllRegions(ctx context.Context, domains []string) ([]enumeration.DomainResult, error) {
	// Use enhanced algorithm by default
	return g.QueryDomainsFromAllRegionsEnhanced(ctx, domains)
}

// queryFromRegion performs DNS queries simulating requests from a specific region
func (g *GeoDNSResolver) queryFromRegion(ctx context.Context, domain string, region GeoDNSRegion) ([]enumeration.DomainResult, error) {
	var results []enumeration.DomainResult
	
	// Query both A and CNAME records
	aResults, err := g.queryGoogleDNS(ctx, domain, "A", region.ClientIP)
	if err == nil {
		results = append(results, aResults...)
	}
	
	cnameResults, err := g.queryGoogleDNS(ctx, domain, "CNAME", region.ClientIP)
	if err == nil {
		results = append(results, cnameResults...)
	}
	
	return results, nil
}

// queryGoogleDNS queries Google DNS API with EDNS Client Subnet
func (g *GeoDNSResolver) queryGoogleDNS(ctx context.Context, domain, recordType, clientIP string) ([]enumeration.DomainResult, error) {
	url := fmt.Sprintf("https://dns.google/resolve?name=%s&type=%s&edns_client_subnet=%s/24", 
		domain, recordType, clientIP)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	// Add headers to appear as a legitimate client
	req.Header.Set("User-Agent", "SubScope-GeoDNS/1.0")
	req.Header.Set("Accept", "application/dns-json")
	
	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	var dnsResp GoogleDNSResponse
	if err := json.Unmarshal(body, &dnsResp); err != nil {
		return nil, err
	}
	
	var results []enumeration.DomainResult
	for _, answer := range dnsResp.Answer {
		result := enumeration.DomainResult{
			Domain:     strings.TrimSuffix(answer.Name, "."),
			Status:     "resolved",
			Source:     fmt.Sprintf("geodns-%s", strings.ToLower(recordType)),
			Timestamp:  time.Now(),
			DNSRecords: make(map[string]string),
		}
		
		// Store the record data
		result.DNSRecords[recordType] = answer.Data
		
		// Detect cloud services if it's a CNAME
		if recordType == "CNAME" {
			if cloudService := g.detectCloudService(answer.Data); cloudService != "" {
				result.DNSRecords["CLOUD_SERVICE"] = cloudService
			}
		}
		
		results = append(results, result)
	}
	
	return results, nil
}

// detectCloudService identifies cloud services (reuse logic from main resolver)
func (g *GeoDNSResolver) detectCloudService(cname string) string {
	cnameLower := strings.ToLower(cname)
	
	// AWS Services
	if strings.Contains(cnameLower, "cloudfront.net") {
		return "AWS-CloudFront"
	}
	if strings.Contains(cnameLower, "amazonaws.com") {
		return "AWS-General"
	}
	
	// Azure Services
	if strings.Contains(cnameLower, "azurestaticapps.net") {
		return "Azure-StaticWebApps"
	}
	if strings.Contains(cnameLower, "azurewebsites.net") {
		return "Azure-AppService"
	}
	if strings.Contains(cnameLower, "azureedge.net") {
		return "Azure-CDN"
	}
	
	// Google Cloud Services
	if strings.Contains(cnameLower, "googleusercontent.com") {
		return "GCP-Storage"
	}
	if strings.Contains(cnameLower, "appspot.com") {
		return "GCP-AppEngine"
	}
	
	// Cloudflare
	if strings.Contains(cnameLower, "cloudflare") {
		return "Cloudflare"
	}
	
	// Fastly
	if strings.Contains(cnameLower, "fastly") {
		return "Fastly-CDN"
	}
	
	// Akamai
	if strings.Contains(cnameLower, "akamai") || strings.Contains(cnameLower, "edgesuite.net") {
		return "Akamai-CDN"
	}
	
	return ""
}

// AnalyzeGeographicDifferences compares results across regions
func (g *GeoDNSResolver) AnalyzeGeographicDifferences(results map[string][]enumeration.DomainResult) GeoDNSAnalysis {
	analysis := GeoDNSAnalysis{
		RegionResults:    make(map[string]int),
		UniqueDomains:    make(map[string][]string),
		CloudServices:    make(map[string]map[string]int),
		GeographicSpread: make(map[string]bool),
	}
	
	allDomains := make(map[string]bool)
	regionDomains := make(map[string]map[string]bool)
	
	// Analyze each region's results
	for region, domainResults := range results {
		regionDomains[region] = make(map[string]bool)
		analysis.RegionResults[region] = len(domainResults)
		analysis.CloudServices[region] = make(map[string]int)
		
		for _, result := range domainResults {
			domain := result.Domain
			allDomains[domain] = true
			regionDomains[region][domain] = true
			
			// Track cloud services by region
			if cloudService, exists := result.DNSRecords["CLOUD_SERVICE"]; exists {
				analysis.CloudServices[region][cloudService]++
			}
		}
	}
	
	// Find region-specific domains
	for domain := range allDomains {
		var foundInRegions []string
		for region := range regionDomains {
			if regionDomains[region][domain] {
				foundInRegions = append(foundInRegions, region)
			}
		}
		
		if len(foundInRegions) < len(g.regions) {
			// Domain not found in all regions - geographic difference detected
			analysis.UniqueDomains[domain] = foundInRegions
			analysis.GeographicSpread[domain] = true
		}
	}
	
	return analysis
}

// GeoDNSAnalysis contains the results of geographic DNS analysis
type GeoDNSAnalysis struct {
	RegionResults    map[string]int              // Number of results per region
	UniqueDomains    map[string][]string         // Domains unique to specific regions
	CloudServices    map[string]map[string]int   // Cloud services by region
	GeographicSpread map[string]bool             // Domains with geographic differences
}

// PrintAnalysis displays the geographic DNS analysis results
func (a *GeoDNSAnalysis) PrintAnalysis() {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("                GEOGRAPHIC DNS ANALYSIS")
	fmt.Println(strings.Repeat("=", 60))
	
	// Region results summary
	fmt.Printf("\n🌍 Results by Region:\n")
	for region, count := range a.RegionResults {
		fmt.Printf("   %-20s: %d domains\n", region, count)
	}
	
	// Geographic differences
	if len(a.UniqueDomains) > 0 {
		fmt.Printf("\n🎯 Geographic Differences Detected:\n")
		for domain, regions := range a.UniqueDomains {
			fmt.Printf("   %-30s: %v\n", domain, regions)
		}
	} else {
		fmt.Printf("\n✅ No significant geographic differences detected\n")
	}
	
	// Cloud service distribution
	fmt.Printf("\n☁️  Cloud Services by Region:\n")
	for region, services := range a.CloudServices {
		if len(services) > 0 {
			fmt.Printf("   %s:\n", region)
			for service, count := range services {
				fmt.Printf("     %-20s: %d\n", service, count)
			}
		}
	}
	
	fmt.Println(strings.Repeat("=", 60))
}

// detectRoundRobin performs multiple DNS queries from baseline region to establish round-robin patterns
func (g *GeoDNSResolver) detectRoundRobin(ctx context.Context, domain string) (*enumeration.RoundRobinBaseline, error) {
	baseline := &enumeration.RoundRobinBaseline{
		Domain:         domain,
		AllIPs:         []string{},
		IPFrequency:    make(map[string]int),
		StableIPSet:    make(map[string]bool),
		BaselineRegion: "US-East", // Use US-East as baseline
		QueryCount:     6,
	}
	
	// Use US-East (4.2.2.2) as baseline region for consistent testing
	baselineClientIP := "4.2.2.2"
	
	if g.config.Verbose {
		fmt.Printf("Establishing round-robin baseline for %s from %s...\n", domain, baseline.BaselineRegion)
	}
	
	// Perform multiple queries with delays to detect rotation
	for i := 0; i < baseline.QueryCount; i++ {
		results, err := g.queryGoogleDNS(ctx, domain, "A", baselineClientIP)
		if err != nil {
			if g.config.Verbose {
				fmt.Printf("Baseline query %d failed for %s: %v\n", i+1, domain, err)
			}
			continue
		}
		
		for _, result := range results {
			if ip, exists := result.DNSRecords["A"]; exists {
				baseline.IPFrequency[ip]++
				if !contains(baseline.AllIPs, ip) {
					baseline.AllIPs = append(baseline.AllIPs, ip)
				}
			}
		}
		
		// Add delay between queries to catch rotation
		if i < baseline.QueryCount-1 {
			time.Sleep(200 * time.Millisecond)
		}
	}
	
	// Analyze if round-robin is detected
	if len(baseline.IPFrequency) > 1 && len(baseline.AllIPs) >= 2 {
		baseline.IsRoundRobin = true
		
		// Mark IPs that appeared in most queries as "stable" (part of round-robin set)
		threshold := baseline.QueryCount / 3 // Appear in at least 1/3 of queries
		for ip, frequency := range baseline.IPFrequency {
			if frequency >= threshold {
				baseline.StableIPSet[ip] = true
			}
		}
		
		if g.config.Verbose {
			fmt.Printf("Round-robin detected for %s: %d unique IPs across %d queries\n", 
				domain, len(baseline.AllIPs), baseline.QueryCount)
		}
	} else if g.config.Verbose {
		fmt.Printf("No round-robin detected for %s: %d unique IPs\n", domain, len(baseline.AllIPs))
	}
	
	return baseline, nil
}

// EnhancedGeoDNSAnalysis contains the results of enhanced geographic analysis
type EnhancedGeoDNSAnalysis struct {
	Domain                    string
	RoundRobinBaseline       *enumeration.RoundRobinBaseline
	RegionalData             map[string]RegionalAnalysis
	IdenticalRecords         *enumeration.IdenticalRecordInfo
	HasTrueGeographicRouting bool
	UniqueIPs                []string
	FilteredUniqueIPs        []string
}

type RegionalAnalysis struct {
	Region           string
	A                []string
	CNAME            string
	CloudService     string
	IsUnique         bool   // True if different from other regions
	IsBaselineFiltered bool // True if this data was filtered out as baseline
}

// analyzeWithBaseline performs enhanced geographic analysis with baseline filtering
func (g *GeoDNSResolver) analyzeWithBaseline(domain string, regionResults map[string][]enumeration.DomainResult, baseline *enumeration.RoundRobinBaseline) *EnhancedGeoDNSAnalysis {
	analysis := &EnhancedGeoDNSAnalysis{
		Domain:             domain,
		RoundRobinBaseline: baseline,
		RegionalData:       make(map[string]RegionalAnalysis),
		UniqueIPs:          []string{},
		FilteredUniqueIPs:  []string{},
	}
	
	// Collect all regional data
	allRegionalRecords := make(map[string]enumeration.RegionalDNSInfo)
	
	for _, region := range g.regions {
		regionName := region.Name
		results, hasResults := regionResults[regionName]
		
		if !hasResults {
			continue
		}
		
		regionalAnalysis := RegionalAnalysis{Region: regionName}
		
		// Process each result from this region
		for _, result := range results {
			if ip, exists := result.DNSRecords["A"]; exists {
				regionalAnalysis.A = append(regionalAnalysis.A, ip)
				
				// Add to unique IPs list if not already present
				if !contains(analysis.UniqueIPs, ip) {
					analysis.UniqueIPs = append(analysis.UniqueIPs, ip)
				}
				
				// Add to filtered list if not in baseline round-robin set
				if !baseline.IsRoundRobin || !baseline.StableIPSet[ip] {
					if !contains(analysis.FilteredUniqueIPs, ip) {
						analysis.FilteredUniqueIPs = append(analysis.FilteredUniqueIPs, ip)
					}
					regionalAnalysis.IsUnique = true
					analysis.HasTrueGeographicRouting = true
				} else {
					regionalAnalysis.IsBaselineFiltered = true
				}
			}
			
			if cname, exists := result.DNSRecords["CNAME"]; exists {
				regionalAnalysis.CNAME = cname
			}
			
			if cloudService, exists := result.DNSRecords["CLOUD_SERVICE"]; exists {
				regionalAnalysis.CloudService = cloudService
			}
		}
		
		analysis.RegionalData[regionName] = regionalAnalysis
		
		// Create regional record for legacy compatibility
		regionalInfo := enumeration.RegionalDNSInfo{
			A:            regionalAnalysis.A,
			CNAME:        regionalAnalysis.CNAME,
			CloudService: regionalAnalysis.CloudService,
		}
		allRegionalRecords[regionName] = regionalInfo
	}
	
	// Determine if records are identical across regions
	analysis.detectIdenticalRecords(allRegionalRecords)
	
	return analysis
}

// detectIdenticalRecords identifies records that are identical across all regions
func (analysis *EnhancedGeoDNSAnalysis) detectIdenticalRecords(allRegionalRecords map[string]enumeration.RegionalDNSInfo) {
	if len(allRegionalRecords) == 0 {
		return
	}
	
	// Get first region's records as baseline for comparison
	var firstRecord enumeration.RegionalDNSInfo
	for _, record := range allRegionalRecords {
		firstRecord = record
		break
	}
	
	// Check if all regions have identical records
	isIdentical := true
	var regions []string
	
	for region, record := range allRegionalRecords {
		regions = append(regions, region)
		
		// Compare A records
		if !stringSlicesEqual(record.A, firstRecord.A) {
			isIdentical = false
		}
		
		// Compare CNAME
		if record.CNAME != firstRecord.CNAME {
			isIdentical = false
		}
		
		// Compare cloud service
		if record.CloudService != firstRecord.CloudService {
			isIdentical = false
		}
	}
	
	// If all records are identical, store in IdenticalRecords
	if isIdentical && len(regions) > 1 {
		analysis.IdenticalRecords = &enumeration.IdenticalRecordInfo{
			A:            firstRecord.A,
			CNAME:        firstRecord.CNAME,
			CloudService: firstRecord.CloudService,
			Regions:      regions,
		}
	}
}

// HasMeaningfulResults determines if the analysis contains meaningful geographic differences
func (analysis *EnhancedGeoDNSAnalysis) HasMeaningfulResults() bool {
	// Include if there are true geographic differences
	if analysis.HasTrueGeographicRouting {
		return true
	}
	
	// Include if round-robin was detected (useful information)
	if analysis.RoundRobinBaseline.IsRoundRobin {
		return true
	}
	
	// Include if there are multiple unique IPs (even if they're all round-robin)
	if len(analysis.UniqueIPs) > 1 {
		return true
	}
	
	// Skip if only identical records across all regions with single IP
	return false
}

// ToGeoDNSDetails converts analysis to GeoDNSDetails format
func (analysis *EnhancedGeoDNSAnalysis) ToGeoDNSDetails() *enumeration.GeoDNSDetails {
	details := &enumeration.GeoDNSDetails{
		// Enhanced fields
		RoundRobinDetected:     analysis.RoundRobinBaseline.IsRoundRobin,
		BaselineIPs:            analysis.RoundRobinBaseline.AllIPs,
		BaselineRegion:         analysis.RoundRobinBaseline.BaselineRegion,
		IsGeographic:           analysis.HasTrueGeographicRouting,
		HasRegionalDifferences: len(analysis.FilteredUniqueIPs) > 0,
		UniqueIPs:              analysis.UniqueIPs,
		FilteredUniqueIPs:      analysis.FilteredUniqueIPs,
		RegionsWithDifferences: len(analysis.RegionalData),
		IdenticalAcrossRegions: analysis.IdenticalRecords,
		
		// Only include unique regional records (not identical ones)
		UniqueRegionalRecords: make(map[string]enumeration.RegionalDNSInfo),
		
		// Legacy fields for backward compatibility
		RegionalRecords:  make(map[string]enumeration.RegionalDNSInfo),
		FoundInRegions:   []string{},
		MissingInRegions: []string{},
	}
	
	// Populate unique regional records (only regions with differences)
	for region, regionalAnalysis := range analysis.RegionalData {
		if regionalAnalysis.IsUnique {
			details.UniqueRegionalRecords[region] = enumeration.RegionalDNSInfo{
				A:            regionalAnalysis.A,
				CNAME:        regionalAnalysis.CNAME,
				CloudService: regionalAnalysis.CloudService,
			}
		}
		
		// Legacy compatibility - include all regional records
		details.RegionalRecords[region] = enumeration.RegionalDNSInfo{
			A:            regionalAnalysis.A,
			CNAME:        regionalAnalysis.CNAME,
			CloudService: regionalAnalysis.CloudService,
		}
		details.FoundInRegions = append(details.FoundInRegions, region)
	}
	
	return details
}

// Helper functions
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}