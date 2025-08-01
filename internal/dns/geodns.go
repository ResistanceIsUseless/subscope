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

// QueryDomainsFromAllRegions queries multiple domains and returns enriched results with GeoDNS details
func (g *GeoDNSResolver) QueryDomainsFromAllRegions(ctx context.Context, domains []string) ([]enumeration.DomainResult, error) {
	// Return early if no domains provided
	if len(domains) == 0 {
		return []enumeration.DomainResult{}, nil
	}
	
	// Map to track all results by domain
	domainRegionMap := make(map[string]map[string]enumeration.RegionalDNSInfo)
	allResults := make(map[string]*enumeration.DomainResult)
	
	for _, domain := range domains {
		domainRegionMap[domain] = make(map[string]enumeration.RegionalDNSInfo)
		
		// Query from all regions
		regionResults, err := g.QueryFromAllRegions(ctx, domain)
		if err != nil {
			continue
		}
		
		// Process results from each region
		for region, results := range regionResults {
			for _, result := range results {
				// Create or update the domain result
				if _, exists := allResults[result.Domain]; !exists {
					allResults[result.Domain] = &enumeration.DomainResult{
						Domain:     result.Domain,
						Status:     result.Status,
						Source:     "geodns",
						Timestamp:  result.Timestamp,
						DNSRecords: make(map[string]string),
						GeoDNS:     &enumeration.GeoDNSDetails{
							RegionalRecords: make(map[string]enumeration.RegionalDNSInfo),
						},
					}
				}
				
				// Ensure domainRegionMap is initialized for this domain
				if _, exists := domainRegionMap[result.Domain]; !exists {
					domainRegionMap[result.Domain] = make(map[string]enumeration.RegionalDNSInfo)
				}
				
				// Collect regional DNS info
				regionalInfo := enumeration.RegionalDNSInfo{}
				
				// Extract A records
				if aRecord, exists := result.DNSRecords["A"]; exists {
					regionalInfo.A = []string{aRecord}
				}
				
				// Extract CNAME
				if cname, exists := result.DNSRecords["CNAME"]; exists {
					regionalInfo.CNAME = cname
				}
				
				// Extract cloud service
				if cloudService, exists := result.DNSRecords["CLOUD_SERVICE"]; exists {
					regionalInfo.CloudService = cloudService
				}
				
				// Store regional info
				allResults[result.Domain].GeoDNS.RegionalRecords[region] = regionalInfo
				domainRegionMap[result.Domain][region] = regionalInfo
			}
		}
	}
	
	// Analyze which regions found each domain
	for _, result := range allResults {
		foundRegions := make([]string, 0)
		missingRegions := make([]string, 0)
		
		for _, region := range g.regions {
			if _, found := result.GeoDNS.RegionalRecords[region.Name]; found {
				foundRegions = append(foundRegions, region.Name)
			} else {
				missingRegions = append(missingRegions, region.Name)
			}
		}
		
		result.GeoDNS.FoundInRegions = foundRegions
		result.GeoDNS.MissingInRegions = missingRegions
		result.GeoDNS.IsGeographic = len(missingRegions) > 0
	}
	
	// Convert map to slice
	var finalResults []enumeration.DomainResult
	for _, result := range allResults {
		finalResults = append(finalResults, *result)
	}
	
	return finalResults, nil
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