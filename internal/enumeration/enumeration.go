package enumeration

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/resistanceisuseless/subscope/internal/config"
)

type Enumerator struct {
	config *config.Config
}

type DomainResult struct {
	Domain     string            `json:"domain"`
	Status     string            `json:"status"`
	DNSRecords map[string]string `json:"dns_records,omitempty"`
	Source     string            `json:"source"`
	Timestamp  time.Time         `json:"timestamp"`
	GeoDNS     *GeoDNSDetails    `json:"geodns,omitempty"`
}

// GeoDNSDetails contains enhanced geographic DNS analysis information
type GeoDNSDetails struct {
	// Round-robin detection results
	RoundRobinDetected bool     `json:"round_robin_detected"`
	BaselineIPs        []string `json:"baseline_ips,omitempty"`
	BaselineRegion     string   `json:"baseline_region,omitempty"`
	
	// Geographic analysis results
	IsGeographic           bool                        `json:"is_geographic"`
	HasRegionalDifferences bool                        `json:"has_regional_differences"`
	UniqueRegionalRecords  map[string]RegionalDNSInfo  `json:"unique_regional_records,omitempty"`
	IdenticalAcrossRegions *IdenticalRecordInfo        `json:"identical_across_regions,omitempty"`
	
	// Tool-chaining friendly outputs
	UniqueIPs              []string `json:"unique_ips,omitempty"`
	FilteredUniqueIPs      []string `json:"filtered_unique_ips,omitempty"` // Excludes baseline round-robin IPs
	RegionsWithDifferences int      `json:"regions_with_differences"`
	
	// Legacy fields for backward compatibility (deprecated)
	FoundInRegions   []string                   `json:"found_in_regions,omitempty"`
	MissingInRegions []string                   `json:"missing_in_regions,omitempty"`
	RegionalRecords  map[string]RegionalDNSInfo `json:"regional_records,omitempty"`
}

// RegionalDNSInfo contains DNS records specific to a region
type RegionalDNSInfo struct {
	A            []string `json:"a,omitempty"`
	CNAME        string   `json:"cname,omitempty"`
	CloudService string   `json:"cloud_service,omitempty"`
}

// IdenticalRecordInfo contains records that are identical across all regions
type IdenticalRecordInfo struct {
	A            []string `json:"a,omitempty"`
	CNAME        string   `json:"cname,omitempty"`
	CloudService string   `json:"cloud_service,omitempty"`
	Regions      []string `json:"regions"`
}

// RoundRobinBaseline contains results from baseline round-robin detection
type RoundRobinBaseline struct {
	Domain         string         `json:"domain"`
	AllIPs         []string       `json:"all_ips"`
	IPFrequency    map[string]int `json:"ip_frequency"`
	IsRoundRobin   bool           `json:"is_round_robin"`
	StableIPSet    map[string]bool `json:"stable_ip_set"`
	BaselineRegion string         `json:"baseline_region"`
	QueryCount     int            `json:"query_count"`
}

func New(config *config.Config) *Enumerator {
	return &Enumerator{
		config: config,
	}
}

func (e *Enumerator) RunPassiveEnumeration(ctx context.Context, domain string) ([]string, error) {
	fmt.Fprintf(os.Stderr, "Running passive enumeration for domain: %s\n", domain)
	
	// Check if subfinder is available
	if _, err := exec.LookPath("subfinder"); err != nil {
		return nil, fmt.Errorf("subfinder not found in PATH. Please install it: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
	}
	
	// Build subfinder command
	args := []string{"-d", domain, "-silent"}
	
	// Add providers if specified
	if len(e.config.Subfinder.Providers) > 0 {
		providers := strings.Join(e.config.Subfinder.Providers, ",")
		args = append(args, "-sources", providers)
	}
	
	// Add timeout if specified
	if e.config.Subfinder.Timeout > 0 {
		args = append(args, "-timeout", fmt.Sprintf("%d", e.config.Subfinder.Timeout))
	}
	
	// Add config path if specified and file exists
	if e.config.Subfinder.ConfigPath != "" {
		// Skip adding config path for now - it might be causing issues
		// args = append(args, "-config", e.config.Subfinder.ConfigPath)
	}
	
	
	cmd := exec.CommandContext(ctx, "subfinder", args...)
	
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start subfinder: %w", err)
	}
	
	var domains []string
	scanner := bufio.NewScanner(stdout)
	
	// Read all domains before waiting for command to complete
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			domains = append(domains, domain)
			if e.config.Verbose {
				fmt.Printf("Found domain: %s\n", domain)
			}
		}
	}
	
	// Wait for command to complete
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("subfinder command failed: %w", err)
	}
	
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading subfinder output: %w", err)
	}
	
	fmt.Fprintf(os.Stderr, "Passive enumeration completed. Found %d domains.\n", len(domains))
	return domains, nil
}

func (e *Enumerator) ProcessDomains(domains []string) []DomainResult {
	var results []DomainResult
	
	for _, domain := range domains {
		result := DomainResult{
			Domain:    domain,
			Status:    "discovered",
			Source:    "subfinder",
			Timestamp: time.Now(),
		}
		results = append(results, result)
	}
	
	return results
}

func (e *Enumerator) ProcessPermutations(permutations []string) []DomainResult {
	var results []DomainResult
	
	for _, domain := range permutations {
		result := DomainResult{
			Domain:    domain,
			Status:    "discovered",
			Source:    "alterx",
			Timestamp: time.Now(),
		}
		results = append(results, result)
	}
	
	return results
}

func (e *Enumerator) ProcessCTDomains(ctDomains []string) []DomainResult {
	var results []DomainResult
	
	for _, domain := range ctDomains {
		result := DomainResult{
			Domain:    domain,
			Status:    "discovered",
			Source:    "certificate_transparency",
			Timestamp: time.Now(),
		}
		results = append(results, result)
	}
	
	return results
}

func (e *Enumerator) ProcessHTTPDomains(httpDomains []string) []DomainResult {
	var results []DomainResult
	
	for _, domain := range httpDomains {
		result := DomainResult{
			Domain:    domain,
			Status:    "discovered",
			Source:    "httpx",
			Timestamp: time.Now(),
		}
		results = append(results, result)
	}
	
	return results
}

func (e *Enumerator) ProcessRDNSDomains(rdnsDomains []string) []DomainResult {
	var results []DomainResult
	
	for _, domain := range rdnsDomains {
		result := DomainResult{
			Domain:    domain,
			Status:    "discovered",
			Source:    "rdns",
			Timestamp: time.Now(),
		}
		results = append(results, result)
	}
	
	return results
}

func (e *Enumerator) ProcessZoneTransferDomains(zoneTransferDomains []string) []DomainResult {
	var results []DomainResult
	
	for _, domain := range zoneTransferDomains {
		result := DomainResult{
			Domain:    domain,
			Status:    "discovered",
			Source:    "zone_transfer",
			Timestamp: time.Now(),
		}
		results = append(results, result)
	}
	
	return results
}

func (e *Enumerator) ProcessRDNSRangeDomains(rdnsRangeDomains []string) []DomainResult {
	var results []DomainResult
	
	for _, domain := range rdnsRangeDomains {
		result := DomainResult{
			Domain:    domain,
			Status:    "discovered",
			Source:    "rdns_range",
			Timestamp: time.Now(),
		}
		results = append(results, result)
	}
	
	return results
}

func (e *Enumerator) ProcessGeoDNSDomains(geoDNSDomains []string) []DomainResult {
	var results []DomainResult
	
	for _, domain := range geoDNSDomains {
		result := DomainResult{
			Domain:    domain,
			Status:    "discovered",
			Source:    "geodns",
			Timestamp: time.Now(),
		}
		results = append(results, result)
	}
	
	return results
}

// LoadInputDomains loads domains from a file for iterative scanning
func (e *Enumerator) LoadInputDomains(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	
	fmt.Fprintf(os.Stderr, "Loading input domains from: %s\n", path)
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open input domains file: %w", err)
	}
	defer file.Close()
	
	var domains []string
	scanner := bufio.NewScanner(file)
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		domain := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines and comments
		if domain == "" || strings.HasPrefix(domain, "#") {
			continue
		}
		
		// Validate domain format
		if isValidDomain(domain) {
			domains = append(domains, domain)
		} else if e.config.Verbose {
			fmt.Printf("Warning: Invalid domain format on line %d: %s\n", lineNum, domain)
		}
	}
	
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading input domains file: %w", err)
	}
	
	fmt.Fprintf(os.Stderr, "Loaded %d valid domains from input file\n", len(domains))
	return domains, nil
}

// ProcessInputDomains processes domains from input file
func (e *Enumerator) ProcessInputDomains(inputDomains []string) []DomainResult {
	var results []DomainResult
	
	for _, domain := range inputDomains {
		result := DomainResult{
			Domain:    domain,
			Status:    "discovered",
			Source:    "input_file",
			Timestamp: time.Now(),
		}
		results = append(results, result)
	}
	
	return results
}

// isValidDomain validates domain name format
func isValidDomain(domain string) bool {
	// Basic domain validation
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	
	// Check for valid domain pattern
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if !domainRegex.MatchString(domain) {
		return false
	}
	
	// Additional check: must have at least one dot (be a subdomain or domain)
	if !strings.Contains(domain, ".") {
		return false
	}
	
	// Validate using Go's built-in validation
	if _, err := net.LookupHost(domain); err != nil {
		// Don't fail validation just because DNS lookup fails
		// The domain format might be valid even if it doesn't resolve
	}
	
	return true
}