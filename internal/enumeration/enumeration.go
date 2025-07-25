package enumeration

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
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
}

func New(config *config.Config) *Enumerator {
	return &Enumerator{
		config: config,
	}
}

func (e *Enumerator) RunPassiveEnumeration(ctx context.Context, domain string) ([]string, error) {
	fmt.Printf("Running passive enumeration for domain: %s\n", domain)
	
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
	
	fmt.Printf("Passive enumeration completed. Found %d domains.\n", len(domains))
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