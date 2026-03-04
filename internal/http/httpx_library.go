package http

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/httpx/runner"
	"github.com/resistanceisuseless/subscope/internal/config"
)

// HTTPXLibrary implements library-based httpx integration
type HTTPXLibrary struct {
	config *config.Config
}

// NewHTTPXLibrary creates a new library-based httpx analyzer
func NewHTTPXLibrary(config *config.Config) *HTTPXLibrary {
	return &HTTPXLibrary{
		config: config,
	}
}

// AnalyzeDomains performs HTTP/HTTPS analysis using httpx library
func (h *HTTPXLibrary) AnalyzeDomains(ctx context.Context, domains []string, targetDomain string) ([]string, error) {
	if len(domains) == 0 {
		return []string{}, nil
	}

	// Limit to reasonable number for HTTP analysis
	analyzeCount := len(domains)
	if analyzeCount > 500 {
		analyzeCount = 500
		fmt.Fprintf(os.Stderr, "Limiting httpx analysis to first %d domains\n", analyzeCount)
	}

	fmt.Fprintf(os.Stderr, "Starting httpx analysis (library mode) for %d domains...\n", analyzeCount)

	// Prepare domain list for analysis
	analyzeDomains := domains[:analyzeCount]
	var discoveredDomains []string
	domainSet := make(map[string]bool)

	// Configure httpx options
	options := runner.Options{
		Methods:            "GET",
		InputTargetHost:    goflags.StringSlice(analyzeDomains),
		JSONOutput:         true,
		Silent:             true,
		NoColor:            true,
		Timeout:            10,
		Retries:            1,
		Threads:            20,
		FollowRedirects:    true,
		TLSProbe:           true,
		CSPProbe:           true,
		TechDetect:         true,
		Location:           true,
		OutputServerHeader: true,
		StatusCode:         true,
		ContentLength:      true,
		OutputResponseTime: true,
		OnResult: func(r runner.Result) {
			if r.Err != nil {
				if h.config.Verbose {
					fmt.Fprintf(os.Stderr, "  Error analyzing %s: %v\n", r.Input, r.Err)
				}
				return
			}

			if h.config.Verbose {
				fmt.Fprintf(os.Stderr, "  HTTP response from %s (status: %d)\n", r.URL, r.StatusCode)
			}

			// Extract domains from httpx result
			newDomains := h.extractDomainsFromResult(r, targetDomain)
			if h.config.Verbose && len(newDomains) > 0 {
				fmt.Fprintf(os.Stderr, "    Found %d new domains from %s\n", len(newDomains), r.URL)
			}

			for _, domain := range newDomains {
				if !domainSet[domain] {
					domainSet[domain] = true
					discoveredDomains = append(discoveredDomains, domain)
					if h.config.Verbose {
						fmt.Fprintf(os.Stderr, "    New domain: %s\n", domain)
					}
				}
			}
		},
	}

	// Validate options
	if err := options.ValidateOptions(); err != nil {
		return nil, fmt.Errorf("failed to validate httpx options: %v", err)
	}

	// Create and run httpx
	httpxRunner, err := runner.New(&options)
	if err != nil {
		return nil, fmt.Errorf("failed to create httpx runner: %v", err)
	}
	defer httpxRunner.Close()

	// Run enumeration within context
	done := make(chan struct{})
	go func() {
		defer close(done)
		httpxRunner.RunEnumeration()
	}()

	// Wait for completion or context cancellation
	select {
	case <-done:
		// Enumeration completed successfully
	case <-ctx.Done():
		fmt.Fprintf(os.Stderr, "Warning: httpx analysis cancelled due to timeout\n")
		return discoveredDomains, ctx.Err()
	}

	fmt.Fprintf(os.Stderr, "httpx analysis (library mode) found %d additional subdomains\n", len(discoveredDomains))
	return discoveredDomains, nil
}

// extractDomainsFromResult extracts domains from httpx runner.Result
func (h *HTTPXLibrary) extractDomainsFromResult(result runner.Result, targetDomain string) []string {
	var domains []string
	domainSet := make(map[string]bool)

	// Extract from redirect location
	if result.Location != "" {
		if domain := h.extractDomainFromURL(result.Location); domain != "" {
			if h.isValidSubdomain(domain, targetDomain) && !domainSet[domain] {
				domainSet[domain] = true
				domains = append(domains, domain)
			}
		}
	}

	// Extract from final URL (after redirects)
	if result.FinalURL != "" && result.FinalURL != result.URL {
		if domain := h.extractDomainFromURL(result.FinalURL); domain != "" {
			if h.isValidSubdomain(domain, targetDomain) && !domainSet[domain] {
				domainSet[domain] = true
				domains = append(domains, domain)
			}
		}
	}

	// Extract from CSP (Content Security Policy) headers
	if result.CSPData != nil {
		// JSON marshal the CSP struct so we get a consistent string representation
		// with actual values (not Go syntax like &{map[...]}) that we can apply
		// a domain regex to.
		if jsonBytes, err := json.Marshal(result.CSPData); err == nil {
			cspStr := string(jsonBytes)
			if cspStr != "" && cspStr != "null" {
				extractedDomains := h.extractDomainsFromCSP(cspStr, targetDomain)
				for _, domain := range extractedDomains {
					if !domainSet[domain] {
						domainSet[domain] = true
						domains = append(domains, domain)
					}
				}
			}
		}
	}

	// Extract from TLS certificate data (if available)
	if result.TLSData != nil {
		extractedDomains := h.extractDomainsFromTLS(result.TLSData, targetDomain)
		for _, domain := range extractedDomains {
			if !domainSet[domain] {
				domainSet[domain] = true
				domains = append(domains, domain)
			}
		}
	}

	return domains
}

// extractDomainFromURL extracts domain from URL string
func (h *HTTPXLibrary) extractDomainFromURL(urlStr string) string {
	// Simple domain extraction from URL
	if strings.HasPrefix(urlStr, "http://") {
		urlStr = urlStr[7:]
	} else if strings.HasPrefix(urlStr, "https://") {
		urlStr = urlStr[8:]
	}

	// Find first slash or colon
	if idx := strings.IndexAny(urlStr, "/:"); idx >= 0 {
		urlStr = urlStr[:idx]
	}

	return strings.ToLower(urlStr)
}

// extractDomainsFromCSP extracts domains from a CSP string (raw header or JSON representation)
func (h *HTTPXLibrary) extractDomainsFromCSP(csp, targetDomain string) []string {
	var domains []string
	domainRegex := regexp.MustCompile(`[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+`)
	matches := domainRegex.FindAllString(csp, -1)
	for _, match := range matches {
		domain := strings.ToLower(strings.TrimSpace(match))
		if h.isValidSubdomain(domain, targetDomain) {
			domains = append(domains, domain)
		}
	}
	return domains
}

// extractDomainsFromTLS extracts domains from TLS certificate data.
// The httpx library returns a typed struct (e.g. *cryptoutil.SimpleX509Certificate),
// not a map, so we JSON-marshal it first to get a consistent map representation
// that matches the JSON field names used in exec mode ("subject_an", "subject_cn").
func (h *HTTPXLibrary) extractDomainsFromTLS(tlsData interface{}, targetDomain string) []string {
	var domains []string

	jsonBytes, err := json.Marshal(tlsData)
	if err != nil {
		return domains
	}

	var tlsMap map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &tlsMap); err != nil {
		return domains
	}

	// Subject Alternative Names
	if san, exists := tlsMap["subject_an"]; exists {
		switch v := san.(type) {
		case string:
			for _, domain := range strings.Split(v, ",") {
				domain = strings.TrimSpace(strings.TrimPrefix(domain, "*."))
				if h.isValidSubdomain(domain, targetDomain) {
					domains = append(domains, domain)
				}
			}
		case []interface{}:
			for _, item := range v {
				if s, ok := item.(string); ok {
					domain := strings.TrimSpace(strings.TrimPrefix(s, "*."))
					if h.isValidSubdomain(domain, targetDomain) {
						domains = append(domains, domain)
					}
				}
			}
		}
	}

	// Subject Common Name
	if cn, exists := tlsMap["subject_cn"]; exists {
		if cnStr, ok := cn.(string); ok {
			domain := strings.TrimSpace(strings.TrimPrefix(cnStr, "*."))
			if h.isValidSubdomain(domain, targetDomain) {
				domains = append(domains, domain)
			}
		}
	}

	return domains
}

// isValidSubdomain validates if domain is a valid subdomain of target
func (h *HTTPXLibrary) isValidSubdomain(subdomain, targetDomain string) bool {
	// Must contain target domain
	if !strings.Contains(subdomain, targetDomain) {
		return false
	}

	// Basic domain validation
	if len(subdomain) == 0 || len(subdomain) > 253 {
		return false
	}

	// Must be a subdomain of target domain or the target domain itself
	if subdomain == targetDomain || strings.HasSuffix(subdomain, "."+targetDomain) {
		return true
	}

	return false
}