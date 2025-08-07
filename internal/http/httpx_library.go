package http

import (
	"context"
	"fmt"
	"os"
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
		// CSPData is a structured type - access its string representation or fields
		cspStr := fmt.Sprintf("%v", result.CSPData)
		if cspStr != "" && cspStr != "<nil>" {
			extractedDomains := h.extractDomainsFromCSP(cspStr, targetDomain)
			for _, domain := range extractedDomains {
				if !domainSet[domain] {
					domainSet[domain] = true
					domains = append(domains, domain)
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

// extractDomainsFromCSP extracts domains from CSP header
func (h *HTTPXLibrary) extractDomainsFromCSP(csp, targetDomain string) []string {
	var domains []string
	// Simple CSP parsing - look for domain patterns
	words := strings.Fields(csp)
	for _, word := range words {
		if strings.Contains(word, ".") && !strings.HasPrefix(word, "http") {
			// Clean up CSP directives
			domain := strings.TrimPrefix(word, "https://")
			domain = strings.TrimPrefix(domain, "http://")
			domain = strings.TrimSuffix(domain, ";")
			domain = strings.TrimSpace(domain)

			if h.isValidSubdomain(domain, targetDomain) {
				domains = append(domains, domain)
			}
		}
	}
	return domains
}

// extractDomainsFromTLS extracts domains from TLS certificate data
func (h *HTTPXLibrary) extractDomainsFromTLS(tlsData interface{}, targetDomain string) []string {
	var domains []string

	// TLS data structure depends on httpx implementation
	// This is a simplified extraction - may need adjustment based on actual structure
	if tlsMap, ok := tlsData.(map[string]interface{}); ok {
		// Look for subject alternative names
		if san, exists := tlsMap["subject_an"]; exists {
			if sanStr, ok := san.(string); ok {
				sanDomains := strings.Split(sanStr, ",")
				for _, domain := range sanDomains {
					domain = strings.TrimSpace(domain)
					// Remove wildcard prefix if present
					if strings.HasPrefix(domain, "*.") {
						domain = domain[2:]
					}
					if h.isValidSubdomain(domain, targetDomain) {
						domains = append(domains, domain)
					}
				}
			}
		}

		// Check subject CN
		if cn, exists := tlsMap["subject_cn"]; exists {
			if cnStr, ok := cn.(string); ok {
				domain := strings.TrimSpace(cnStr)
				if strings.HasPrefix(domain, "*.") {
					domain = domain[2:]
				}
				if h.isValidSubdomain(domain, targetDomain) {
					domains = append(domains, domain)
				}
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