package http

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/resistanceisuseless/subscope/internal/config"
)

type Analyzer struct {
	config *config.Config
}

type HTTPXResult struct {
	URL            string                 `json:"url"`
	Input          string                 `json:"input"`
	Title          string                 `json:"title"`
	StatusCode     int                    `json:"status-code"`
	ContentLength  int                    `json:"content-length"`
	ResponseTime   string                 `json:"response-time"`
	WebServer      string                 `json:"webserver"`
	TLSData        map[string]interface{} `json:"tls"`
	CSPData        string                 `json:"csp"`
	Location       string                 `json:"location"`
	FinalURL       string                 `json:"final-url"`
	Technologies   []string               `json:"tech"`
}

func New(config *config.Config) *Analyzer {
	return &Analyzer{
		config: config,
	}
}

func (h *Analyzer) AnalyzeDomains(ctx context.Context, domains []string, targetDomain string) ([]string, error) {
	fmt.Fprintf(os.Stderr, "Starting httpx analysis for %d domains...\n", len(domains))
	
	// Check if httpx is available
	if _, err := exec.LookPath("httpx"); err != nil {
		return nil, fmt.Errorf("httpx not found in PATH. Please install it: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
	}
	
	// Limit to reasonable number for HTTP analysis
	analyzeCount := len(domains)
	if analyzeCount > 500 {
		analyzeCount = 500
		fmt.Fprintf(os.Stderr, "Limiting httpx analysis to first %d domains\n", analyzeCount)
	}
	
	// Build httpx command
	args := []string{
		"-json",                    // JSON output
		"-silent",                  // Suppress banner
		"-no-color",               // No color output
		"-timeout", "10",          // 10 second timeout
		"-retries", "1",           // 1 retry
		"-threads", "20",          // 20 threads
		"-follow-redirects",       // Follow redirects
		"-tls-probe",              // Extract TLS data
		"-csp-probe",              // Extract CSP headers
		"-location",               // Include redirect location
		"-tech-detect",            // Technology detection
		"-web-server",             // Extract web server
		"-status-code",            // Include status code
		"-content-length",         // Include content length
		"-response-time",          // Include response time
	}
	
	cmd := exec.CommandContext(ctx, "httpx", args...)
	
	// Create stdin pipe to send domains
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}
	
	// Create stdout pipe to read results
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	
	// Start httpx
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start httpx: %w", err)
	}
	
	// Send domains to httpx
	go func() {
		defer stdin.Close()
		for i := 0; i < analyzeCount; i++ {
			if h.config.Verbose {
				fmt.Fprintf(os.Stderr, "  Testing HTTP/HTTPS: %s\n", domains[i])
			}
			fmt.Fprintf(stdin, "%s\n", domains[i])
		}
	}()
	
	// Read and parse results
	var discoveredDomains []string
	domainSet := make(map[string]bool)
	scanner := bufio.NewScanner(stdout)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		
		var result HTTPXResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue // Skip malformed JSON
		}
		
		if h.config.Verbose {
			fmt.Fprintf(os.Stderr, "  HTTP response from %s (status: %d)\n", result.URL, result.StatusCode)
		}
		
		// Extract domains from various sources
		newDomains := h.extractDomainsFromHTTPX(result, targetDomain)
		if h.config.Verbose && len(newDomains) > 0 {
			fmt.Fprintf(os.Stderr, "    Found %d new domains from %s\n", len(newDomains), result.URL)
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
	}
	
	// Wait for httpx to complete
	if err := cmd.Wait(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: httpx completed with error: %v\n", err)
	}
	
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading httpx output: %w", err)
	}
	
	fmt.Fprintf(os.Stderr, "httpx analysis found %d additional subdomains\n", len(discoveredDomains))
	return discoveredDomains, nil
}

func (h *Analyzer) extractDomainsFromHTTPX(result HTTPXResult, targetDomain string) []string {
	var domains []string
	domainSet := make(map[string]bool)
	
	// Domain extraction regex
	domainRegex := regexp.MustCompile(`[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	
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
	if result.CSPData != "" {
		matches := domainRegex.FindAllString(result.CSPData, -1)
		for _, match := range matches {
			domain := strings.ToLower(strings.TrimSpace(match))
			if h.isValidSubdomain(domain, targetDomain) && !domainSet[domain] {
				domainSet[domain] = true
				domains = append(domains, domain)
			}
		}
	}
	
	// Extract from TLS certificate data
	if result.TLSData != nil {
		if san, exists := result.TLSData["subject_an"]; exists {
			if sanStr, ok := san.(string); ok {
				matches := domainRegex.FindAllString(sanStr, -1)
				for _, match := range matches {
					domain := strings.ToLower(strings.TrimSpace(match))
					// Remove wildcard prefix if present
					if strings.HasPrefix(domain, "*.") {
						domain = domain[2:]
					}
					if h.isValidSubdomain(domain, targetDomain) && !domainSet[domain] {
						domainSet[domain] = true
						domains = append(domains, domain)
					}
				}
			}
		}
		
		// Also check subject CN
		if cn, exists := result.TLSData["subject_cn"]; exists {
			if cnStr, ok := cn.(string); ok {
				domain := strings.ToLower(strings.TrimSpace(cnStr))
				if strings.HasPrefix(domain, "*.") {
					domain = domain[2:]
				}
				if h.isValidSubdomain(domain, targetDomain) && !domainSet[domain] {
					domainSet[domain] = true
					domains = append(domains, domain)
				}
			}
		}
	}
	
	return domains
}

func (h *Analyzer) extractDomainFromURL(urlStr string) string {
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

func (h *Analyzer) isValidSubdomain(subdomain, targetDomain string) bool {
	// Must contain target domain
	if !strings.Contains(subdomain, targetDomain) {
		return false
	}
	
	// Basic domain validation
	if len(subdomain) == 0 || len(subdomain) > 253 {
		return false
	}
	
	// Check for valid characters
	validDomain := regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
	if !validDomain.MatchString(subdomain) {
		return false
	}
	
	// Check for consecutive dots or invalid patterns
	if strings.Contains(subdomain, "..") || strings.HasPrefix(subdomain, ".") || strings.HasSuffix(subdomain, ".") {
		return false
	}
	
	// Must be a subdomain of target domain or the target domain itself
	if subdomain == targetDomain || strings.HasSuffix(subdomain, "."+targetDomain) {
		return true
	}
	
	return false
}