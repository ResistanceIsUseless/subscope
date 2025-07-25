package ct

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/resistanceisuseless/subscope/internal/config"
)

type Analyzer struct {
	config     *config.Config
	httpClient *http.Client
}

type Certificate struct {
	IssuerCAID     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	ID             int64  `json:"id"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	SerialNumber   string `json:"serial_number"`
}

func New(config *config.Config) *Analyzer {
	return &Analyzer{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (ct *Analyzer) QueryCertificates(ctx context.Context, domain string) ([]string, error) {
	fmt.Printf("Querying Certificate Transparency logs for: %s\n", domain)
	
	// Add stealth capabilities - random delay
	if ct.config.Stealth.RequestJitter && ct.config.Stealth.RandomDelay > 0 {
		delay := rand.Intn(ct.config.Stealth.RandomDelay)
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}
	
	// Query crt.sh API
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create CT request: %w", err)
	}
	
	// Use random User-Agent from configured list
	userAgent := "SubScope/0.1.0"
	if len(ct.config.Stealth.UserAgents) > 0 {
		userAgent = ct.config.Stealth.UserAgents[rand.Intn(len(ct.config.Stealth.UserAgents))]
	}
	req.Header.Set("User-Agent", userAgent)
	
	resp, err := ct.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CT query failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CT API returned status %d", resp.StatusCode)
	}
	
	var certs []Certificate
	if err := json.NewDecoder(resp.Body).Decode(&certs); err != nil {
		// Some responses might be empty or malformed
		return []string{}, nil
	}
	
	// Extract unique subdomains
	subdomains := make(map[string]bool)
	targetDomain := domain
	
	for _, cert := range certs {
		names := ct.extractSubdomainsFromCert(cert, targetDomain)
		for _, name := range names {
			if ct.isValidSubdomain(name, targetDomain) {
				subdomains[name] = true
			}
		}
	}
	
	// Convert to slice
	var result []string
	for subdomain := range subdomains {
		result = append(result, subdomain)
	}
	
	fmt.Printf("Certificate Transparency found %d unique subdomains\n", len(result))
	return result, nil
}

func (ct *Analyzer) extractSubdomainsFromCert(cert Certificate, targetDomain string) []string {
	var domains []string
	
	// Extract from common name
	if cert.CommonName != "" {
		domains = append(domains, cert.CommonName)
	}
	
	// Extract from Subject Alternative Names (in name_value field)
	if cert.NameValue != "" {
		// name_value contains newline-separated domain names
		names := strings.Split(cert.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name != "" {
				domains = append(domains, name)
			}
		}
	}
	
	// Clean and filter domains
	var cleanDomains []string
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		domain = strings.ToLower(domain)
		
		// Remove wildcard prefix
		if strings.HasPrefix(domain, "*.") {
			domain = domain[2:]
		}
		
		if domain != "" && strings.Contains(domain, targetDomain) {
			cleanDomains = append(cleanDomains, domain)
		}
	}
	
	return cleanDomains
}

func (ct *Analyzer) isValidSubdomain(subdomain, targetDomain string) bool {
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