package wildcard

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	"github.com/resistanceisuseless/subscope/internal/config"
	"github.com/resistanceisuseless/subscope/internal/enumeration"
)

type Detector struct {
	config      *config.Config
	resolver    *net.Resolver
	wildcardIPs map[string][]string // domain -> wildcard IPs
}

type WildcardTest struct {
	Domain     string
	TestDomain string
	IPs        []string
	IsWildcard bool
}

func New(config *config.Config) *Detector {
	return &Detector{
		config:      config,
		resolver:    &net.Resolver{},
		wildcardIPs: make(map[string][]string),
	}
}

func (w *Detector) DetectWildcards(ctx context.Context, targetDomain string) error {
	fmt.Fprintf(os.Stderr, "Detecting wildcard DNS responses for %s...\n", targetDomain)
	
	// Generate random subdomain names to test for wildcards
	testSubdomains := w.generateTestSubdomains(targetDomain, 5)
	
	var wildcardIPs []string
	wildcardCount := 0
	
	for _, testDomain := range testSubdomains {
		ips, err := w.resolveDomain(ctx, testDomain)
		if err != nil {
			continue // No resolution, not a wildcard
		}
		
		if len(ips) > 0 {
			wildcardCount++
			for _, ip := range ips {
				if !w.containsIP(wildcardIPs, ip) {
					wildcardIPs = append(wildcardIPs, ip)
				}
			}
		}
	}
	
	// If most test domains resolve, it's likely a wildcard
	if wildcardCount >= 3 {
		w.wildcardIPs[targetDomain] = wildcardIPs
		fmt.Printf("Wildcard DNS detected for %s: %d IPs (%v)\n", 
			targetDomain, len(wildcardIPs), wildcardIPs)
	} else {
		fmt.Fprintf(os.Stderr, "No wildcard DNS detected for %s\n", targetDomain)
	}
	
	return nil
}

func (w *Detector) FilterWildcardResults(results []enumeration.DomainResult, targetDomain string) []enumeration.DomainResult {
	wildcardIPs, hasWildcard := w.wildcardIPs[targetDomain]
	if !hasWildcard {
		return results // No wildcard filtering needed
	}
	
	fmt.Printf("Filtering %d results against wildcard IPs...\n", len(results))
	
	var filteredResults []enumeration.DomainResult
	filteredCount := 0
	
	for _, result := range results {
		if result.Status != "resolved" || result.DNSRecords == nil {
			// Keep non-resolved entries
			filteredResults = append(filteredResults, result)
			continue
		}
		
		// Check if this result's IP matches wildcard IPs
		isWildcard := false
		if ip, exists := result.DNSRecords["A"]; exists {
			if w.containsIP(wildcardIPs, ip) {
				isWildcard = true
			}
		}
		
		// Also check A_ALL for multiple IPs
		if allIPs, exists := result.DNSRecords["A_ALL"]; exists && !isWildcard {
			ips := strings.Split(allIPs, ",")
			for _, ip := range ips {
				ip = strings.TrimSpace(ip)
				if w.containsIP(wildcardIPs, ip) {
					isWildcard = true
					break
				}
			}
		}
		
		if isWildcard {
			// Mark as wildcard but keep in results with modified status
			result.Status = "wildcard"
			filteredResults = append(filteredResults, result)
			filteredCount++
		} else {
			// Keep legitimate results
			filteredResults = append(filteredResults, result)
		}
	}
	
	fmt.Printf("Marked %d domains as wildcard responses\n", filteredCount)
	return filteredResults
}

func (w *Detector) generateTestSubdomains(targetDomain string, count int) []string {
	var testDomains []string
	
	// Use random strings that are very unlikely to exist
	randomStrings := []string{
		"thisisaveryrandomsubdomainthatdoesnotexist",
		"wildcardtest12345",
		"nonexistentsubdomain999",
		"randomtestdomain123456789",
		"shouldnotresolve987654321",
	}
	
	// Add timestamp-based random strings
	now := time.Now().Unix()
	for i := 0; i < count && i < len(randomStrings); i++ {
		testDomain := fmt.Sprintf("%s%d.%s", randomStrings[i], now+int64(i), targetDomain)
		testDomains = append(testDomains, testDomain)
	}
	
	// Add some truly random strings
	charset := "abcdefghijklmnopqrstuvwxyz0123456789"
	for len(testDomains) < count {
		var randomStr strings.Builder
		for i := 0; i < 20; i++ {
			randomStr.WriteByte(charset[rand.Intn(len(charset))])
		}
		testDomain := fmt.Sprintf("%s.%s", randomStr.String(), targetDomain)
		testDomains = append(testDomains, testDomain)
	}
	
	return testDomains
}

func (w *Detector) resolveDomain(ctx context.Context, domain string) ([]string, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	
	ips, err := w.resolver.LookupIPAddr(timeoutCtx, domain)
	if err != nil {
		return nil, err
	}
	
	var ipStrings []string
	for _, ip := range ips {
		ipStrings = append(ipStrings, ip.IP.String())
	}
	
	return ipStrings, nil
}

func (w *Detector) containsIP(ipList []string, targetIP string) bool {
	for _, ip := range ipList {
		if ip == targetIP {
			return true
		}
	}
	return false
}

func (w *Detector) IsWildcardDomain(targetDomain string) bool {
	_, exists := w.wildcardIPs[targetDomain]
	return exists
}

func (w *Detector) GetWildcardIPs(targetDomain string) []string {
	if ips, exists := w.wildcardIPs[targetDomain]; exists {
		return ips
	}
	return nil
}