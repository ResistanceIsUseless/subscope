package rdns

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/resistanceisuseless/subscope/internal/config"
	"github.com/resistanceisuseless/subscope/internal/enumeration"
)

type Analyzer struct {
	config      *config.Config
	resolver    *net.Resolver
	workers     int
	rateLimiter chan struct{}
}

type RDNSResult struct {
	IPAddress string
	Hostnames []string
	Source    string
}

func New(config *config.Config) *Analyzer {
	// Set up rate limiter for RDNS queries
	rateLimit := 20 // Conservative rate limit for RDNS
	if config.RateLimit.Global > 0 && config.RateLimit.Global < 50 {
		rateLimit = config.RateLimit.Global
	}
	
	rateLimiter := make(chan struct{}, rateLimit)
	
	// Start rate limiter goroutine
	go func() {
		ticker := time.NewTicker(time.Second / time.Duration(rateLimit))
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				select {
				case rateLimiter <- struct{}{}:
				default:
					// Channel full, skip this tick
				}
			}
		}
	}()
	
	return &Analyzer{
		config:      config,
		resolver:    &net.Resolver{},
		workers:     10, // Conservative worker count for RDNS
		rateLimiter: rateLimiter,
	}
}

func (r *Analyzer) AnalyzeIPs(ctx context.Context, results []enumeration.DomainResult, targetDomain string) ([]string, error) {
	fmt.Printf("Starting RDNS analysis for resolved domains...\n")
	
	// Extract unique IP addresses from resolved domains
	ipSet := make(map[string]bool)
	for _, result := range results {
		if result.Status == "resolved" && result.DNSRecords != nil {
			if ip, exists := result.DNSRecords["A"]; exists && ip != "" {
				ipSet[ip] = true
			}
			// Also check A_ALL for multiple IPs
			if allIPs, exists := result.DNSRecords["A_ALL"]; exists {
				ips := strings.Split(allIPs, ",")
				for _, ip := range ips {
					ipSet[strings.TrimSpace(ip)] = true
				}
			}
		}
	}
	
	if len(ipSet) == 0 {
		fmt.Println("No IP addresses found for RDNS analysis")
		return []string{}, nil
	}
	
	// Convert to slice
	var ips []string
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	
	fmt.Printf("Performing RDNS lookups on %d unique IP addresses...\n", len(ips))
	
	// Process IPs concurrently
	jobs := make(chan string, len(ips))
	rdnsResults := make(chan RDNSResult, len(ips))
	
	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < r.workers; i++ {
		wg.Add(1)
		go r.worker(ctx, jobs, rdnsResults, &wg)
	}
	
	// Send jobs
	go func() {
		defer close(jobs)
		for _, ip := range ips {
			jobs <- ip
		}
	}()
	
	// Collect results
	go func() {
		wg.Wait()
		close(rdnsResults)
	}()
	
	// Extract discovered domains
	var discoveredDomains []string
	domainSet := make(map[string]bool)
	totalHostnames := 0
	
	for result := range rdnsResults {
		for _, hostname := range result.Hostnames {
			totalHostnames++
			if r.isValidSubdomain(hostname, targetDomain) && !domainSet[hostname] {
				domainSet[hostname] = true
				discoveredDomains = append(discoveredDomains, hostname)
			}
		}
	}
	
	if r.config.Verbose {
		fmt.Printf("RDNS analysis found %d hostnames (%d relevant to %s)\n", 
			totalHostnames, len(discoveredDomains), targetDomain)
	} else if len(discoveredDomains) > 0 {
		fmt.Printf("RDNS analysis found %d new subdomains from reverse lookups\n", len(discoveredDomains))
	}
	
	return discoveredDomains, nil
}

func (r *Analyzer) worker(ctx context.Context, jobs <-chan string, results chan<- RDNSResult, wg *sync.WaitGroup) {
	defer wg.Done()
	
	for ip := range jobs {
		result := r.performRDNS(ctx, ip)
		if result != nil {
			results <- *result
		}
	}
}

func (r *Analyzer) performRDNS(ctx context.Context, ip string) *RDNSResult {
	// Rate limiting
	select {
	case <-r.rateLimiter:
		// Got permission, proceed
	case <-ctx.Done():
		return nil
	}
	
	// Set timeout for RDNS lookup
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	
	// Perform reverse DNS lookup
	hostnames, err := r.resolver.LookupAddr(timeoutCtx, ip)
	if err != nil {
		return nil // No hostnames found
	}
	
	// Clean up hostnames (remove trailing dots)
	var cleanHostnames []string
	for _, hostname := range hostnames {
		hostname = strings.TrimSpace(hostname)
		if strings.HasSuffix(hostname, ".") {
			hostname = hostname[:len(hostname)-1]
		}
		if hostname != "" {
			cleanHostnames = append(cleanHostnames, strings.ToLower(hostname))
		}
	}
	
	if len(cleanHostnames) == 0 {
		return nil
	}
	
	return &RDNSResult{
		IPAddress: ip,
		Hostnames: cleanHostnames,
		Source:    "rdns",
	}
}

func (r *Analyzer) isValidSubdomain(subdomain, targetDomain string) bool {
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

// ScanIPRange performs reverse DNS lookups on an IP range (CIDR notation)
func (r *Analyzer) ScanIPRange(ctx context.Context, cidr, targetDomain string) ([]string, error) {
	fmt.Printf("Starting RDNS scan of IP range %s...\n", cidr)
	
	// Parse CIDR
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR notation: %s", cidr)
	}
	
	// Generate IP addresses in the range
	ips := r.generateIPsFromCIDR(ipNet)
	
	// Limit the number of IPs to scan for performance
	maxIPs := 254 // Default /24 subnet size
	if len(ips) > maxIPs {
		fmt.Printf("IP range contains %d addresses, limiting to first %d\n", len(ips), maxIPs)
		ips = ips[:maxIPs]
	}
	
	fmt.Printf("Scanning %d IP addresses for reverse DNS records...\n", len(ips))
	
	// Process IPs concurrently
	jobs := make(chan string, len(ips))
	rdnsResults := make(chan RDNSResult, len(ips))
	
	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < r.workers; i++ {
		wg.Add(1)
		go r.worker(ctx, jobs, rdnsResults, &wg)
	}
	
	// Send jobs
	go func() {
		defer close(jobs)
		for _, ip := range ips {
			jobs <- ip
		}
	}()
	
	// Collect results
	go func() {
		wg.Wait()
		close(rdnsResults)
	}()
	
	// Extract discovered domains
	var discoveredDomains []string
	domainSet := make(map[string]bool)
	totalHostnames := 0
	
	for result := range rdnsResults {
		for _, hostname := range result.Hostnames {
			totalHostnames++
			if r.isValidSubdomain(hostname, targetDomain) && !domainSet[hostname] {
				domainSet[hostname] = true
				discoveredDomains = append(discoveredDomains, hostname)
			}
		}
	}
	
	if r.config.Verbose {
		fmt.Printf("IP range scan found %d hostnames (%d relevant to %s)\n", 
			totalHostnames, len(discoveredDomains), targetDomain)
	} else if len(discoveredDomains) > 0 {
		fmt.Printf("IP range scan found %d new subdomains\n", len(discoveredDomains))
	}
	
	return discoveredDomains, nil
}

// ScanIPRangesFromSubnets scans multiple IP ranges derived from discovered IPs
func (r *Analyzer) ScanIPRangesFromSubnets(ctx context.Context, results []enumeration.DomainResult, targetDomain string) ([]string, error) {
	fmt.Printf("Deriving IP ranges from discovered subdomains...\n")
	
	// Extract unique IP addresses and derive /24 subnets
	subnetSet := make(map[string]bool)
	for _, result := range results {
		if result.Status == "resolved" && result.DNSRecords != nil {
			if ip, exists := result.DNSRecords["A"]; exists && ip != "" {
				subnet := r.getSubnet24(ip)
				if subnet != "" {
					subnetSet[subnet] = true
				}
			}
			// Also check A_ALL for multiple IPs
			if allIPs, exists := result.DNSRecords["A_ALL"]; exists {
				ips := strings.Split(allIPs, ",")
				for _, ipStr := range ips {
					subnet := r.getSubnet24(strings.TrimSpace(ipStr))
					if subnet != "" {
						subnetSet[subnet] = true
					}
				}
			}
		}
	}
	
	if len(subnetSet) == 0 {
		fmt.Println("No IP ranges found to scan")
		return []string{}, nil
	}
	
	fmt.Printf("Found %d unique /24 subnets to scan\n", len(subnetSet))
	
	var allDomains []string
	domainSet := make(map[string]bool)
	
	// Scan each subnet
	for subnet := range subnetSet {
		domains, err := r.ScanIPRange(ctx, subnet, targetDomain)
		if err != nil {
			if r.config.Verbose {
				fmt.Printf("Failed to scan subnet %s: %v\n", subnet, err)
			}
			continue
		}
		
		// Add unique domains
		for _, domain := range domains {
			if !domainSet[domain] {
				domainSet[domain] = true
				allDomains = append(allDomains, domain)
			}
		}
	}
	
	return allDomains, nil
}

// generateIPsFromCIDR generates a list of IP addresses from a CIDR range
func (r *Analyzer) generateIPsFromCIDR(ipNet *net.IPNet) []string {
	var ips []string
	
	// Get the first IP in the network
	ip := ipNet.IP.Mask(ipNet.Mask)
	
	// Iterate through all IPs in the range
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); r.incrementIP(ip) {
		ips = append(ips, ip.String())
	}
	
	// Remove network and broadcast addresses for /24 and smaller subnets
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1] // Remove first and last
	}
	
	return ips
}

// incrementIP increments an IP address by 1
func (r *Analyzer) incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// getSubnet24 derives a /24 subnet from an IP address
func (r *Analyzer) getSubnet24(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	
	// Convert to IPv4 if possible
	if ipv4 := ip.To4(); ipv4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", ipv4[0], ipv4[1], ipv4[2])
	}
	
	return ""
}

// ScanSpecificIPs performs reverse DNS lookups on a list of specific IP addresses
func (r *Analyzer) ScanSpecificIPs(ctx context.Context, ipList []string, targetDomain string) ([]string, error) {
	if len(ipList) == 0 {
		return []string{}, nil
	}
	
	fmt.Printf("Starting RDNS scan of %d specific IP addresses...\n", len(ipList))
	
	// Process IPs concurrently
	jobs := make(chan string, len(ipList))
	rdnsResults := make(chan RDNSResult, len(ipList))
	
	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < r.workers; i++ {
		wg.Add(1)
		go r.worker(ctx, jobs, rdnsResults, &wg)
	}
	
	// Send jobs
	go func() {
		defer close(jobs)
		for _, ip := range ipList {
			if net.ParseIP(ip) != nil { // Validate IP
				jobs <- ip
			}
		}
	}()
	
	// Collect results
	go func() {
		wg.Wait()
		close(rdnsResults)
	}()
	
	// Extract discovered domains
	var discoveredDomains []string
	domainSet := make(map[string]bool)
	totalHostnames := 0
	
	for result := range rdnsResults {
		for _, hostname := range result.Hostnames {
			totalHostnames++
			if r.isValidSubdomain(hostname, targetDomain) && !domainSet[hostname] {
				domainSet[hostname] = true
				discoveredDomains = append(discoveredDomains, hostname)
			}
		}
	}
	
	fmt.Printf("Specific IP scan found %d hostnames (%d relevant to %s)\n", 
		totalHostnames, len(discoveredDomains), targetDomain)
	
	return discoveredDomains, nil
}