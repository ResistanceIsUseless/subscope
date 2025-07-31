package dns

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/resistanceisuseless/subscope/internal/config"
	"github.com/resistanceisuseless/subscope/internal/enumeration"
)

type Resolver struct {
	config     *config.Config
	resolvers  []*net.Resolver
	workers    int
	timeout    time.Duration
	rateLimiter chan struct{}
}

func New(config *config.Config) *Resolver {
	// Set default rate limit if not specified
	rateLimit := config.RateLimit.Global
	if rateLimit <= 0 {
		rateLimit = 50 // Default 50 requests per second
	}
	
	// Create rate limiter channel
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
	
	// Create multiple resolvers with different DNS servers for improved speed
	dnsServers := []string{
		"8.8.8.8:53",     // Google
		"8.8.4.4:53",     // Google
		"1.1.1.1:53",     // Cloudflare
		"1.0.0.1:53",     // Cloudflare
		"208.67.222.222:53", // OpenDNS
		"208.67.220.220:53", // OpenDNS
	}
	
	var resolvers []*net.Resolver
	for _, server := range dnsServers {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Millisecond * 200,
				}
				return d.DialContext(ctx, network, server)
			},
		}
		resolvers = append(resolvers, resolver)
	}
	
	return &Resolver{
		config:      config,
		resolvers:   resolvers,
		workers:     20, // Default worker count
		timeout:     5 * time.Second,
		rateLimiter: rateLimiter,
	}
}

func (r *Resolver) ResolveDomains(ctx context.Context, results []enumeration.DomainResult) []enumeration.DomainResult {
	fmt.Fprintf(os.Stderr, "Starting DNS resolution for %d domains (rate limit: %d/sec, %d DNS servers)...\n", 
		len(results), r.config.RateLimit.Global, len(r.resolvers))
		
	jobs := make(chan enumeration.DomainResult, len(results))
	resolved := make(chan enumeration.DomainResult, len(results))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < r.workers; i++ {
		wg.Add(1)
		go r.worker(ctx, jobs, resolved, &wg, i)
	}

	// Shuffle results for better load distribution across DNS servers
	shuffledResults := make([]enumeration.DomainResult, len(results))
	copy(shuffledResults, results)
	rand.Shuffle(len(shuffledResults), func(i, j int) {
		shuffledResults[i], shuffledResults[j] = shuffledResults[j], shuffledResults[i]
	})

	// Send jobs
	go func() {
		defer close(jobs)
		for _, result := range shuffledResults {
			jobs <- result
		}
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resolved)
	}()

	var resolvedResults []enumeration.DomainResult
	resolvedCount := 0
	for result := range resolved {
		resolvedResults = append(resolvedResults, result)
		if result.Status == "resolved" {
			resolvedCount++
		}
		
		// Progress indicator (verbose: every 100, non-verbose: every 1000)
		progressInterval := 1000
		if r.config.Verbose {
			progressInterval = 100
		}
		if len(resolvedResults)%progressInterval == 0 && len(resolvedResults) > 0 {
			fmt.Fprintf(os.Stderr, "Processed %d/%d domains (%d resolved)\n", 
				len(resolvedResults), len(results), resolvedCount)
		}
	}
	
	if r.config.Verbose {
		fmt.Fprintf(os.Stderr, "DNS resolution completed: %d/%d domains resolved\n", 
			resolvedCount, len(results))
	} else {
		// Only show resolved count in non-verbose mode
		fmt.Fprintf(os.Stderr, "DNS resolution completed: %d domains resolved\n", resolvedCount)
	}

	return resolvedResults
}

func (r *Resolver) worker(ctx context.Context, jobs <-chan enumeration.DomainResult, results chan<- enumeration.DomainResult, wg *sync.WaitGroup, workerID int) {
	defer wg.Done()

	// Each worker uses a different DNS server to distribute load
	resolverIndex := workerID % len(r.resolvers)

	for result := range jobs {
		resolvedResult := r.resolveDomain(ctx, result, resolverIndex)
		results <- resolvedResult
	}
}

func (r *Resolver) resolveDomain(ctx context.Context, result enumeration.DomainResult, resolverIndex int) enumeration.DomainResult {
	// Rate limiting - wait for permission to make request
	select {
	case <-r.rateLimiter:
		// Got permission, proceed
	case <-ctx.Done():
		result.Status = "cancelled"
		return result
	}
	
	// Add jitter if enabled
	if r.config.RateLimit.Jitter {
		jitterMs := rand.Intn(50) // 0-50ms jitter (reduced for speed)
		time.Sleep(time.Duration(jitterMs) * time.Millisecond)
	}
	
	// Check if this domain should use rotation detection (for domains with known load balancing)
	if r.shouldUseRotationDetection(result.Domain) {
		return r.resolveWithRotationDetection(ctx, result.Domain, resolverIndex)
	}
	
	timeoutCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Initialize DNS records map if nil
	if result.DNSRecords == nil {
		result.DNSRecords = make(map[string]string)
	}

	// Use the assigned resolver for this worker
	resolver := r.resolvers[resolverIndex]

	// Resolve A records
	ips, err := resolver.LookupIPAddr(timeoutCtx, result.Domain)
	if err != nil {
		// Check if it's a timeout or network error, try fallback if available
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "no such host") {
			// Try with a different resolver if available
			if len(r.resolvers) > 1 {
				fallbackIndex := (resolverIndex + 1) % len(r.resolvers)
				ips, err = r.resolvers[fallbackIndex].LookupIPAddr(timeoutCtx, result.Domain)
			}
		}
		if err != nil {
			result.Status = "failed"
			return result
		}
	}

	if len(ips) > 0 {
		result.Status = "resolved"
		// Store first IP address as primary
		result.DNSRecords["A"] = ips[0].IP.String()
		
		// Store all IPs
		var allIPs []string
		var cloudRegions []string
		for _, ip := range ips {
			ipStr := ip.IP.String()
			allIPs = append(allIPs, ipStr)
			
			// Detect cloud region for each IP
			if region := r.detectCloudRegion(ipStr); region != "" {
				cloudRegions = append(cloudRegions, region)
			}
		}
		if len(allIPs) > 1 {
			result.DNSRecords["A_ALL"] = strings.Join(allIPs, ",")
		}
		
		// Add cloud region information if detected
		if len(cloudRegions) > 0 {
			// Remove duplicates
			regionSet := make(map[string]bool)
			var uniqueRegions []string
			for _, region := range cloudRegions {
				if !regionSet[region] {
					regionSet[region] = true
					uniqueRegions = append(uniqueRegions, region)
				}
			}
			result.DNSRecords["CLOUD_REGIONS"] = strings.Join(uniqueRegions, ",")
		}
		
		// Collect additional DNS records (CNAME, SOA) using miekg/dns
		r.collectAdditionalRecords(timeoutCtx, result.Domain, &result)
	} else {
		result.Status = "no_records"
	}

	return result
}

// resolveWithRotationDetection performs multiple DNS queries to detect round-robin patterns
func (r *Resolver) resolveWithRotationDetection(ctx context.Context, domain string, resolverIndex int) enumeration.DomainResult {
	result := enumeration.DomainResult{
		Domain:     domain,
		Status:     "discovered",
		Source:     "dns_resolution_lb", // Mark as load balancing detection
		Timestamp:  time.Now(),
		DNSRecords: make(map[string]string),
	}
	
	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	
	resolver := r.resolvers[resolverIndex]
	allUniqueIPs := make(map[string]bool)
	var allIPSets [][]string
	
	// Perform multiple queries to detect rotation
	for i := 0; i < 5; i++ {
		ips, err := resolver.LookupIPAddr(timeoutCtx, domain)
		if err != nil {
			if i == 0 {
				// If first query fails, return failed result
				result.Status = "failed"
				return result
			}
			// Continue with other queries even if one fails
			continue
		}
		
		if len(ips) > 0 {
			var currentSet []string
			for _, ip := range ips {
				ipStr := ip.IP.String()
				currentSet = append(currentSet, ipStr)
				allUniqueIPs[ipStr] = true
			}
			allIPSets = append(allIPSets, currentSet)
		}
		
		// Small delay between queries
		time.Sleep(100 * time.Millisecond)
	}
	
	if len(allUniqueIPs) > 0 {
		result.Status = "resolved"
		
		// Store all unique IPs found across queries
		var uniqueIPs []string
		var cloudRegions []string
		for ip := range allUniqueIPs {
			uniqueIPs = append(uniqueIPs, ip)
			
			// Detect cloud region for each IP
			if region := r.detectCloudRegion(ip); region != "" {
				cloudRegions = append(cloudRegions, region)
			}
		}
		
		// Use first IP as primary
		result.DNSRecords["A"] = uniqueIPs[0]
		
		// Store all IPs
		if len(uniqueIPs) > 1 {
			result.DNSRecords["A_ALL"] = strings.Join(uniqueIPs, ",")
		}
		
		// Add cloud region information if detected
		if len(cloudRegions) > 0 {
			// Remove duplicates
			regionSet := make(map[string]bool)
			var uniqueRegions []string
			for _, region := range cloudRegions {
				if !regionSet[region] {
					regionSet[region] = true
					uniqueRegions = append(uniqueRegions, region)
				}
			}
			result.DNSRecords["CLOUD_REGIONS"] = strings.Join(uniqueRegions, ",")
		}
		
		// Detect rotation patterns
		if len(allIPSets) > 1 {
			hasRotation := false
			for i := 1; i < len(allIPSets); i++ {
				if !equalStringSlices(allIPSets[0], allIPSets[i]) {
					hasRotation = true
					break
				}
			}
			
			if hasRotation {
				result.DNSRecords["LOAD_BALANCING"] = "round-robin"
				result.DNSRecords["UNIQUE_IPS"] = fmt.Sprintf("%d", len(allUniqueIPs))
				result.DNSRecords["ROTATION_DETECTED"] = "true"
			}
		}
		
		// Collect additional DNS records
		r.collectAdditionalRecords(timeoutCtx, domain, &result)
	} else {
		result.Status = "no_records"
	}
	
	return result
}

// equalStringSlices checks if two string slices contain the same elements in the same order
func equalStringSlices(a, b []string) bool {
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

// ResolveWithRotationDetection performs DNS resolution with load balancing detection
func (r *Resolver) ResolveWithRotationDetection(ctx context.Context, domain string) enumeration.DomainResult {
	// Use the first resolver for rotation detection
	return r.resolveWithRotationDetection(ctx, domain, 0)
}

// shouldUseRotationDetection determines if a domain should use rotation detection
func (r *Resolver) shouldUseRotationDetection(domain string) bool {
	// Use rotation detection for common load-balanced services and main target domains
	loadBalancedPatterns := []string{
		"google.com", "googleapis.com", "youtube.com", "googlevideo.com",
		"facebook.com", "fbcdn.net", "instagram.com",
		"amazon.com", "amazonaws.com", "aws.com",
		"microsoft.com", "azure.com", "office.com",
		"cloudflare.com", "cloudflaressl.com",
		"akamai.com", "edgesuite.net", "akamaitechnologies.com",
		"fastly.com", "fastlylb.net",
		"twitter.com", "twimg.com",
		"netflix.com", "nflximg.net", "nflxvideo.net",
		"cdn.jsdelivr.net", "unpkg.com",
	}
	
	domainLower := strings.ToLower(domain)
	
	// Check if domain matches known load-balanced services
	for _, pattern := range loadBalancedPatterns {
		if strings.Contains(domainLower, pattern) {
			return true
		}
	}
	
	// Also use rotation detection for apex domains (main targets)
	parts := strings.Split(domain, ".")
	if len(parts) == 2 {
		return true // Apex domain
	}
	
	return false
}

// collectAdditionalRecords collects CNAME and SOA records using miekg/dns
func (r *Resolver) collectAdditionalRecords(ctx context.Context, domain string, result *enumeration.DomainResult) {
	// Create DNS client for additional record queries
	client := &dns.Client{
		Timeout: 5 * time.Second,
	}
	
	// Try multiple DNS servers for reliability
	dnsServers := []string{"8.8.8.8:53", "1.1.1.1:53", "208.67.222.222:53"}
	
	// Collect CNAME records
	r.collectCNAME(client, dnsServers, domain, result)
	
	// Collect TXT records
	r.collectTXT(client, dnsServers, domain, result)
	
	// Collect SOA records for the domain's zone
	r.collectSOA(client, dnsServers, domain, result)
}

// collectCNAME attempts to collect CNAME records
func (r *Resolver) collectCNAME(client *dns.Client, servers []string, domain string, result *enumeration.DomainResult) {
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeCNAME)
	
	for _, server := range servers {
		resp, _, err := client.Exchange(msg, server)
		if err != nil {
			continue
		}
		
		if resp.Rcode == dns.RcodeSuccess {
			for _, ans := range resp.Answer {
				if cname, ok := ans.(*dns.CNAME); ok {
					cnameTarget := strings.TrimSuffix(cname.Target, ".")
					result.DNSRecords["CNAME"] = cnameTarget
					
					// Detect cloud services from CNAME
					if cloudService := r.detectCloudService(cnameTarget); cloudService != "" {
						result.DNSRecords["CLOUD_SERVICE"] = cloudService
					}
					return // Found CNAME, no need to try other servers
				}
			}
		}
	}
}

// collectTXT attempts to collect TXT records
func (r *Resolver) collectTXT(client *dns.Client, servers []string, domain string, result *enumeration.DomainResult) {
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
	
	for _, server := range servers {
		resp, _, err := client.Exchange(msg, server)
		if err != nil {
			continue
		}
		
		if resp.Rcode == dns.RcodeSuccess {
			var txtRecords []string
			for _, ans := range resp.Answer {
				if txt, ok := ans.(*dns.TXT); ok {
					// Join all TXT strings (as a single TXT record can have multiple strings)
					txtRecord := strings.Join(txt.Txt, "")
					txtRecords = append(txtRecords, txtRecord)
				}
			}
			if len(txtRecords) > 0 {
				// Join multiple TXT records with semicolon separator
				result.DNSRecords["TXT"] = strings.Join(txtRecords, "; ")
				return // Found TXT records, no need to try other servers
			}
		}
	}
}

// collectSOA attempts to collect SOA records for the domain's zone
func (r *Resolver) collectSOA(client *dns.Client, servers []string, domain string, result *enumeration.DomainResult) {
	// Try SOA for the domain itself and its parent zones
	domains := []string{domain}
	
	// Add parent domains (up to 3 levels)
	parts := strings.Split(domain, ".")
	if len(parts) > 2 {
		for i := 1; i < len(parts) && i < 3; i++ {
			parentDomain := strings.Join(parts[i:], ".")
			domains = append(domains, parentDomain)
		}
	}
	
	for _, testDomain := range domains {
		msg := &dns.Msg{}
		msg.SetQuestion(dns.Fqdn(testDomain), dns.TypeSOA)
		
		for _, server := range servers {
			resp, _, err := client.Exchange(msg, server)
			if err != nil {
				continue
			}
			
			if resp.Rcode == dns.RcodeSuccess {
				for _, ans := range resp.Answer {
					if soa, ok := ans.(*dns.SOA); ok {
						soaRecord := fmt.Sprintf("%s %s %d %d %d %d %d",
							strings.TrimSuffix(soa.Ns, "."),
							strings.TrimSuffix(soa.Mbox, "."),
							soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minttl)
						result.DNSRecords["SOA"] = soaRecord
						
						// Detect cloud DNS providers from SOA nameserver
						if cloudDNS := r.detectCloudDNS(soa.Ns); cloudDNS != "" {
							result.DNSRecords["CLOUD_DNS"] = cloudDNS
						}
						return // Found SOA, no need to continue
					}
				}
			}
		}
	}
}

// detectCloudService identifies cloud services from CNAME targets
func (r *Resolver) detectCloudService(cname string) string {
	cnameLower := strings.ToLower(cname)
	
	// AWS Services
	if strings.Contains(cnameLower, "cloudfront.net") {
		return "AWS-CloudFront"
	}
	if strings.Contains(cnameLower, "amazonaws.com") {
		return "AWS-General"
	}
	if strings.Contains(cnameLower, "awsglobalaccelerator.com") {
		return "AWS-GlobalAccelerator"
	}
	if strings.Contains(cnameLower, "elb.amazonaws.com") {
		return "AWS-ELB"
	}
	if strings.Contains(cnameLower, "s3.amazonaws.com") || strings.Contains(cnameLower, "s3-website") {
		return "AWS-S3"
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
	if strings.Contains(cnameLower, "azure.com") {
		return "Azure-General"
	}
	if strings.Contains(cnameLower, "trafficmanager.net") {
		return "Azure-TrafficManager"
	}
	
	// Google Cloud Services
	if strings.Contains(cnameLower, "googleusercontent.com") {
		return "GCP-Storage"
	}
	if strings.Contains(cnameLower, "appspot.com") {
		return "GCP-AppEngine"
	}
	if strings.Contains(cnameLower, "run.app") {
		return "GCP-CloudRun"
	}
	if strings.Contains(cnameLower, "cloudfunctions.net") {
		return "GCP-CloudFunctions"
	}
	
	// Cloudflare
	if strings.Contains(cnameLower, "cloudflaressl.com") || strings.Contains(cnameLower, "cloudflare.net") {
		return "Cloudflare"
	}
	
	// Fastly
	if strings.Contains(cnameLower, "fastly.com") || strings.Contains(cnameLower, "fastlylb.net") {
		return "Fastly-CDN"
	}
	
	// Akamai
	if strings.Contains(cnameLower, "akamai") || strings.Contains(cnameLower, "edgesuite.net") {
		return "Akamai-CDN"
	}
	
	// GitHub Pages
	if strings.Contains(cnameLower, "github.io") || strings.Contains(cnameLower, "githubapp.com") {
		return "GitHub-Pages"
	}
	
	// Netlify
	if strings.Contains(cnameLower, "netlify.com") || strings.Contains(cnameLower, "netlify.app") {
		return "Netlify"
	}
	
	// Vercel
	if strings.Contains(cnameLower, "vercel.app") || strings.Contains(cnameLower, "vercel.com") {
		return "Vercel"
	}
	
	return ""
}

// detectCloudDNS identifies cloud DNS providers from SOA nameservers
func (r *Resolver) detectCloudDNS(ns string) string {
	nsLower := strings.ToLower(ns)
	
	// AWS Route53
	if strings.Contains(nsLower, "awsdns") {
		return "AWS-Route53"
	}
	
	// Azure DNS
	if strings.Contains(nsLower, "azure-dns") {
		return "Azure-DNS"
	}
	
	// Google Cloud DNS
	if strings.Contains(nsLower, "googledomains.com") || strings.Contains(nsLower, "google.com") {
		return "GCP-DNS"
	}
	
	// Cloudflare DNS
	if strings.Contains(nsLower, "cloudflare.com") {
		return "Cloudflare-DNS"
	}
	
	// Other popular DNS services
	if strings.Contains(nsLower, "dnsimple.com") {
		return "DNSimple"
	}
	if strings.Contains(nsLower, "dnsmadeeasy.com") {
		return "DNS-Made-Easy"
	}
	if strings.Contains(nsLower, "nsone.net") {
		return "NS1"
	}
	
	return ""
}

// detectCloudRegion identifies cloud provider regions from IP addresses
func (r *Resolver) detectCloudRegion(ipAddr string) string {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return ""
	}
	
	// AWS IP ranges (common ones)
	awsRanges := []struct {
		cidr   string
		region string
	}{
		{"52.0.0.0/8", "AWS-Global"},
		{"54.0.0.0/8", "AWS-Global"},
		{"18.0.0.0/8", "AWS-Global"},
		// US East (N. Virginia)
		{"3.80.0.0/12", "AWS-us-east-1"},
		{"52.0.0.0/11", "AWS-us-east-1"}, 
		// US West (Oregon)
		{"54.186.0.0/15", "AWS-us-west-2"},
		{"52.24.0.0/14", "AWS-us-west-2"},
		// Europe (Ireland)
		{"54.72.0.0/13", "AWS-eu-west-1"},
		{"52.48.0.0/12", "AWS-eu-west-1"},
		// Asia Pacific (Tokyo)
		{"54.92.0.0/12", "AWS-ap-northeast-1"},
		{"52.68.0.0/14", "AWS-ap-northeast-1"},
	}
	
	// Google Cloud IP ranges
	gcpRanges := []struct {
		cidr   string
		region string
	}{
		{"35.0.0.0/8", "GCP-Global"},
		{"34.0.0.0/8", "GCP-Global"},
		{"104.196.0.0/14", "GCP-us-central1"},
		{"104.154.0.0/15", "GCP-us-central1"},
		{"35.184.0.0/13", "GCP-us-central1"},
		{"35.194.0.0/16", "GCP-us-east1"},
		{"35.185.0.0/16", "GCP-us-west1"},
		{"35.197.0.0/16", "GCP-europe-west1"},
		{"35.195.0.0/16", "GCP-asia-southeast1"},
	}
	
	// Azure IP ranges
	azureRanges := []struct {
		cidr   string
		region string
	}{
		{"13.0.0.0/8", "Azure-Global"},
		{"40.0.0.0/8", "Azure-Global"},
		{"52.0.0.0/8", "Azure-Global"},
		{"104.0.0.0/8", "Azure-Global"},
		{"20.0.0.0/8", "Azure-Global"},
		// East US
		{"13.82.0.0/16", "Azure-eastus"},
		{"40.76.0.0/14", "Azure-eastus"},
		// West US
		{"13.91.0.0/16", "Azure-westus"},
		{"40.118.0.0/15", "Azure-westus"},
		// West Europe
		{"13.69.0.0/16", "Azure-westeurope"},
		{"40.68.0.0/14", "Azure-westeurope"},
	}
	
	// Cloudflare ranges
	cloudflareRanges := []struct {
		cidr   string
		region string
	}{
		{"104.16.0.0/12", "Cloudflare-Global"},
		{"172.64.0.0/13", "Cloudflare-Global"},
		{"108.162.192.0/18", "Cloudflare-Global"},
	}
	
	// Check against all ranges
	allRanges := [][]struct {
		cidr   string
		region string
	}{awsRanges, gcpRanges, azureRanges, cloudflareRanges}
	
	for _, ranges := range allRanges {
		for _, r := range ranges {
			_, network, err := net.ParseCIDR(r.cidr)
			if err != nil {
				continue
			}
			if network.Contains(ip) {
				return r.region
			}
		}
	}
	
	return ""
}

// AttemptZoneTransfer attempts an AXFR zone transfer for the given domain
func (r *Resolver) AttemptZoneTransfer(ctx context.Context, domain string) ([]string, error) {
	fmt.Fprintf(os.Stderr, "Attempting zone transfer (AXFR) for %s...\n", domain)
	
	// First, get the name servers for the domain
	nameServers, err := r.getNameServers(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get name servers for %s: %v", domain, err)
	}
	
	if len(nameServers) == 0 {
		fmt.Fprintf(os.Stderr, "No name servers found for %s\n", domain)
		return []string{}, nil
	}
	
	fmt.Fprintf(os.Stderr, "Found %d name servers for %s\n", len(nameServers), domain)
	
	var allDomains []string
	domainSet := make(map[string]bool)
	
	// Try zone transfer with each name server
	for _, ns := range nameServers {
		if r.config.Verbose {
			fmt.Printf("Trying zone transfer with name server: %s\n", ns)
		}
		
		domains, err := r.performAXFR(ctx, domain, ns)
		if err != nil {
			if r.config.Verbose {
				fmt.Printf("Zone transfer failed for %s: %v\n", ns, err)
			}
			continue
		}
		
		// Add unique domains
		for _, d := range domains {
			if !domainSet[d] {
				domainSet[d] = true
				allDomains = append(allDomains, d)
			}
		}
		
		// If we got results from this server, we can break (successful AXFR)
		if len(domains) > 0 {
			fmt.Printf("Zone transfer successful from %s - found %d domains\n", ns, len(domains))
			break
		}
	}
	
	if len(allDomains) == 0 {
		fmt.Fprintf(os.Stderr, "Zone transfer not allowed or no records found for %s\n", domain)
	} else {
		fmt.Printf("Zone transfer completed - found %d unique domains\n", len(allDomains))
	}
	
	return allDomains, nil
}

// getNameServers retrieves the name servers for a domain
func (r *Resolver) getNameServers(ctx context.Context, domain string) ([]string, error) {
	// Create DNS client
	client := &dns.Client{
		Timeout: 10 * time.Second,
	}
	
	// Create NS query
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	
	// Try different DNS servers until we get a response
	for _, resolverAddr := range []string{"8.8.8.8:53", "1.1.1.1:53", "208.67.222.222:53"} {
		resp, _, err := client.ExchangeContext(ctx, msg, resolverAddr)
		if err != nil {
			continue
		}
		
		if resp.Rcode != dns.RcodeSuccess {
			continue
		}
		
		var nameServers []string
		for _, ans := range resp.Answer {
			if ns, ok := ans.(*dns.NS); ok {
				nameServers = append(nameServers, strings.TrimSuffix(ns.Ns, "."))
			}
		}
		
		if len(nameServers) > 0 {
			return nameServers, nil
		}
	}
	
	return nil, fmt.Errorf("no name servers found")
}

// performAXFR performs the actual zone transfer
func (r *Resolver) performAXFR(ctx context.Context, domain, nameServer string) ([]string, error) {
	// Rate limiting
	select {
	case <-r.rateLimiter:
		// Got permission, proceed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	
	// Resolve name server to IP if needed
	nsAddr := nameServer
	if !strings.Contains(nsAddr, ":") {
		nsAddr += ":53"
	}
	
	// Resolve hostname to IP if it's not already an IP
	if net.ParseIP(strings.Split(nsAddr, ":")[0]) == nil {
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, strings.Split(nsAddr, ":")[0])
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("failed to resolve name server %s", nameServer)
		}
		nsAddr = ips[0].IP.String() + ":53"
	}
	
	// Create transfer client with timeout
	transfer := &dns.Transfer{
		TsigSecret: nil,
	}
	
	// Create AXFR message
	msg := &dns.Msg{}
	msg.SetAxfr(dns.Fqdn(domain))
	
	// Perform the transfer
	transferCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	
	// Start the transfer
	transferChan, err := transfer.In(msg, nsAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to initiate zone transfer: %v", err)
	}
	
	var domains []string
	domainSet := make(map[string]bool)
	
	// Read all transfer messages
	for envelope := range transferChan {
		if envelope.Error != nil {
			return nil, fmt.Errorf("zone transfer error: %v", envelope.Error)
		}
		
		// Extract domains from the response
		for _, rr := range envelope.RR {
			// Get the domain name from the resource record
			domain := strings.TrimSuffix(rr.Header().Name, ".")
			if domain != "" && !domainSet[domain] {
				domainSet[domain] = true
				domains = append(domains, domain)
			}
		}
		
		// Check for context cancellation
		select {
		case <-transferCtx.Done():
			return domains, transferCtx.Err()
		default:
		}
	}
	
	return domains, nil
}

