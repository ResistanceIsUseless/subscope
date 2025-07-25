package arin

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/resistanceisuseless/subscope/internal/config"
	"github.com/resistanceisuseless/subscope/internal/enumeration"
)

type Analyzer struct {
	config      *config.Config
	httpClient  *http.Client
	workers     int
	rateLimiter chan struct{}
}

type RDAPResponse struct {
	ObjectClassName string      `json:"objectClassName"`
	Handle          string      `json:"handle"`
	StartAddress    string      `json:"startAddress"`
	EndAddress      string      `json:"endAddress"`
	IPVersion       string      `json:"ipVersion"`
	Name            string      `json:"name"`
	Type            string      `json:"type"`
	Country         string      `json:"country"`
	ParentHandle    string      `json:"parentHandle"`
	Entities        []Entity    `json:"entities"`
	Remarks         []Remark    `json:"remarks"`
	Links           []Link      `json:"links"`
	Events          []Event     `json:"events"`
	Status          []string    `json:"status"`
}

type Entity struct {
	ObjectClassName string   `json:"objectClassName"`
	Handle          string   `json:"handle"`
	VCardArray      [][]interface{} `json:"vcardArray"`
	Roles           []string `json:"roles"`
	PublicIds       []PublicId `json:"publicIds"`
	Entities        []Entity `json:"entities"`
	Remarks         []Remark `json:"remarks"`
	Links           []Link   `json:"links"`
	Events          []Event  `json:"events"`
}

type PublicId struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

type Remark struct {
	Title       string   `json:"title"`
	Type        string   `json:"type"`
	Description []string `json:"description"`
	Links       []Link   `json:"links"`
}

type Link struct {
	Value string `json:"value"`
	Rel   string `json:"rel"`
	Href  string `json:"href"`
	Type  string `json:"type"`
}

type Event struct {
	EventAction string `json:"eventAction"`
	EventDate   string `json:"eventDate"`
}

type OrganizationInfo struct {
	IPAddress    string
	Organization string
	Country      string
	Network      string
	Handle       string
	Source       string
}

func New(config *config.Config) *Analyzer {
	// Set up rate limiter for RDAP queries (be respectful)
	rateLimit := 5 // Conservative rate limit for RDAP APIs
	
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
		config: config,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		workers:     3, // Conservative worker count for RDAP
		rateLimiter: rateLimiter,
	}
}

func (a *Analyzer) AnalyzeIPs(ctx context.Context, results []enumeration.DomainResult) ([]OrganizationInfo, error) {
	fmt.Printf("Starting RDAP organization analysis...\n")
	
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
		fmt.Println("No IP addresses found for RDAP analysis")
		return []OrganizationInfo{}, nil
	}
	
	// Convert to slice
	var ips []string
	for ip := range ipSet {
		// Skip private IP ranges
		if a.isPrivateIP(ip) {
			continue
		}
		ips = append(ips, ip)
	}
	
	if len(ips) == 0 {
		fmt.Println("No public IP addresses found for RDAP analysis")
		return []OrganizationInfo{}, nil
	}
	
	fmt.Printf("Performing RDAP lookups on %d unique public IP addresses...\n", len(ips))
	
	// Process IPs concurrently
	jobs := make(chan string, len(ips))
	orgResults := make(chan OrganizationInfo, len(ips))
	
	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < a.workers; i++ {
		wg.Add(1)
		go a.worker(ctx, jobs, orgResults, &wg)
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
		close(orgResults)
	}()
	
	var organizations []OrganizationInfo
	for org := range orgResults {
		organizations = append(organizations, org)
	}
	
	fmt.Printf("RDAP analysis found organization data for %d IP addresses\n", len(organizations))
	return organizations, nil
}

func (a *Analyzer) worker(ctx context.Context, jobs <-chan string, results chan<- OrganizationInfo, wg *sync.WaitGroup) {
	defer wg.Done()
	
	for ip := range jobs {
		if orgInfo := a.performRDAP(ctx, ip); orgInfo != nil {
			results <- *orgInfo
		}
	}
}

func (a *Analyzer) performRDAP(ctx context.Context, ip string) *OrganizationInfo {
	// Rate limiting
	select {
	case <-a.rateLimiter:
		// Got permission, proceed
	case <-ctx.Done():
		return nil
	}
	
	// RDAP endpoints for different RIRs
	rdapEndpoints := []string{
		"https://rdap.arin.net/registry/ip/",
		"https://rdap.db.ripe.net/ip/",
		"https://rdap.apnic.net/ip/",
		"https://rdap.lacnic.net/rdap/ip/",
		"https://rdap.afrinic.net/rdap/ip/",
	}
	
	for _, endpoint := range rdapEndpoints {
		if orgInfo := a.queryRDAP(ctx, endpoint, ip); orgInfo != nil {
			return orgInfo
		}
	}
	
	return nil // No data found from any RIR
}

func (a *Analyzer) queryRDAP(ctx context.Context, endpoint, ip string) *OrganizationInfo {
	url := endpoint + ip
	
	// Add stealth capabilities - random delay
	if a.config.Stealth.RequestJitter && a.config.Stealth.RandomDelay > 0 {
		delay := rand.Intn(a.config.Stealth.RandomDelay)
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	
	// Use random User-Agent from configured list
	userAgent := "SubScope/0.1.0"
	if len(a.config.Stealth.UserAgents) > 0 {
		userAgent = a.config.Stealth.UserAgents[rand.Intn(len(a.config.Stealth.UserAgents))]
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/rdap+json")
	
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil // Try next endpoint
	}
	
	var rdapResp RDAPResponse
	if err := json.NewDecoder(resp.Body).Decode(&rdapResp); err != nil {
		return nil
	}
	
	// Extract organization information
	orgInfo := &OrganizationInfo{
		IPAddress: ip,
		Network:   fmt.Sprintf("%s-%s", rdapResp.StartAddress, rdapResp.EndAddress),
		Handle:    rdapResp.Handle,
		Country:   rdapResp.Country,
		Source:    a.extractSource(endpoint),
	}
	
	// Extract organization name from entities
	for _, entity := range rdapResp.Entities {
		if a.containsRole(entity.Roles, "registrant") {
			if orgName := a.extractOrgName(entity); orgName != "" {
				orgInfo.Organization = orgName
				break
			}
		}
	}
	
	// If no registrant found, try any entity with organization info
	if orgInfo.Organization == "" {
		for _, entity := range rdapResp.Entities {
			if orgName := a.extractOrgName(entity); orgName != "" {
				orgInfo.Organization = orgName
				break
			}
		}
	}
	
	return orgInfo
}

func (a *Analyzer) extractOrgName(entity Entity) string {
	if len(entity.VCardArray) < 2 {
		return ""
	}
	
	// vCard format: ["vcard", [["fn", {}, "text", "Organization Name"], ...]]
	// entity.VCardArray[1] is already []interface{} containing the vCard fields
	vcardFields := entity.VCardArray[1]
	
	for _, field := range vcardFields {
		fieldArray, ok := field.([]interface{})
		if !ok || len(fieldArray) < 4 {
			continue
		}
		
		fieldName, ok := fieldArray[0].(string)
		if !ok {
			continue
		}
		
		if fieldName == "fn" || fieldName == "org" {
			if orgName, ok := fieldArray[3].(string); ok {
				return strings.TrimSpace(orgName)
			}
		}
	}
	
	return ""
}

func (a *Analyzer) containsRole(roles []string, targetRole string) bool {
	for _, role := range roles {
		if strings.EqualFold(role, targetRole) {
			return true
		}
	}
	return false
}

func (a *Analyzer) extractSource(endpoint string) string {
	if strings.Contains(endpoint, "arin.net") {
		return "ARIN"
	} else if strings.Contains(endpoint, "ripe.net") {
		return "RIPE"
	} else if strings.Contains(endpoint, "apnic.net") {
		return "APNIC"
	} else if strings.Contains(endpoint, "lacnic.net") {
		return "LACNIC"
	} else if strings.Contains(endpoint, "afrinic.net") {
		return "AFRINIC"
	}
	return "Unknown"
}

func (a *Analyzer) isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	
	// Check for private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	
	for _, rangeStr := range privateRanges {
		_, cidr, err := net.ParseCIDR(rangeStr)
		if err != nil {
			continue
		}
		if cidr.Contains(ip) {
			return true
		}
	}
	
	return false
}