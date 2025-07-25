package summary

import (
	"fmt"
	"sort"
	"strings"

	"github.com/resistanceisuseless/subscope/internal/arin"
	"github.com/resistanceisuseless/subscope/internal/enumeration"
)

type Summary struct {
	TotalDomains      int
	ResolvedDomains   int
	FailedDomains     int
	Sources           map[string]int
	CloudProviders    map[string]int
	CloudServices     map[string]int  // New: DNS-based cloud service detection
	CloudDNS          map[string]int  // New: DNS provider detection
	Organizations     map[string]int
	Countries         map[string]int
	IPRanges          map[string]string
	NewDomains        int
	WildcardFiltered  int
	CloudHostingCount int             // New: Count of domains with cloud hosting
}

func Analyze(results []enumeration.DomainResult, orgData []arin.OrganizationInfo) *Summary {
	summary := &Summary{
		Sources:        make(map[string]int),
		CloudProviders: make(map[string]int),
		CloudServices:  make(map[string]int),
		CloudDNS:       make(map[string]int),
		Organizations:  make(map[string]int),
		Countries:      make(map[string]int),
		IPRanges:       make(map[string]string),
	}

	// Count domains by status and source
	for _, result := range results {
		summary.TotalDomains++
		
		// Count by status
		switch result.Status {
		case "resolved":
			summary.ResolvedDomains++
		case "failed":
			summary.FailedDomains++
		case "wildcard":
			summary.WildcardFiltered++
		case "new_resolved":
			summary.NewDomains++
			summary.ResolvedDomains++
		}
		
		// Count by source
		summary.Sources[result.Source]++
		
		// Analyze DNS records for cloud services
		if result.DNSRecords != nil {
			// Check for cloud service detection from CNAME
			if cloudService, exists := result.DNSRecords["CLOUD_SERVICE"]; exists && cloudService != "" {
				summary.CloudServices[cloudService]++
				summary.CloudHostingCount++
			}
			
			// Check for cloud DNS providers from SOA
			if cloudDNS, exists := result.DNSRecords["CLOUD_DNS"]; exists && cloudDNS != "" {
				summary.CloudDNS[cloudDNS]++
			}
		}
	}

	// Analyze organization data
	for _, org := range orgData {
		if org.Organization != "" {
			summary.Organizations[org.Organization]++
			
			// Detect cloud providers
			cloudProvider := detectCloudProvider(org.Organization)
			if cloudProvider != "" {
				summary.CloudProviders[cloudProvider]++
			}
		}
		
		if org.Country != "" {
			summary.Countries[org.Country]++
		}
		
		// Track IP ranges by organization
		if org.Organization != "" && org.Network != "" {
			summary.IPRanges[org.Network] = org.Organization
		}
	}

	return summary
}

func detectCloudProvider(organization string) string {
	org := strings.ToLower(organization)
	
	// Common cloud provider patterns
	cloudPatterns := map[string][]string{
		"Amazon Web Services (AWS)": {"amazon", "aws", "ec2", "amazoncom"},
		"Microsoft Azure": {"microsoft", "azure"},
		"Google Cloud Platform": {"google", "gcp", "google cloud"},
		"Cloudflare": {"cloudflare"},
		"DigitalOcean": {"digitalocean", "digital ocean"},
		"Linode": {"linode"},
		"OVH": {"ovh"},
		"Hetzner": {"hetzner"},
		"Alibaba Cloud": {"alibaba", "aliyun"},
		"IBM Cloud": {"ibm", "softlayer"},
		"Oracle Cloud": {"oracle"},
		"Vultr": {"vultr"},
		"Akamai": {"akamai"},
		"Fastly": {"fastly"},
	}
	
	for provider, patterns := range cloudPatterns {
		for _, pattern := range patterns {
			if strings.Contains(org, pattern) {
				return provider
			}
		}
	}
	
	return ""
}

func (s *Summary) Print() {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("                    ENUMERATION SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	
	// Domain statistics
	fmt.Printf("\n📊 Domain Statistics:\n")
	fmt.Printf("   Total Domains Found: %d\n", s.TotalDomains)
	fmt.Printf("   Successfully Resolved: %d (%.1f%%)\n", 
		s.ResolvedDomains, 
		float64(s.ResolvedDomains)/float64(s.TotalDomains)*100)
	if s.FailedDomains > 0 {
		fmt.Printf("   Failed Resolution: %d\n", s.FailedDomains)
	}
	if s.NewDomains > 0 {
		fmt.Printf("   🆕 New Domains: %d\n", s.NewDomains)
	}
	if s.WildcardFiltered > 0 {
		fmt.Printf("   Wildcard Filtered: %d\n", s.WildcardFiltered)
	}
	
	// Discovery sources
	fmt.Printf("\n🔍 Discovery Sources:\n")
	sources := sortMapByValue(s.Sources)
	for _, kv := range sources {
		fmt.Printf("   %-25s: %d domains\n", kv.Key, kv.Value)
	}
	
	// Cloud services (from DNS analysis)
	if len(s.CloudServices) > 0 {
		fmt.Printf("\n☁️  Cloud Services (via DNS):\n")
		services := sortMapByValue(s.CloudServices)
		for _, kv := range services {
			fmt.Printf("   %-25s: %d domains\n", kv.Key, kv.Value)
		}
		fmt.Printf("   Total cloud-hosted domains: %d (%.1f%%)\n", 
			s.CloudHostingCount, 
			float64(s.CloudHostingCount)/float64(s.ResolvedDomains)*100)
	}
	
	// Cloud DNS providers
	if len(s.CloudDNS) > 0 {
		fmt.Printf("\n🌐 DNS Providers:\n")
		dnsProviders := sortMapByValue(s.CloudDNS)
		for _, kv := range dnsProviders {
			fmt.Printf("   %-25s: detected\n", kv.Key)
		}
	}
	
	// Cloud providers (from IP analysis)
	if len(s.CloudProviders) > 0 {
		fmt.Printf("\n☁️  Cloud Providers (via IP):\n")
		providers := sortMapByValue(s.CloudProviders)
		for _, kv := range providers {
			fmt.Printf("   %-25s: %d IPs\n", kv.Key, kv.Value)
		}
	}
	
	// Top organizations
	if len(s.Organizations) > 0 {
		fmt.Printf("\n🏢 Top Organizations:\n")
		orgs := sortMapByValue(s.Organizations)
		limit := 10
		if len(orgs) < limit {
			limit = len(orgs)
		}
		for i := 0; i < limit; i++ {
			fmt.Printf("   %-25s: %d IPs\n", orgs[i].Key, orgs[i].Value)
		}
		if len(orgs) > limit {
			fmt.Printf("   ... and %d more organizations\n", len(orgs)-limit)
		}
	}
	
	// Countries
	if len(s.Countries) > 0 {
		fmt.Printf("\n🌍 Geographic Distribution:\n")
		countries := sortMapByValue(s.Countries)
		for _, kv := range countries {
			fmt.Printf("   %-25s: %d IPs\n", kv.Key, kv.Value)
		}
	}
	
	fmt.Println("\n" + strings.Repeat("=", 60))
}

type KeyValue struct {
	Key   string
	Value int
}

func sortMapByValue(m map[string]int) []KeyValue {
	var kvs []KeyValue
	for k, v := range m {
		kvs = append(kvs, KeyValue{k, v})
	}
	
	sort.Slice(kvs, func(i, j int) bool {
		return kvs[i].Value > kvs[j].Value
	})
	
	return kvs
}