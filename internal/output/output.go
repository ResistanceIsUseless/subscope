package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/resistanceisuseless/subscope/internal/config"
	"github.com/resistanceisuseless/subscope/internal/enumeration"
)

type EnumerationResult struct {
	Metadata          Metadata                   `json:"metadata"`
	Statistics        Statistics                 `json:"statistics"`
	ResolvedDomains   []enumeration.DomainResult `json:"resolved_domains"`
	DiscoveredDomains []enumeration.DomainResult `json:"discovered_domains,omitempty"`
	FailedGenerated   []enumeration.DomainResult `json:"failed_generated,omitempty"`
}

type Metadata struct {
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Tool      ToolInfo  `json:"tool"`
	Target    string    `json:"target"`
	ScanType  string    `json:"scan_type"`
}

type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Statistics struct {
	DomainsResolved    int           `json:"domains_resolved"`
	DomainsDiscovered  int           `json:"domains_discovered"`
	DomainsGenerated   int           `json:"domains_generated_failed"`
	ExecutionTime      time.Duration `json:"execution_time"`
	Sources            []string      `json:"sources"`
}

type Writer struct {
	config *config.Config
}

func New(config *config.Config) *Writer {
	return &Writer{
		config: config,
	}
}

func (w *Writer) WriteResults(results []enumeration.DomainResult) error {
	startTime := time.Now()
	
	// Filter results based on verbose mode
	filteredResults := results
	if !w.config.Verbose {
		// In non-verbose mode, exclude failed AlterX resolutions
		var filtered []enumeration.DomainResult
		for _, result := range results {
			// Include all non-alterx results, or resolved alterx results
			if result.Source != "alterx" || result.Status != "failed" {
				filtered = append(filtered, result)
			}
		}
		filteredResults = filtered
	}
	
	// Separate domains into three categories
	var resolvedDomains []enumeration.DomainResult     // Successfully resolved domains
	var discoveredDomains []enumeration.DomainResult   // Real domains found but not resolved/failed
	var failedGenerated []enumeration.DomainResult     // AlterX generated domains that failed
	
	for _, result := range filteredResults {
		if result.Status == "resolved" || result.Status == "new_resolved" {
			// Ensure resolved domains have all required DNS records
			if result.DNSRecords == nil {
				result.DNSRecords = make(map[string]string)
			}
			// Always include IP address for resolved domains (should already be there)
			resolvedDomains = append(resolvedDomains, result)
		} else if result.Source == "alterx" && (result.Status == "failed" || result.Status == "no_records") {
			// AlterX generated domains that failed to resolve - these are likely non-existent
			failedGenerated = append(failedGenerated, result)
		} else {
			// Real domains found through enumeration but failed to resolve or are wildcards
			// These could be legitimate domains that are temporarily down or have no A records
			discoveredDomains = append(discoveredDomains, result)
		}
	}
	
	// Create comprehensive result structure
	enumerationResult := EnumerationResult{
		Metadata: Metadata{
			Version:   "1.0",
			Timestamp: time.Now(),
			Tool: ToolInfo{
				Name:    "SubScope",
				Version: "0.1.0",
			},
			Target:   w.config.Target.Domain,
			ScanType: "passive+zone_transfer+httpx+rdns+geodns+resolution",
		},
		Statistics: Statistics{
			DomainsResolved:   len(resolvedDomains),
			DomainsDiscovered: len(discoveredDomains),
			DomainsGenerated:  len(failedGenerated),
			ExecutionTime:     time.Since(startTime),
			Sources:           []string{"subfinder", "zone_transfer", "alterx", "httpx", "rdns", "rdns_range", "geodns", "dns_resolution"},
		},
		ResolvedDomains:   resolvedDomains,
		DiscoveredDomains: discoveredDomains,
		FailedGenerated:   failedGenerated,
	}
	
	switch w.config.Output.Format {
	case "json":
		return w.writeJSON(enumerationResult)
	case "csv":
		return w.writeCSV(enumerationResult)
	case "massdns":
		return w.writeMassDNS(enumerationResult)
	case "dnsx":
		return w.writeDNSx(enumerationResult)
	case "aquatone":
		return w.writeAquatone(enumerationResult)
	case "eyewitness":
		return w.writeEyeWitness(enumerationResult)
	default:
		return fmt.Errorf("unsupported output format: %s", w.config.Output.Format)
	}
}

func (w *Writer) writeJSON(result EnumerationResult) error {
	file, err := os.Create(w.config.Output.File)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()
	
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}
	
	fmt.Fprintf(os.Stderr, "Results written to: %s\n", w.config.Output.File)
	return nil
}

func (w *Writer) writeCSV(result EnumerationResult) error {
	file, err := os.Create(w.config.Output.File)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{"Domain", "Status", "IP_Address", "DNS_Records", "Source", "Timestamp"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write data rows - prioritize resolved domains, then real discovered domains
	// Exclude failed generated domains from CSV output
	allDomains := append(result.ResolvedDomains, result.DiscoveredDomains...)
	for _, domain := range allDomains {
		var ipAddress, dnsRecords string
		
		if domain.DNSRecords != nil {
			if ip, exists := domain.DNSRecords["A"]; exists {
				ipAddress = ip
			}
			
			// Convert DNS records map to string
			var recordParts []string
			for recordType, value := range domain.DNSRecords {
				recordParts = append(recordParts, fmt.Sprintf("%s:%s", recordType, value))
			}
			dnsRecords = strings.Join(recordParts, ";")
		}

		row := []string{
			domain.Domain,
			domain.Status,
			ipAddress,
			dnsRecords,
			domain.Source,
			domain.Timestamp.Format(time.RFC3339),
		}

		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	fmt.Fprintf(os.Stderr, "CSV results written to: %s\n", w.config.Output.File)
	return nil
}

func (w *Writer) writeMassDNS(result EnumerationResult) error {
	file, err := os.Create(w.config.Output.File)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Write domains with trailing dot for massdns compatibility
	// Prioritize resolved domains, then add real discovered domains (exclude failed generated)
	allDomains := append(result.ResolvedDomains, result.DiscoveredDomains...)
	count := 0
	for _, domain := range allDomains {
		// Only include resolved or discovered domains
		if domain.Status == "resolved" || domain.Status == "discovered" || domain.Status == "new_resolved" {
			_, err := fmt.Fprintf(file, "%s.\n", domain.Domain)
			if err != nil {
				return fmt.Errorf("failed to write massdns entry: %w", err)
			}
			count++
		}
	}

	fmt.Fprintf(os.Stderr, "MassDNS format written to: %s (%d domains)\n", 
		w.config.Output.File, count)
	return nil
}

func (w *Writer) writeDNSx(result EnumerationResult) error {
	file, err := os.Create(w.config.Output.File)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Write domains in simple list format for dnsx compatibility
	// Prioritize resolved domains, then add real discovered domains (exclude failed generated)
	allDomains := append(result.ResolvedDomains, result.DiscoveredDomains...)
	count := 0
	for _, domain := range allDomains {
		// Only include domains that are likely to resolve
		if domain.Status == "resolved" || domain.Status == "discovered" || domain.Status == "new_resolved" {
			_, err := fmt.Fprintf(file, "%s\n", domain.Domain)
			if err != nil {
				return fmt.Errorf("failed to write dnsx entry: %w", err)
			}
			count++
		}
	}

	fmt.Fprintf(os.Stderr, "DNSx format written to: %s (%d domains)\n", 
		w.config.Output.File, count)
	return nil
}

func (w *Writer) writeAquatone(result EnumerationResult) error {
	file, err := os.Create(w.config.Output.File)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Aquatone expects: domain,ip,port format
	count := 0
	for _, domain := range result.ResolvedDomains {
		if domain.DNSRecords != nil {
			if ip, exists := domain.DNSRecords["A"]; exists {
				// Add common HTTP/HTTPS ports
				_, err1 := fmt.Fprintf(file, "%s,%s,80\n", domain.Domain, ip)
				_, err2 := fmt.Fprintf(file, "%s,%s,443\n", domain.Domain, ip)
				if err1 != nil || err2 != nil {
					return fmt.Errorf("failed to write aquatone entry: %v", err1)
				}
				count += 2
			}
		}
	}

	fmt.Fprintf(os.Stderr, "Aquatone format written to: %s (%d entries)\n", 
		w.config.Output.File, count)
	return nil
}

func (w *Writer) writeEyeWitness(result EnumerationResult) error {
	file, err := os.Create(w.config.Output.File)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// EyeWitness expects simple URL list
	count := 0
	for _, domain := range result.ResolvedDomains {
		// Add both HTTP and HTTPS URLs
		_, err1 := fmt.Fprintf(file, "http://%s\n", domain.Domain)
		_, err2 := fmt.Fprintf(file, "https://%s\n", domain.Domain)
		if err1 != nil || err2 != nil {
			return fmt.Errorf("failed to write eyewitness entry: %v", err1)
		}
		count += 2
	}

	fmt.Fprintf(os.Stderr, "EyeWitness format written to: %s (%d URLs)\n", 
		w.config.Output.File, count)
	return nil
}