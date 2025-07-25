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
	Metadata   Metadata       `json:"metadata"`
	Statistics Statistics     `json:"statistics"`
	Results    []enumeration.DomainResult `json:"results"`
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
	DomainsFound   int           `json:"domains_found"`
	ExecutionTime  time.Duration `json:"execution_time"`
	Sources        []string      `json:"sources"`
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
			ScanType: "passive+ct+alterx+httpx+rdns+resolution",
		},
		Statistics: Statistics{
			DomainsFound:  len(filteredResults),
			ExecutionTime: time.Since(startTime),
			Sources:       []string{"subfinder", "certificate_transparency", "alterx", "httpx", "rdns", "dns_resolution"},
		},
		Results: filteredResults,
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
	
	fmt.Printf("Results written to: %s\n", w.config.Output.File)
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

	// Write data rows
	for _, domain := range result.Results {
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

	fmt.Printf("CSV results written to: %s\n", w.config.Output.File)
	return nil
}

func (w *Writer) writeMassDNS(result EnumerationResult) error {
	file, err := os.Create(w.config.Output.File)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Write domains with trailing dot for massdns compatibility
	for _, domain := range result.Results {
		// Only include resolved or discovered domains
		if domain.Status == "resolved" || domain.Status == "discovered" {
			_, err := fmt.Fprintf(file, "%s.\n", domain.Domain)
			if err != nil {
				return fmt.Errorf("failed to write massdns entry: %w", err)
			}
		}
	}

	fmt.Printf("MassDNS format written to: %s (%d domains)\n", 
		w.config.Output.File, len(result.Results))
	return nil
}

func (w *Writer) writeDNSx(result EnumerationResult) error {
	file, err := os.Create(w.config.Output.File)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Write domains in simple list format for dnsx compatibility
	for _, domain := range result.Results {
		// Only include domains that are likely to resolve
		if domain.Status == "resolved" || domain.Status == "discovered" {
			_, err := fmt.Fprintf(file, "%s\n", domain.Domain)
			if err != nil {
				return fmt.Errorf("failed to write dnsx entry: %w", err)
			}
		}
	}

	fmt.Printf("DNSx format written to: %s (%d domains)\n", 
		w.config.Output.File, len(result.Results))
	return nil
}