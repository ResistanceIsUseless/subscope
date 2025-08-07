package enumeration

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"github.com/resistanceisuseless/subscope/internal/config"
)

// SubfinderLibrary implements library-based subfinder integration
type SubfinderLibrary struct {
	config *config.Config
}

// NewSubfinderLibrary creates a new library-based subfinder enumerator
func NewSubfinderLibrary(config *config.Config) *SubfinderLibrary {
	return &SubfinderLibrary{
		config: config,
	}
}

// EnumerateSubdomains performs passive subdomain enumeration using subfinder library
func (s *SubfinderLibrary) EnumerateSubdomains(ctx context.Context, domain string) ([]string, error) {
	fmt.Fprintf(os.Stderr, "Running passive enumeration (library mode) for domain: %s\n", domain)

	// Configure subfinder options
	subfinderOpts := &runner.Options{
		Threads:            10, // Default threads
		Timeout:            30, // 30 second timeout
		MaxEnumerationTime: 10, // 10 minute max enumeration time
		Resolvers:          []string{"8.8.8.8", "1.1.1.1"}, // Default resolvers
		All:                false, // Use active sources only
		Silent:             true,  // Silent mode
		RemoveWildcard:     true,  // Remove wildcard subdomains
		CaptureSources:     true,  // Capture source information
	}

	// Apply custom configuration if available
	if len(s.config.Subfinder.Providers) > 0 {
		// Convert provider list to sources configuration
		// This would need to be mapped to subfinder's source configuration
	}

	if s.config.Subfinder.Timeout > 0 {
		subfinderOpts.Timeout = s.config.Subfinder.Timeout
	}

	// Storage for discovered domains and source mapping
	var domains []string
	sourceMapping := make(map[string][]string) // domain -> sources that found it
	output := &bytes.Buffer{}

	// Set up result callback for real-time processing
	subfinderOpts.ResultCallback = func(s *resolve.HostEntry) {
		domain := strings.TrimSpace(s.Host)
		if domain != "" {
			domains = append(domains, domain)
			
			// Track sources for this domain
			if s.Source != "" {
				sourceMapping[domain] = append(sourceMapping[domain], s.Source)
			}
			
			// Write to output buffer for compatibility
			fmt.Fprintln(output, domain)
		}
	}

	// Create subfinder runner
	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create subfinder runner: %v", err)
	}

	// Run enumeration
	ctx, cancel := context.WithTimeout(ctx, time.Duration(subfinderOpts.MaxEnumerationTime)*time.Minute)
	defer cancel()

	_, err = subfinder.EnumerateSingleDomainWithCtx(ctx, domain, []io.Writer{output})
	if err != nil {
		return nil, fmt.Errorf("subfinder enumeration failed: %v", err)
	}

	// Log source information if verbose
	if s.config.Verbose && len(sourceMapping) > 0 {
		fmt.Fprintf(os.Stderr, "Source breakdown:\n")
		sourceCounts := make(map[string]int)
		for _, sources := range sourceMapping {
			for _, source := range sources {
				sourceCounts[source]++
			}
		}
		for source, count := range sourceCounts {
			fmt.Fprintf(os.Stderr, "  %s: %d domains\n", source, count)
		}
	}

	// Deduplicate domains (callback might have duplicates)
	uniqueDomains := make(map[string]bool)
	var result []string
	for _, domain := range domains {
		if !uniqueDomains[domain] {
			uniqueDomains[domain] = true
			result = append(result, domain)
		}
	}

	fmt.Fprintf(os.Stderr, "Passive enumeration (library mode) completed. Found %d domains.\n", len(result))
	return result, nil
}

// EnumerateSubdomainsLegacy performs enumeration with fallback parsing (if callback fails)
func (s *SubfinderLibrary) EnumerateSubdomainsLegacy(ctx context.Context, domain string) ([]string, error) {
	subfinderOpts := &runner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: 10,
		Resolvers:          []string{"8.8.8.8", "1.1.1.1"},
		All:                false,
		Silent:             true,
		RemoveWildcard:     true,
	}

	if s.config.Subfinder.Timeout > 0 {
		subfinderOpts.Timeout = s.config.Subfinder.Timeout
	}

	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create subfinder runner: %v", err)
	}

	// Use buffer to capture output
	output := &bytes.Buffer{}
	
	ctx, cancel := context.WithTimeout(ctx, time.Duration(subfinderOpts.MaxEnumerationTime)*time.Minute)
	defer cancel()

	_, err = subfinder.EnumerateSingleDomainWithCtx(ctx, domain, []io.Writer{output})
	if err != nil {
		return nil, fmt.Errorf("subfinder enumeration failed: %v", err)
	}

	// Parse results from buffer
	var domains []string
	scanner := bufio.NewScanner(output)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			domains = append(domains, domain)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading subfinder output: %v", err)
	}

	return domains, nil
}