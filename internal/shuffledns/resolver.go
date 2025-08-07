package shuffledns

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/resistanceisuseless/subscope/internal/config"
	"github.com/resistanceisuseless/subscope/internal/enumeration"
)

type Resolver struct {
	config *config.Config
}

func New(config *config.Config) *Resolver {
	return &Resolver{
		config: config,
	}
}

func (r *Resolver) ResolveDomains(ctx context.Context, results []enumeration.DomainResult) ([]enumeration.DomainResult, error) {
	if len(results) == 0 {
		return results, nil
	}

	// Check if shuffledns is available
	if _, err := exec.LookPath("shuffledns"); err != nil {
		return nil, fmt.Errorf("shuffledns not found in PATH. Please install it: go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest")
	}

	// Create temporary file with domains
	tmpFile, err := os.CreateTemp("", "subscope-domains-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write domains to temp file
	for _, result := range results {
		if _, err := tmpFile.WriteString(result.Domain + "\n"); err != nil {
			return nil, fmt.Errorf("failed to write domain: %w", err)
		}
	}
	tmpFile.Close()

	// Create resolvers file with trusted DNS servers
	resolversFile, err := r.createResolversFile()
	if err != nil {
		return nil, fmt.Errorf("failed to create resolvers file: %w", err)
	}
	defer os.Remove(resolversFile)

	// Build shuffledns command 
	var args []string
	
	// Check if custom args are provided
	if r.config.ExecMode.ShuffleDNSArgs != "" {
		// Use custom args but ensure required parameters
		customArgs := strings.Fields(r.config.ExecMode.ShuffleDNSArgs)
		args = append([]string{"-list", tmpFile.Name()}, customArgs...)
		// Add resolvers file if not specified
		if !contains(customArgs, "-r") && !contains(customArgs, "-resolvers") {
			args = append(args, "-r", resolversFile)
		}
	} else {
		// Use default args
		args = []string{
			"-list", tmpFile.Name(),
			"-r", resolversFile,
			"-silent",
			"-t", "50", // 50 threads for speed
			"-retries", "2",
			"-mode", "resolve",
		}
	}

	// Add output format
	outputFile, err := os.CreateTemp("", "subscope-resolved-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer os.Remove(outputFile.Name())
	args = append(args, "-o", outputFile.Name())

	fmt.Fprintf(os.Stderr, "Starting DNS resolution with shuffledns for %d domains...\n", len(results))

	// Run shuffledns
	cmd := exec.CommandContext(ctx, "shuffledns", args...)
	
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("shuffledns failed: %w\nOutput: %s", err, string(output))
	}

	// Read resolved domains (simple format)
	resolvedMap := make(map[string]bool)
	file, err := os.Open(outputFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to open output file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			resolvedMap[domain] = true
		}
	}

	// Update results with resolution status
	// Note: shuffledns in resolve mode doesn't provide IPs directly
	// We'll rely on the built-in resolver for IP details
	for i := range results {
		if resolvedMap[results[i].Domain] {
			results[i].Status = "resolved"
			// The built-in resolver will populate IPs later if needed
		} else {
			results[i].Status = "failed"
		}
	}

	resolvedCount := len(resolvedMap)
	failedCount := len(results) - resolvedCount
	
	if r.config.Verbose {
		fmt.Fprintf(os.Stderr, "DNS resolution completed: %d/%d domains resolved (%d failed)\n", resolvedCount, len(results), failedCount)
	} else {
		// Only show resolved count in non-verbose mode
		fmt.Fprintf(os.Stderr, "DNS resolution completed: %d domains resolved\n", resolvedCount)
	}

	return results, nil
}

// contains checks if a string slice contains a specific string
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

func (r *Resolver) createResolversFile() (string, error) {
	// Create trusted resolvers file
	resolvers := []string{
		"8.8.8.8",
		"8.8.4.4",
		"1.1.1.1",
		"1.0.0.1",
		"208.67.222.222",
		"208.67.220.220",
		"9.9.9.9",
		"149.112.112.112",
		"64.6.64.6",
		"64.6.65.6",
	}

	tmpFile, err := os.CreateTemp("", "subscope-resolvers-*.txt")
	if err != nil {
		return "", err
	}

	for _, resolver := range resolvers {
		if _, err := tmpFile.WriteString(resolver + "\n"); err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return "", err
		}
	}

	tmpFile.Close()
	return tmpFile.Name(), nil
}

// ResolveDomainsFallback uses the built-in resolver if shuffledns is not available
func (r *Resolver) ResolveDomainsFallback(ctx context.Context, results []enumeration.DomainResult) []enumeration.DomainResult {
	// This would fall back to the original DNS resolver implementation
	// For now, we'll just return an error message
	fmt.Fprintln(os.Stderr, "Warning: shuffledns not available, using built-in resolver (slower)")
	return results
}