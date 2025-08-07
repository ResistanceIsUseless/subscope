package alterx

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/resistanceisuseless/subscope/internal/config"
)

type Integration struct {
	config *config.Config
}

func New(config *config.Config) *Integration {
	return &Integration{
		config: config,
	}
}

func (a *Integration) GenerateDynamicWordlist(ctx context.Context, discoveredSubdomains []string) ([]string, error) {
	if !a.config.AlterX.EnableEnrichment {
		return []string{}, nil
	}

	// Check if alterx is available
	if _, err := exec.LookPath("alterx"); err != nil {
		fmt.Printf("Warning: alterx not found in PATH. Skipping dynamic wordlist generation.\n")
		fmt.Printf("Install with: go install github.com/projectdiscovery/alterx/cmd/alterx@latest\n")
		return []string{}, nil
	}

	if len(discoveredSubdomains) == 0 {
		return []string{}, nil
	}

	fmt.Printf("Generating dynamic wordlist from %d discovered subdomains...\n", len(discoveredSubdomains))

	// Build alterx command
	var args []string
	
	// Check if custom args are provided
	if a.config.ExecMode.AlterXArgs != "" {
		// Use custom args but ensure silent mode
		customArgs := strings.Fields(a.config.ExecMode.AlterXArgs)
		args = customArgs
		if !contains(customArgs, "-silent") && !contains(customArgs, "-s") {
			args = append(args, "-silent")
		}
	} else {
		// Use default args
		args = []string{"-silent"}
		
		if a.config.AlterX.EnableEnrichment {
			args = append(args, "-enrich")
		}

		// Add patterns if specified
		if len(a.config.AlterX.Patterns) > 0 {
			for _, pattern := range a.config.AlterX.Patterns {
				args = append(args, "-p", pattern)
			}
		}
	}

	// Create command with context for timeout
	cmd := exec.CommandContext(ctx, "alterx", args...)
	
	// Prepare input - pass discovered subdomains to alterx
	inputData := strings.Join(discoveredSubdomains, "\n")
	cmd.Stdin = strings.NewReader(inputData)

	// Execute command
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("alterx command failed: %w", err)
	}

	// Parse output
	var permutations []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" && a.isValidDomain(domain) {
			permutations = append(permutations, domain)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading alterx output: %w", err)
	}

	// Limit permutations to configured maximum
	if len(permutations) > a.config.AlterX.MaxPermutations {
		fmt.Printf("Limiting alterx output from %d to %d permutations\n", 
			len(permutations), a.config.AlterX.MaxPermutations)
		permutations = permutations[:a.config.AlterX.MaxPermutations]
	}

	fmt.Printf("Generated %d dynamic permutations\n", len(permutations))
	return permutations, nil
}

func (a *Integration) AnalyzeNamingPatterns(subdomains []string) []string {
	patterns := make(map[string]bool)
	
	// Common environment patterns
	envPattern := regexp.MustCompile(`(dev|test|staging|prod|qa|uat)-.*|.*-(dev|test|staging|prod|qa|uat)`)
	
	// Number patterns
	numberPattern := regexp.MustCompile(`.*\d+.*`)
	
	// Hyphen patterns
	hyphenPattern := regexp.MustCompile(`.*-.*`)
	
	for _, subdomain := range subdomains {
		// Remove the domain part to focus on subdomain structure
		parts := strings.Split(subdomain, ".")
		if len(parts) > 0 {
			sub := parts[0]
			
			if envPattern.MatchString(sub) {
				patterns["env-pattern"] = true
			}
			if numberPattern.MatchString(sub) {
				patterns["number-pattern"] = true
			}
			if hyphenPattern.MatchString(sub) {
				patterns["hyphen-pattern"] = true
			}
		}
	}
	
	var result []string
	for pattern := range patterns {
		result = append(result, pattern)
	}
	
	return result
}

func (a *Integration) isValidDomain(domain string) bool {
	// Basic domain validation
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	
	// Check for valid characters
	validDomain := regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
	if !validDomain.MatchString(domain) {
		return false
	}
	
	// Check for consecutive dots or hyphens
	if strings.Contains(domain, "..") || strings.Contains(domain, "--") {
		return false
	}
	
	// Must contain at least one dot
	if !strings.Contains(domain, ".") {
		return false
	}
	
	return true
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