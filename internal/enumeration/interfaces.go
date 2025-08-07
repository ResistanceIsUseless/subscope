package enumeration

import (
	"context"
)

// SubdomainEnumerator defines the interface for subdomain enumeration
type SubdomainEnumerator interface {
	EnumerateSubdomains(ctx context.Context, domain string) ([]string, error)
}

// HTTPAnalyzer defines the interface for HTTP analysis
type HTTPAnalyzer interface {
	AnalyzeDomains(ctx context.Context, domains []string, targetDomain string) ([]string, error)
}

// IntegrationMode defines how tools are integrated
type IntegrationMode string

const (
	IntegrationModeLibrary IntegrationMode = "library" // Use Go libraries directly
	IntegrationModeExec    IntegrationMode = "exec"    // Use external executables
	IntegrationModeAuto    IntegrationMode = "auto"    // Library if available, fallback to exec
)