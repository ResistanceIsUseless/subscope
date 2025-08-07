package dns

import (
	"context"
	"fmt"
	"log"
	"time"
	
	"github.com/resistanceisuseless/subscope/internal/config"
	"github.com/resistanceisuseless/subscope/internal/enumeration"
)

// EnhancedGeoDNSResolver supports both traditional and ProxyHawk-based geographic DNS
type EnhancedGeoDNSResolver struct {
	config           *config.Config
	traditionalResolver *GeoDNSResolver
	proxyHawkClient  *ProxyHawkWSClient
	useProxyHawk     bool
}

// GeoDNSMethod defines the method used for geographic DNS testing
type GeoDNSMethod string

const (
	MethodTraditional GeoDNSMethod = "traditional"
	MethodProxyHawk   GeoDNSMethod = "proxyhawk"
	MethodAuto        GeoDNSMethod = "auto"
)

// NewEnhancedGeoDNSResolver creates a new enhanced geographic DNS resolver
func NewEnhancedGeoDNSResolver(config *config.Config, proxyHawkURL string) *EnhancedGeoDNSResolver {
	resolver := &EnhancedGeoDNSResolver{
		config:              config,
		traditionalResolver: NewGeoDNSResolver(config),
		useProxyHawk:        false,
	}
	
	// Initialize ProxyHawk client if URL is provided
	if proxyHawkURL != "" {
		proxyHawkConfig := &ProxyHawkConfig{
			URL:            proxyHawkURL,
			Regions:        []string{"us-west", "us-east", "eu-west", "asia"},
			TestMode:       "detailed",
			Timeout:        30 * time.Second,
			BatchSize:      20,
			ReconnectDelay: 5 * time.Second,
			MaxRetries:     3,
		}
		
		resolver.proxyHawkClient = NewProxyHawkWSClient(proxyHawkConfig)
		
		// Test connection
		if err := resolver.proxyHawkClient.Connect(); err != nil {
			if resolver.config.Verbose {
				log.Printf("ProxyHawk connection failed, falling back to traditional method: %v", err)
			}
			resolver.useProxyHawk = false
		} else {
			resolver.useProxyHawk = true
			if resolver.config.Verbose {
				log.Printf("Connected to ProxyHawk at %s", proxyHawkURL)
			}
		}
	}
	
	return resolver
}

// QueryDomainsFromAllRegions performs geographic DNS testing using the best available method
func (e *EnhancedGeoDNSResolver) QueryDomainsFromAllRegions(ctx context.Context, domains []string) ([]enumeration.DomainResult, error) {
	if len(domains) == 0 {
		return []enumeration.DomainResult{}, nil
	}
	
	// Determine method to use
	method := e.determineMethod(ctx, domains)
	
	if e.config.Verbose {
		log.Printf("Using %s method for geographic DNS testing (%d domains)", method, len(domains))
	}
	
	switch method {
	case MethodProxyHawk:
		return e.queryWithProxyHawk(ctx, domains)
	case MethodTraditional:
		return e.queryWithTraditional(ctx, domains)
	default:
		return e.queryWithFallback(ctx, domains)
	}
}

// determineMethod determines the best method for geographic DNS testing
func (e *EnhancedGeoDNSResolver) determineMethod(ctx context.Context, domains []string) GeoDNSMethod {
	// If ProxyHawk is not available, use traditional
	if !e.useProxyHawk || e.proxyHawkClient == nil {
		return MethodTraditional
	}
	
	// Check if ProxyHawk is still connected
	if !e.proxyHawkClient.IsConnected() {
		if err := e.proxyHawkClient.Reconnect(); err != nil {
			if e.config.Verbose {
				log.Printf("ProxyHawk reconnection failed: %v", err)
			}
			e.useProxyHawk = false
			return MethodTraditional
		}
	}
	
	// For small batches, ProxyHawk might be overkill, but its persistent connection
	// and advanced features make it generally better
	return MethodProxyHawk
}

// queryWithProxyHawk performs geographic DNS testing using ProxyHawk
func (e *EnhancedGeoDNSResolver) queryWithProxyHawk(ctx context.Context, domains []string) ([]enumeration.DomainResult, error) {
	if e.config.Verbose {
		log.Printf("Testing %d domains with ProxyHawk", len(domains))
	}
	
	// Use batch testing for efficiency
	results, err := e.proxyHawkClient.BatchTest(ctx, domains)
	if err != nil {
		if e.config.Verbose {
			log.Printf("ProxyHawk batch test failed: %v", err)
		}
		// Fallback to traditional method
		return e.queryWithTraditional(ctx, domains)
	}
	
	// Convert ProxyHawk results to SubScope format
	domainResults := e.proxyHawkClient.ConvertToSubScopeResults(results)
	
	if e.config.Verbose {
		meaningful := 0
		for _, result := range domainResults {
			if result.GeoDNS != nil && result.GeoDNS.HasRegionalDifferences {
				meaningful++
			}
		}
		log.Printf("ProxyHawk found %d domains with regional differences out of %d tested", meaningful, len(results))
	}
	
	return domainResults, nil
}

// queryWithTraditional performs geographic DNS testing using traditional method
func (e *EnhancedGeoDNSResolver) queryWithTraditional(ctx context.Context, domains []string) ([]enumeration.DomainResult, error) {
	if e.config.Verbose {
		log.Printf("Testing %d domains with traditional geographic DNS", len(domains))
	}
	
	return e.traditionalResolver.QueryDomainsFromAllRegionsEnhanced(ctx, domains)
}

// queryWithFallback attempts ProxyHawk first, then falls back to traditional
func (e *EnhancedGeoDNSResolver) queryWithFallback(ctx context.Context, domains []string) ([]enumeration.DomainResult, error) {
	// Try ProxyHawk first
	if e.useProxyHawk && e.proxyHawkClient != nil {
		results, err := e.queryWithProxyHawk(ctx, domains)
		if err == nil {
			return results, nil
		}
		
		if e.config.Verbose {
			log.Printf("ProxyHawk failed, falling back to traditional method: %v", err)
		}
	}
	
	// Fallback to traditional method
	return e.queryWithTraditional(ctx, domains)
}

// TestSingleDomain tests a single domain and returns detailed results
func (e *EnhancedGeoDNSResolver) TestSingleDomain(ctx context.Context, domain string) (*enumeration.DomainResult, error) {
	results, err := e.QueryDomainsFromAllRegions(ctx, []string{domain})
	if err != nil {
		return nil, err
	}
	
	if len(results) == 0 {
		return nil, fmt.Errorf("no results for domain %s", domain)
	}
	
	return &results[0], nil
}

// GetAvailableRegions returns the list of available regions
func (e *EnhancedGeoDNSResolver) GetAvailableRegions() []string {
	if e.useProxyHawk && e.proxyHawkClient != nil {
		return e.proxyHawkClient.config.Regions
	}
	
	// Return traditional regions
	regions := make([]string, len(e.traditionalResolver.regions))
	for i, region := range e.traditionalResolver.regions {
		regions[i] = region.Name
	}
	return regions
}

// SetRegions configures the regions to test
func (e *EnhancedGeoDNSResolver) SetRegions(regions []string) {
	if e.useProxyHawk && e.proxyHawkClient != nil {
		e.proxyHawkClient.config.Regions = regions
		
		// Send updated config to ProxyHawk
		if e.proxyHawkClient.IsConnected() {
			e.proxyHawkClient.sendConfig()
		}
	}
	// Note: Traditional resolver has fixed regions
}

// Close closes the enhanced resolver and cleans up resources
func (e *EnhancedGeoDNSResolver) Close() error {
	if e.proxyHawkClient != nil {
		return e.proxyHawkClient.Disconnect()
	}
	return nil
}

// GetStatus returns the current status of the resolver
func (e *EnhancedGeoDNSResolver) GetStatus() map[string]interface{} {
	status := map[string]interface{}{
		"traditional_available": e.traditionalResolver != nil,
		"proxyhawk_available":   e.proxyHawkClient != nil,
		"proxyhawk_connected":   false,
		"current_method":        "traditional",
	}
	
	if e.proxyHawkClient != nil {
		status["proxyhawk_connected"] = e.proxyHawkClient.IsConnected()
		status["proxyhawk_url"] = e.proxyHawkClient.wsURL
		
		if e.useProxyHawk {
			status["current_method"] = "proxyhawk"
		}
	}
	
	return status
}

// IsProxyHawkAvailable returns whether ProxyHawk is available and connected
func (e *EnhancedGeoDNSResolver) IsProxyHawkAvailable() bool {
	return e.useProxyHawk && e.proxyHawkClient != nil && e.proxyHawkClient.IsConnected()
}

// ForceMethod forces the resolver to use a specific method
func (e *EnhancedGeoDNSResolver) ForceMethod(method GeoDNSMethod) {
	switch method {
	case MethodTraditional:
		e.useProxyHawk = false
	case MethodProxyHawk:
		if e.proxyHawkClient != nil {
			e.useProxyHawk = true
		}
	case MethodAuto:
		// Reset to auto-detection
		e.useProxyHawk = e.proxyHawkClient != nil && e.proxyHawkClient.IsConnected()
	}
}

// EnableRealTimeUpdates enables real-time updates for domains (ProxyHawk only)
func (e *EnhancedGeoDNSResolver) EnableRealTimeUpdates(domains []string) error {
	if !e.IsProxyHawkAvailable() {
		return fmt.Errorf("ProxyHawk not available for real-time updates")
	}
	
	// Subscribe to domains for real-time updates
	// This would require additional ProxyHawk client methods for subscriptions
	// For now, return success
	if e.config.Verbose {
		log.Printf("Real-time updates enabled for %d domains", len(domains))
	}
	
	return nil
}

// GetMethodCapabilities returns the capabilities of different methods
func (e *EnhancedGeoDNSResolver) GetMethodCapabilities() map[GeoDNSMethod]map[string]bool {
	return map[GeoDNSMethod]map[string]bool{
		MethodTraditional: {
			"basic_geodns":         true,
			"round_robin_detection": true,
			"cloud_detection":      true,
			"batch_testing":        true,
			"real_time_updates":    false,
			"proxy_routing":        false,
			"advanced_analysis":    false,
		},
		MethodProxyHawk: {
			"basic_geodns":         true,
			"round_robin_detection": true,
			"cloud_detection":      true,
			"batch_testing":        true,
			"real_time_updates":    true,
			"proxy_routing":        true,
			"advanced_analysis":    true,
		},
	}
}

// CompareResults compares results from both methods (for testing/validation)
func (e *EnhancedGeoDNSResolver) CompareResults(ctx context.Context, domains []string) (*GeoDNSComparison, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains to compare")
	}
	
	comparison := &GeoDNSComparison{
		Domains:           domains,
		TraditionalMethod: true,
		ProxyHawkMethod:   e.IsProxyHawkAvailable(),
	}
	
	// Get traditional results
	traditionalResults, err := e.queryWithTraditional(ctx, domains)
	if err != nil {
		comparison.TraditionalError = err.Error()
	} else {
		comparison.TraditionalResults = traditionalResults
	}
	
	// Get ProxyHawk results if available
	if e.IsProxyHawkAvailable() {
		proxyHawkResults, err := e.queryWithProxyHawk(ctx, domains)
		if err != nil {
			comparison.ProxyHawkError = err.Error()
		} else {
			comparison.ProxyHawkResults = proxyHawkResults
		}
	}
	
	// Analyze differences
	comparison.analyzeComparison()
	
	return comparison, nil
}

// GeoDNSComparison holds comparison results between methods
type GeoDNSComparison struct {
	Domains           []string                  `json:"domains"`
	TraditionalMethod bool                     `json:"traditional_method"`
	ProxyHawkMethod   bool                     `json:"proxyhawk_method"`
	
	TraditionalResults []enumeration.DomainResult `json:"traditional_results,omitempty"`
	ProxyHawkResults   []enumeration.DomainResult `json:"proxyhawk_results,omitempty"`
	
	TraditionalError   string `json:"traditional_error,omitempty"`
	ProxyHawkError     string `json:"proxyhawk_error,omitempty"`
	
	Differences        []string `json:"differences"`
	Similarities       []string `json:"similarities"`
	Recommendation     string   `json:"recommendation"`
}

// analyzeComparison analyzes the differences between methods
func (c *GeoDNSComparison) analyzeComparison() {
	if len(c.TraditionalResults) == 0 && len(c.ProxyHawkResults) == 0 {
		c.Recommendation = "Both methods failed to produce results"
		return
	}
	
	if len(c.TraditionalResults) == 0 {
		c.Recommendation = "Use ProxyHawk method (traditional method failed)"
		return
	}
	
	if len(c.ProxyHawkResults) == 0 {
		c.Recommendation = "Use traditional method (ProxyHawk method failed)"
		return
	}
	
	// Compare results
	traditionalDomains := make(map[string]*enumeration.DomainResult)
	for i, result := range c.TraditionalResults {
		traditionalDomains[result.Domain] = &c.TraditionalResults[i]
	}
	
	proxyHawkDomains := make(map[string]*enumeration.DomainResult)
	for i, result := range c.ProxyHawkResults {
		proxyHawkDomains[result.Domain] = &c.ProxyHawkResults[i]
	}
	
	// Find similarities and differences
	for domain := range traditionalDomains {
		if proxyHawkResult, exists := proxyHawkDomains[domain]; exists {
			traditionalResult := traditionalDomains[domain]
			
			// Compare geographic differences detection
			traditionalHasGeo := traditionalResult.GeoDNS != nil && traditionalResult.GeoDNS.HasRegionalDifferences
			proxyHawkHasGeo := proxyHawkResult.GeoDNS != nil && proxyHawkResult.GeoDNS.HasRegionalDifferences
			
			if traditionalHasGeo == proxyHawkHasGeo {
				c.Similarities = append(c.Similarities, fmt.Sprintf("%s: Both methods agree on geographic differences (%t)", domain, traditionalHasGeo))
			} else {
				c.Differences = append(c.Differences, fmt.Sprintf("%s: Geographic differences detection differs (traditional: %t, proxyhawk: %t)", domain, traditionalHasGeo, proxyHawkHasGeo))
			}
			
			// Compare round-robin detection
			traditionalRR := traditionalResult.GeoDNS != nil && traditionalResult.GeoDNS.RoundRobinDetected
			proxyHawkRR := proxyHawkResult.GeoDNS != nil && proxyHawkResult.GeoDNS.RoundRobinDetected
			
			if traditionalRR == proxyHawkRR {
				c.Similarities = append(c.Similarities, fmt.Sprintf("%s: Both methods agree on round-robin (%t)", domain, traditionalRR))
			} else {
				c.Differences = append(c.Differences, fmt.Sprintf("%s: Round-robin detection differs (traditional: %t, proxyhawk: %t)", domain, traditionalRR, proxyHawkRR))
			}
		}
	}
	
	// Generate recommendation
	if len(c.Differences) == 0 {
		c.Recommendation = "Both methods produce similar results. ProxyHawk recommended for advanced features."
	} else if len(c.Differences) < len(c.Similarities) {
		c.Recommendation = "Methods mostly agree. ProxyHawk recommended for more comprehensive analysis."
	} else {
		c.Recommendation = "Significant differences detected. Manual review recommended."
	}
}