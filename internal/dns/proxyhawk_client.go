package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"sync"
	"time"
	
	"github.com/gorilla/websocket"
	"github.com/resistanceisuseless/subscope/internal/enumeration"
)

// ProxyHawkWSClient uses WebSocket for persistent connection to ProxyHawk
type ProxyHawkWSClient struct {
	conn      *websocket.Conn
	wsURL     string
	connected bool
	
	// Response handlers
	handlers  map[string]chan ProxyHawkMessage
	handlerMu sync.RWMutex
	
	// Configuration
	config    *ProxyHawkConfig
	
	// Reconnection logic
	reconnectMutex sync.Mutex
	stopChan       chan struct{}
	
	// Message ID counter
	messageIDCounter int64
	messageIDMutex   sync.Mutex
}

// ProxyHawkConfig holds ProxyHawk client configuration
type ProxyHawkConfig struct {
	URL            string
	Regions        []string
	TestMode       string
	Timeout        time.Duration
	BatchSize      int
	ReconnectDelay time.Duration
	MaxRetries     int
}

// ProxyHawkMessage represents a WebSocket message
type ProxyHawkMessage struct {
	Type      string          `json:"type"`
	ID        string          `json:"id,omitempty"`
	Domain    string          `json:"domain,omitempty"`
	Action    string          `json:"action,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
	Error     string          `json:"error,omitempty"`
}

// ProxyHawkGeoTestRequest represents a geographic test request
type ProxyHawkGeoTestRequest struct {
	Domain  string   `json:"domain"`
	Regions []string `json:"regions,omitempty"`
	Mode    string   `json:"mode,omitempty"`
}

// ProxyHawkGeoTestResult represents the result from ProxyHawk geographic testing
type ProxyHawkGeoTestResult struct {
	Domain                   string                                 `json:"domain"`
	TestedAt                 time.Time                             `json:"tested_at"`
	HasGeographicDifferences bool                                  `json:"has_geographic_differences"`
	IsRoundRobin            bool                                  `json:"is_round_robin"`
	Confidence              float64                               `json:"confidence"`
	RegionResults           map[string]*ProxyHawkRegionResult     `json:"region_results"`
	Summary                 *ProxyHawkTestSummary                 `json:"summary"`
}

// ProxyHawkRegionResult represents test results for a specific region
type ProxyHawkRegionResult struct {
	Region       string                      `json:"region"`
	ProxyUsed    string                      `json:"proxy_used"`
	DNSResults   []ProxyHawkDNSResult       `json:"dns_results"`
	HTTPResults  []ProxyHawkHTTPResult      `json:"http_results"`
	ResponseTime time.Duration              `json:"response_time"`
	Success      bool                       `json:"success"`
	Error        string                     `json:"error,omitempty"`
}

// ProxyHawkDNSResult represents a DNS lookup result from ProxyHawk
type ProxyHawkDNSResult struct {
	QueryTime time.Time `json:"query_time"`
	IP        string    `json:"ip"`
	TTL       uint32    `json:"ttl"`
	Type      string    `json:"type"`
}

// ProxyHawkHTTPResult represents an HTTP test result from ProxyHawk
type ProxyHawkHTTPResult struct {
	RequestTime  time.Time         `json:"request_time"`
	StatusCode   int              `json:"status_code"`
	ResponseTime time.Duration    `json:"response_time"`
	Headers      map[string]string `json:"headers"`
	ServerHeader string           `json:"server_header"`
	ContentHash  string           `json:"content_hash"`
	ContentSize  int64            `json:"content_size"`
	RemoteAddr   string           `json:"remote_addr"`
}

// ProxyHawkTestSummary provides a summary of ProxyHawk test results
type ProxyHawkTestSummary struct {
	UniqueIPs        []string          `json:"unique_ips"`
	UniqueServers    []string          `json:"unique_servers"`
	ResponseTimeDiff time.Duration     `json:"response_time_diff"`
	ContentVariations map[string]int   `json:"content_variations"`
	GeographicSpread bool             `json:"geographic_spread"`
}

// NewProxyHawkWSClient creates a new ProxyHawk WebSocket client
func NewProxyHawkWSClient(config *ProxyHawkConfig) *ProxyHawkWSClient {
	if config == nil {
		config = &ProxyHawkConfig{
			URL:            "ws://localhost:8888/ws",
			Regions:        []string{"us-west", "us-east", "eu-west"},
			TestMode:       "basic",
			Timeout:        30 * time.Second,
			BatchSize:      50,
			ReconnectDelay: 5 * time.Second,
			MaxRetries:     3,
		}
	}
	
	return &ProxyHawkWSClient{
		wsURL:    config.URL,
		config:   config,
		handlers: make(map[string]chan ProxyHawkMessage),
		stopChan: make(chan struct{}),
	}
}

// Connect establishes WebSocket connection to ProxyHawk
func (c *ProxyHawkWSClient) Connect() error {
	c.reconnectMutex.Lock()
	defer c.reconnectMutex.Unlock()
	
	if c.connected {
		return nil
	}
	
	u, err := url.Parse(c.wsURL)
	if err != nil {
		return fmt.Errorf("invalid WebSocket URL: %w", err)
	}
	
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to connect to ProxyHawk: %w", err)
	}
	
	c.conn = conn
	c.connected = true
	
	// Start read pump
	go c.readPump()
	
	// Configure client preferences
	if err := c.sendConfig(); err != nil {
		log.Printf("Failed to send initial config: %v", err)
	}
	
	return nil
}

// Disconnect closes the WebSocket connection
func (c *ProxyHawkWSClient) Disconnect() error {
	c.reconnectMutex.Lock()
	defer c.reconnectMutex.Unlock()
	
	if !c.connected {
		return nil
	}
	
	close(c.stopChan)
	
	if c.conn != nil {
		c.conn.Close()
	}
	
	c.connected = false
	return nil
}

// TestDomainAsync sends test request without blocking
func (c *ProxyHawkWSClient) TestDomainAsync(domain string, callback func(*ProxyHawkGeoTestResult, error)) error {
	if !c.connected {
		if err := c.Connect(); err != nil {
			return err
		}
	}
	
	msgID := c.generateMessageID()
	
	// Register callback
	c.handlerMu.Lock()
	resultChan := make(chan ProxyHawkMessage, 1)
	c.handlers[msgID] = resultChan
	c.handlerMu.Unlock()
	
	// Send test request
	msg := ProxyHawkMessage{
		Type:   "test",
		ID:     msgID,
		Domain: domain,
		Data:   c.marshalJSON(ProxyHawkGeoTestRequest{
			Domain:  domain,
			Regions: c.config.Regions,
			Mode:    c.config.TestMode,
		}),
		Timestamp: time.Now(),
	}
	
	if err := c.conn.WriteJSON(msg); err != nil {
		c.handlerMu.Lock()
		delete(c.handlers, msgID)
		c.handlerMu.Unlock()
		return err
	}
	
	// Handle response asynchronously
	go func() {
		defer func() {
			c.handlerMu.Lock()
			delete(c.handlers, msgID)
			c.handlerMu.Unlock()
		}()
		
		select {
		case response := <-resultChan:
			if response.Error != "" {
				callback(nil, fmt.Errorf("ProxyHawk error: %s", response.Error))
				return
			}
			
			var result ProxyHawkGeoTestResult
			if err := json.Unmarshal(response.Data, &result); err != nil {
				callback(nil, fmt.Errorf("failed to parse result: %w", err))
				return
			}
			
			callback(&result, nil)
			
		case <-time.After(c.config.Timeout):
			callback(nil, fmt.Errorf("timeout waiting for response: %s", domain))
		}
	}()
	
	return nil
}

// TestDomain performs synchronous testing of a domain
func (c *ProxyHawkWSClient) TestDomain(ctx context.Context, domain string) (*ProxyHawkGeoTestResult, error) {
	resultChan := make(chan *ProxyHawkGeoTestResult, 1)
	errChan := make(chan error, 1)
	
	err := c.TestDomainAsync(domain, func(result *ProxyHawkGeoTestResult, err error) {
		if err != nil {
			errChan <- err
		} else {
			resultChan <- result
		}
	})
	
	if err != nil {
		return nil, err
	}
	
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errChan:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// BatchTest tests multiple domains efficiently
func (c *ProxyHawkWSClient) BatchTest(ctx context.Context, domains []string) ([]*ProxyHawkGeoTestResult, error) {
	if len(domains) == 0 {
		return []*ProxyHawkGeoTestResult{}, nil
	}
	
	if !c.connected {
		if err := c.Connect(); err != nil {
			return nil, err
		}
	}
	
	msgID := c.generateMessageID()
	
	// Register handler for batch results
	c.handlerMu.Lock()
	resultChan := make(chan ProxyHawkMessage, len(domains))
	c.handlers[msgID] = resultChan
	c.handlerMu.Unlock()
	
	// Send batch request
	msg := ProxyHawkMessage{
		Type: "batch_test",
		ID:   msgID,
		Data: c.marshalJSON(map[string]interface{}{
			"domains": domains,
			"regions": c.config.Regions,
			"mode":    c.config.TestMode,
		}),
		Timestamp: time.Now(),
	}
	
	if err := c.conn.WriteJSON(msg); err != nil {
		c.handlerMu.Lock()
		delete(c.handlers, msgID)
		c.handlerMu.Unlock()
		return nil, err
	}
	
	// Collect results
	var results []*ProxyHawkGeoTestResult
	expectedResults := len(domains)
	
	defer func() {
		c.handlerMu.Lock()
		delete(c.handlers, msgID)
		c.handlerMu.Unlock()
	}()
	
	for len(results) < expectedResults {
		select {
		case response := <-resultChan:
			if response.Type == "batch_result" {
				var batchResults []*ProxyHawkGeoTestResult
				if err := json.Unmarshal(response.Data, &batchResults); err != nil {
					return nil, fmt.Errorf("failed to parse batch results: %w", err)
				}
				results = append(results, batchResults...)
				break
			} else if response.Type == "batch_partial" {
				var partialData struct {
					Results []*ProxyHawkGeoTestResult `json:"results"`
				}
				if err := json.Unmarshal(response.Data, &partialData); err != nil {
					continue
				}
				results = append(results, partialData.Results...)
			}
			
		case <-ctx.Done():
			return results, ctx.Err()
		case <-time.After(c.config.Timeout):
			return results, fmt.Errorf("batch test timeout after receiving %d/%d results", len(results), expectedResults)
		}
	}
	
	return results, nil
}

// ConvertToSubScopeResults converts ProxyHawk results to SubScope format
func (c *ProxyHawkWSClient) ConvertToSubScopeResults(results []*ProxyHawkGeoTestResult) []enumeration.DomainResult {
	var domainResults []enumeration.DomainResult
	
	for _, result := range results {
		if result == nil {
			continue
		}
		
		domainResult := enumeration.DomainResult{
			Domain:     result.Domain,
			Status:     "resolved",
			Source:     "proxyhawk-geodns",
			Timestamp:  result.TestedAt,
			DNSRecords: make(map[string]string),
			GeoDNS:     c.convertToGeoDNSDetails(result),
		}
		
		// Extract DNS records from the first successful region
		for _, regionResult := range result.RegionResults {
			if regionResult.Success && len(regionResult.DNSResults) > 0 {
				for _, dnsResult := range regionResult.DNSResults {
					if dnsResult.Type == "A" {
						domainResult.DNSRecords["A"] = dnsResult.IP
						break
					}
				}
				break
			}
		}
		
		domainResults = append(domainResults, domainResult)
	}
	
	return domainResults
}

// convertToGeoDNSDetails converts ProxyHawk result to GeoDNS details
func (c *ProxyHawkWSClient) convertToGeoDNSDetails(result *ProxyHawkGeoTestResult) *enumeration.GeoDNSDetails {
	details := &enumeration.GeoDNSDetails{
		RoundRobinDetected:     result.IsRoundRobin,
		IsGeographic:           result.HasGeographicDifferences,
		HasRegionalDifferences: result.HasGeographicDifferences,
		UniqueIPs:              result.Summary.UniqueIPs,
		RegionsWithDifferences: len(result.RegionResults),
		RegionalRecords:        make(map[string]enumeration.RegionalDNSInfo),
		FoundInRegions:         []string{},
	}
	
	// Convert region results
	for region, regionResult := range result.RegionResults {
		if regionResult.Success {
			regionalInfo := enumeration.RegionalDNSInfo{
				A: []string{},
			}
			
			// Extract A records
			for _, dnsResult := range regionResult.DNSResults {
				if dnsResult.Type == "A" {
					regionalInfo.A = append(regionalInfo.A, dnsResult.IP)
				}
			}
			
			// Extract server info from HTTP results
			for _, httpResult := range regionResult.HTTPResults {
				if httpResult.ServerHeader != "" {
					regionalInfo.CloudService = httpResult.ServerHeader
					break
				}
			}
			
			details.RegionalRecords[region] = regionalInfo
			details.FoundInRegions = append(details.FoundInRegions, region)
		}
	}
	
	return details
}

// readPump handles incoming messages from ProxyHawk
func (c *ProxyHawkWSClient) readPump() {
	defer func() {
		if c.conn != nil {
			c.conn.Close()
		}
		c.connected = false
	}()
	
	for {
		select {
		case <-c.stopChan:
			return
		default:
		}
		
		var msg ProxyHawkMessage
		err := c.conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("ProxyHawk WebSocket error: %v", err)
			}
			return
		}
		
		// Route message to appropriate handler
		c.routeMessage(msg)
	}
}

// routeMessage routes incoming messages to appropriate handlers
func (c *ProxyHawkWSClient) routeMessage(msg ProxyHawkMessage) {
	c.handlerMu.RLock()
	defer c.handlerMu.RUnlock()
	
	if msg.ID != "" {
		if handler, exists := c.handlers[msg.ID]; exists {
			select {
			case handler <- msg:
			default:
				// Handler channel is full, skip
			}
		}
	}
	
	// Handle special message types
	switch msg.Type {
	case "welcome":
		log.Printf("Connected to ProxyHawk: %s", string(msg.Data))
	case "error":
		log.Printf("ProxyHawk error: %s", msg.Error)
	}
}

// sendConfig sends initial client configuration to ProxyHawk
func (c *ProxyHawkWSClient) sendConfig() error {
	msg := ProxyHawkMessage{
		Type: "set_config",
		Data: c.marshalJSON(map[string]interface{}{
			"regions":    c.config.Regions,
			"test_mode":  c.config.TestMode,
			"batch_size": c.config.BatchSize,
		}),
		Timestamp: time.Now(),
	}
	
	return c.conn.WriteJSON(msg)
}

// generateMessageID generates a unique message ID
func (c *ProxyHawkWSClient) generateMessageID() string {
	c.messageIDMutex.Lock()
	defer c.messageIDMutex.Unlock()
	
	c.messageIDCounter++
	return fmt.Sprintf("subscope_%d_%d", time.Now().UnixNano(), c.messageIDCounter)
}

// marshalJSON marshals data to JSON
func (c *ProxyHawkWSClient) marshalJSON(data interface{}) json.RawMessage {
	bytes, err := json.Marshal(data)
	if err != nil {
		return json.RawMessage(`{"error": "marshal failed"}`)
	}
	return json.RawMessage(bytes)
}

// IsConnected returns whether the client is connected
func (c *ProxyHawkWSClient) IsConnected() bool {
	c.reconnectMutex.Lock()
	defer c.reconnectMutex.Unlock()
	return c.connected
}

// Reconnect attempts to reconnect to ProxyHawk
func (c *ProxyHawkWSClient) Reconnect() error {
	if err := c.Disconnect(); err != nil {
		log.Printf("Error during disconnect: %v", err)
	}
	
	time.Sleep(c.config.ReconnectDelay)
	return c.Connect()
}