package persistence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/resistanceisuseless/subscope/internal/config"
	"github.com/resistanceisuseless/subscope/internal/enumeration"
)

type Tracker struct {
	config   *config.Config
	dataDir  string
	histFile string
}

type DomainHistory struct {
	Domain        string    `json:"domain"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	SeenCount     int       `json:"seen_count"`
	Sources       []string  `json:"sources"`
	Status        string    `json:"status"`
	IsNew         bool      `json:"is_new,omitempty"`
}

type HistoryData struct {
	TargetDomain string                   `json:"target_domain"`
	LastUpdated  time.Time               `json:"last_updated"`
	Domains      map[string]DomainHistory `json:"domains"`
}

func New(config *config.Config) *Tracker {
	// Create data directory in home directory
	homeDir, _ := os.UserHomeDir()
	dataDir := filepath.Join(homeDir, ".subscope", "history")
	
	return &Tracker{
		config:  config,
		dataDir: dataDir,
	}
}

func (t *Tracker) TrackDomains(targetDomain string, results []enumeration.DomainResult) ([]enumeration.DomainResult, error) {
	fmt.Printf("Tracking domain history for %s...\n", targetDomain)
	
	// Ensure data directory exists
	if err := os.MkdirAll(t.dataDir, 0755); err != nil {
		return results, fmt.Errorf("failed to create history directory: %w", err)
	}
	
	// Set history file path
	safeDomain := t.sanitizeDomainName(targetDomain)
	t.histFile = filepath.Join(t.dataDir, fmt.Sprintf("%s.json", safeDomain))
	
	// Load existing history
	history, err := t.loadHistory(targetDomain)
	if err != nil {
		fmt.Printf("Warning: Failed to load domain history: %v\n", err)
		history = &HistoryData{
			TargetDomain: targetDomain,
			Domains:      make(map[string]DomainHistory),
		}
	}
	
	// Track new and updated domains
	newDomainCount := 0
	updatedResults := make([]enumeration.DomainResult, len(results))
	
	for i, result := range results {
		domain := strings.ToLower(result.Domain)
		now := time.Now()
		
		if existing, exists := history.Domains[domain]; exists {
			// Update existing domain
			existing.LastSeen = now
			existing.SeenCount++
			existing.Status = result.Status
			
			// Add new sources if not already present
			if !t.containsSource(existing.Sources, result.Source) {
				existing.Sources = append(existing.Sources, result.Source)
			}
			
			existing.IsNew = false
			history.Domains[domain] = existing
			
			// Copy result without modification
			updatedResults[i] = result
		} else {
			// New domain discovered
			newDomain := DomainHistory{
				Domain:    domain,
				FirstSeen: now,
				LastSeen:  now,
				SeenCount: 1,
				Sources:   []string{result.Source},
				Status:    result.Status,
				IsNew:     true,
			}
			history.Domains[domain] = newDomain
			newDomainCount++
			
			// Mark result as new
			result.Status = "new_" + result.Status
			updatedResults[i] = result
		}
	}
	
	// Update history metadata
	history.LastUpdated = time.Now()
	
	// Save updated history
	if err := t.saveHistory(history); err != nil {
		fmt.Printf("Warning: Failed to save domain history: %v\n", err)
	} else {
		fmt.Printf("Domain tracking complete: %d new domains, %d total tracked\n", 
			newDomainCount, len(history.Domains))
	}
	
	return updatedResults, nil
}

func (t *Tracker) GetDomainStats(targetDomain string) (*HistoryData, error) {
	safeDomain := t.sanitizeDomainName(targetDomain)
	histFile := filepath.Join(t.dataDir, fmt.Sprintf("%s.json", safeDomain))
	
	history, err := t.loadHistoryFromFile(histFile, targetDomain)
	if err != nil {
		return nil, err
	}
	
	return history, nil
}

func (t *Tracker) GetNewDomains(targetDomain string, since time.Time) ([]DomainHistory, error) {
	history, err := t.GetDomainStats(targetDomain)
	if err != nil {
		return nil, err
	}
	
	var newDomains []DomainHistory
	for _, domain := range history.Domains {
		if domain.FirstSeen.After(since) {
			newDomains = append(newDomains, domain)
		}
	}
	
	return newDomains, nil
}

func (t *Tracker) loadHistory(targetDomain string) (*HistoryData, error) {
	return t.loadHistoryFromFile(t.histFile, targetDomain)
}

func (t *Tracker) loadHistoryFromFile(filePath, targetDomain string) (*HistoryData, error) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// No history file exists, create new
		return &HistoryData{
			TargetDomain: targetDomain,
			Domains:      make(map[string]DomainHistory),
		}, nil
	}
	
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read history file: %w", err)
	}
	
	var history HistoryData
	if err := json.Unmarshal(data, &history); err != nil {
		return nil, fmt.Errorf("failed to parse history file: %w", err)
	}
	
	return &history, nil
}

func (t *Tracker) saveHistory(history *HistoryData) error {
	data, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal history data: %w", err)
	}
	
	if err := os.WriteFile(t.histFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write history file: %w", err)
	}
	
	return nil
}

func (t *Tracker) containsSource(sources []string, source string) bool {
	for _, s := range sources {
		if s == source {
			return true
		}
	}
	return false
}

func (t *Tracker) sanitizeDomainName(domain string) string {
	// Replace characters that aren't safe for filenames
	safe := strings.ReplaceAll(domain, ".", "_")
	safe = strings.ReplaceAll(safe, "*", "wildcard")
	safe = strings.ReplaceAll(safe, "/", "_")
	safe = strings.ReplaceAll(safe, "\\", "_")
	safe = strings.ReplaceAll(safe, ":", "_")
	return safe
}

// CleanupOldEntries removes domains not seen in the last N days
func (t *Tracker) CleanupOldEntries(targetDomain string, daysToKeep int) error {
	history, err := t.GetDomainStats(targetDomain)
	if err != nil {
		return err
	}
	
	cutoff := time.Now().AddDate(0, 0, -daysToKeep)
	initialCount := len(history.Domains)
	
	for domain, entry := range history.Domains {
		if entry.LastSeen.Before(cutoff) {
			delete(history.Domains, domain)
		}
	}
	
	if len(history.Domains) < initialCount {
		if err := t.saveHistory(history); err != nil {
			return err
		}
		fmt.Printf("Cleaned up %d old domain entries (older than %d days)\n", 
			initialCount-len(history.Domains), daysToKeep)
	}
	
	return nil
}