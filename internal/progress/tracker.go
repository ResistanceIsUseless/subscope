package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Tracker provides simple progress tracking for CLI mode
type Tracker struct {
	mu        sync.Mutex
	writer    io.Writer
	phase     string
	current   int
	total     int
	startTime time.Time
	enabled   bool
	lastLine  string
}

// New creates a new progress tracker
func New(enabled bool) *Tracker {
	return &Tracker{
		writer:    os.Stdout,
		startTime: time.Now(),
		enabled:   enabled,
	}
}

// StartPhase starts a new phase of execution
func (p *Tracker) StartPhase(phase string, total int) {
	if !p.enabled {
		return
	}
	
	p.mu.Lock()
	defer p.mu.Unlock()
	
	p.phase = phase
	p.current = 0
	p.total = total
	p.clearLine()
	p.print()
}

// Update updates the current progress
func (p *Tracker) Update(current int) {
	if !p.enabled {
		return
	}
	
	p.mu.Lock()
	defer p.mu.Unlock()
	
	p.current = current
	p.clearLine()
	p.print()
}

// Increment increments the current progress by 1
func (p *Tracker) Increment() {
	if !p.enabled {
		return
	}
	
	p.mu.Lock()
	defer p.mu.Unlock()
	
	p.current++
	p.clearLine()
	p.print()
}

// Complete marks the current phase as complete
func (p *Tracker) Complete() {
	if !p.enabled {
		return
	}
	
	p.mu.Lock()
	defer p.mu.Unlock()
	
	p.current = p.total
	p.clearLine()
	p.print()
	fmt.Fprintln(p.writer) // Move to next line
	p.lastLine = ""
}

// Info prints an informational message without affecting progress
func (p *Tracker) Info(format string, args ...interface{}) {
	if !p.enabled {
		fmt.Printf(format+"\n", args...)
		return
	}
	
	p.mu.Lock()
	defer p.mu.Unlock()
	
	p.clearLine()
	fmt.Fprintf(p.writer, format+"\n", args...)
	p.print() // Reprint progress on next line
}

// clearLine clears the current line
func (p *Tracker) clearLine() {
	if p.lastLine != "" {
		// Clear the line by overwriting with spaces
		fmt.Fprintf(p.writer, "\r%s\r", strings.Repeat(" ", len(p.lastLine)))
	}
}

// print prints the current progress
func (p *Tracker) print() {
	if p.phase == "" {
		return
	}
	
	elapsed := time.Since(p.startTime)
	
	// Calculate percentage
	percent := float64(0)
	if p.total > 0 {
		percent = float64(p.current) / float64(p.total) * 100
	}
	
	// Format progress bar
	barWidth := 20
	filled := int(percent / 100 * float64(barWidth))
	bar := strings.Repeat("=", filled) + strings.Repeat("-", barWidth-filled)
	
	// Format the progress line
	if p.total > 0 {
		p.lastLine = fmt.Sprintf("%-30s [%s] %3.0f%% (%d/%d) [%s]", 
			p.phase, bar, percent, p.current, p.total, formatDuration(elapsed))
	} else {
		// For phases without a known total
		p.lastLine = fmt.Sprintf("%-30s [%s] %d items [%s]", 
			p.phase, strings.Repeat("=", p.current%barWidth)+">", p.current, formatDuration(elapsed))
	}
	
	fmt.Fprint(p.writer, "\r"+p.lastLine)
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	} else {
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

// Disable disables progress tracking (useful for verbose mode)
func (p *Tracker) Disable() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled = false
}

// Enable enables progress tracking
func (p *Tracker) Enable() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled = true
}