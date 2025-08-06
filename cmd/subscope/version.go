package main

// Version information for SubScope
var (
	// Version is the current version of SubScope
	// Update this for major.minor.patch changes:
	// - Major: Breaking changes, incompatible API changes
	// - Minor: New features, backwards compatible
	// - Patch: Bug fixes, backwards compatible
	Version = "1.0.0"
	
	// BuildDate is set during build time
	BuildDate = "dev"
	
	// GitCommit is set during build time
	GitCommit = "dev"
)

// GetVersionInfo returns formatted version information
func GetVersionInfo() string {
	if BuildDate != "dev" && GitCommit != "dev" {
		return Version + " (" + GitCommit + ", built " + BuildDate + ")"
	}
	return Version + " (dev build)"
}