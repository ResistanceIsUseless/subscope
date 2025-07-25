# SubScope - Advanced Subdomain Enumeration Tool

SubScope is an enterprise-grade subdomain enumeration tool that combines multiple discovery techniques with intelligent filtering and stealth capabilities for comprehensive reconnaissance.

## Features

- **Multi-Source Discovery**: Integrates passive enumeration, certificate transparency, dynamic wordlist generation, and active probing
- **Intelligent Filtering**: Wildcard detection and filtering to eliminate false positives
- **Enhanced DNS Analysis**: Collects CNAME, SOA records with automatic cloud service detection
- **Geographic DNS Resolution**: Queries from multiple global regions to catch geo-specific subdomains
- **Organization Intelligence**: RDAP integration for IP ownership data from all major RIRs
- **Cloud Infrastructure Mapping**: Identifies AWS, Azure, GCP, and CDN services automatically
- **Domain Persistence**: Track new domains across scans with built-in history
- **Stealth Capabilities**: User-agent rotation, request jitter, and rate limiting
- **Multiple Output Formats**: JSON, CSV, massdns, dnsx, Aquatone, and EyeWitness formats for tool chaining
- **Input Domain Support**: Load domains from files for iterative scanning workflows
- **Progress Indicators**: Real-time progress bars for long-running operations
- **Rate Limit Profiles**: Stealth, normal, and aggressive scanning modes
- **Go Install Support**: Easy installation and distribution

## Installation

### Using Go Install
```bash
go install -v github.com/resistanceisuseless/subscope/cmd/subscope@latest
```

### Building from Source
```bash
git clone https://github.com/resistanceisuseless/subscope
cd subscope
go build -o subscope cmd/subscope/main.go
```

### Dependencies

SubScope integrates with these tools (install separately):
- [subfinder](https://github.com/projectdiscovery/subfinder) - Passive subdomain enumeration
- [httpx](https://github.com/projectdiscovery/httpx) - HTTP/HTTPS probing
- [shuffledns](https://github.com/projectdiscovery/shuffledns) - Fast DNS resolution (recommended)
- [alterx](https://github.com/projectdiscovery/alterx) - Dynamic wordlist generation (optional, use with -all flag)

```bash
# Install core dependencies
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

# Optional dependency for -all flag
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
```

## Usage

SubScope supports both short and long flag options following standard Unix conventions.

### Basic Enumeration
```bash
# Default optimized pipeline (faster)
subscope -d example.com
subscope --domain example.com

# Complete pipeline with all phases
subscope -d example.com -a
subscope --domain example.com --all

# Geographic DNS analysis only
subscope -d example.com -g
subscope --domain example.com --geo
```

### Flag Options

#### Core Flags
- `-d, --domain`: Target domain to enumerate
- `-c, --config`: Configuration file path
- `-o, --output`: Output file path (default: results.json)
- `-f, --format`: Output format (json, csv, massdns, dnsx, aquatone, eyewitness)

#### Analysis Modes
- `-a, --all`: Run all phases including CT, AlterX, RDAP, and persistence
- `-g, --geo`: Enable geographic DNS analysis from multiple regions
- `-v, --verbose`: Enable verbose logging
- `-i, --interactive`: Run in interactive TUI mode (not yet implemented)

#### Input/Output Options
- `--input-domains`: Path to file containing additional domains to scan
- `--merge`: Merge input domains with discovered domains (default: replace)
- `--progress`: Show progress indicators for long-running operations
- `--profile`: Apply rate limit profile (stealth, normal, aggressive)

#### Information
- `-s, --stats`: Show domain history statistics
- `--new-since`: Show new domains since date (YYYY-MM-DD)
- `--create-config`: Create default configuration file

### Output Formats
```bash
# JSON output (default)
subscope -d example.com -o results.json

# CSV format
subscope -d example.com -f csv -o results.csv

# massdns format
subscope -d example.com -f massdns -o domains.txt

# dnsx format
subscope -d example.com -f dnsx -o dnsx-input.txt

# Aquatone format (domain,ip,port)
subscope -d example.com -f aquatone -o aquatone-input.txt

# EyeWitness format (URL list)
subscope -d example.com -f eyewitness -o eyewitness-urls.txt
```

### Input Domain Support
```bash
# Load domains from file and scan them instead of discovered domains
subscope -d example.com --input-domains domains.txt

# Merge input domains with discovered domains
subscope -d example.com --input-domains domains.txt --merge

# Iterative scanning example
subscope -d example.com -o round1.json
# Extract domains from previous scan results and scan them
subscope -d example.com --input-domains extracted-domains.txt -o round2.json
```

### Geographic DNS Analysis
```bash
# Geographic analysis only (faster than --all)
subscope -d example.com --geo

# Geographic analysis with verbose output
subscope -d example.com -g -v

# Combined with custom output format
subscope -d example.com -g -f csv -o geo-results.csv
```

### Progress Indicators
```bash
# Show progress bars for long-running operations
subscope -d example.com --progress

# Works with all modes
subscope -d example.com -a --progress  # All phases with progress
subscope -d example.com -g --progress  # Geographic analysis with progress
```

### Rate Limit Profiles
```bash
# Stealth mode - minimal footprint (5 req/sec, delays, jitter)
subscope -d example.com --profile stealth

# Normal mode - balanced performance (20 req/sec)
subscope -d example.com --profile normal

# Aggressive mode - maximum speed (100 req/sec, no delays)
subscope -d example.com --profile aggressive

# Combine with other options
subscope -d example.com --profile stealth -g --progress
```

### Configuration

Create a default configuration file:
```bash
subscope -create-config
```

This creates `~/.config/subscope/config.yaml` with customizable settings:
- Rate limiting and jitter
- Stealth options (user agents, delays)
- Tool-specific configurations
- Output preferences

### Domain History & Tracking

View domain statistics:
```bash
subscope -d example.com -s
subscope --domain example.com --stats
```

Show new domains discovered since a specific date:
```bash
subscope -d example.com --new-since 2024-01-01
```

## Enumeration Pipeline

### Default Pipeline (Optimized)
By default, SubScope runs these phases for faster results:

1. **Wildcard Detection**: Tests for wildcard DNS to prevent false positives
2. **Passive Enumeration**: Uses subfinder to query multiple data sources (includes CT logs)
3. **HTTP/HTTPS Analysis**: Probes with httpx to discover from headers, SSL certs, and redirects
4. **DNS Resolution**: Uses shuffledns for fast multi-threaded resolution (falls back to built-in if not installed)
5. **RDNS Analysis**: Performs reverse lookups on resolved IPs
6. **Wildcard Filtering**: Removes false positives from wildcard responses

### Complete Pipeline (-a/--all flag)
Use `-a` or `--all` flag to enable all phases including:

1-6. All default phases above, plus:
7. **Certificate Transparency**: Additional CT log queries (temporarily disabled)
8. **Dynamic Wordlist**: Generates permutations using alterx (after HTTP discovery)
9. **Enhanced RDNS**: IP range scanning for additional subdomain discovery
10. **Geographic DNS Analysis**: Multi-region queries to detect geo-specific subdomains
11. **Organization Data**: Queries RDAP APIs for IP ownership information
12. **Persistence Tracking**: Marks new domains and maintains history

## Output Format

### JSON Output Structure

SubScope now organizes results into three distinct categories for better clarity:

```json
{
  "metadata": {
    "version": "1.0",
    "timestamp": "2025-01-25T10:30:00Z",
    "tool": {
      "name": "SubScope",
      "version": "0.1.0"
    },
    "target": "example.com",
    "scan_type": "passive+zone_transfer+httpx+rdns+geodns+resolution"
  },
  "statistics": {
    "domains_resolved": 45,
    "domains_discovered": 12,
    "domains_generated_failed": 234,
    "execution_time": "5m30s",
    "sources": ["subfinder", "zone_transfer", "httpx", "rdns", "geodns"]
  },
  "resolved_domains": [
    {
      "domain": "api.example.com",
      "status": "resolved",
      "dns_records": {
        "A": "192.0.2.1",
        "A_ALL": "192.0.2.1,192.0.2.2",
        "CNAME": "api-prod.cloudfront.net",
        "TXT": "v=spf1 include:_spf.google.com ~all",
        "SOA": "ns-123.awsdns-12.com awsdns-hostmaster.amazon.com 1 7200 900 1209600 86400",
        "CLOUD_SERVICE": "AWS-CloudFront",
        "CLOUD_DNS": "AWS-Route53"
      },
      "source": "subfinder",
      "timestamp": "2025-01-25T10:25:00Z"
    }
  ],
  "discovered_domains": [
    {
      "domain": "old-api.example.com",
      "status": "failed",
      "source": "subfinder",
      "timestamp": "2025-01-25T10:25:00Z"
    }
  ],
  "failed_generated": [
    {
      "domain": "api-dev-staging-test.example.com",
      "status": "failed",
      "source": "alterx",
      "timestamp": "2025-01-25T10:25:00Z"
    }
  ]
}
```

### Result Categories

- **`resolved_domains`**: Successfully resolved domains with complete DNS information (IP addresses, CNAME, TXT, SOA records when present)
- **`discovered_domains`**: Real domains found through legitimate enumeration sources but failed to resolve or have no A records (could be temporarily down or misconfigured)
- **`failed_generated`**: AlterX-generated permutations that failed to resolve (likely non-existent domains created by wordlist generation)

### Domain Status Values
- `discovered`: Found but not yet resolved
- `resolved`: Successfully resolved to IP address
- `wildcard`: Matches wildcard DNS pattern
- `failed`: DNS resolution failed
- `new_resolved`: Newly discovered and resolved (with persistence enabled)

### Discovery Sources
- `subfinder`: Passive enumeration
- `zone_transfer`: DNS zone transfer (AXFR) attempts
- `alterx`: Dynamic wordlist/bruteforcing
- `httpx`: HTTP headers, SSL certificates, redirects
- `rdns`: Reverse DNS lookup
- `rdns_range`: IP range scanning for reverse DNS
- `geodns`: Geographic DNS resolution differences

## Advanced Features

### Enhanced DNS Analysis

SubScope automatically collects comprehensive DNS records for each resolved domain:

#### DNS Records Collected
- **A/AAAA**: IP addresses (IPv4/IPv6)
- **CNAME**: Canonical name records with automatic cloud service detection
- **SOA**: Start of Authority records for DNS provider identification

#### Automatic Cloud Service Detection
SubScope identifies cloud services and infrastructure automatically:

**Supported Cloud Providers:**
- **AWS**: CloudFront, ELB, S3, Global Accelerator, Lambda, etc.
- **Azure**: Static Web Apps, App Service, CDN, Traffic Manager, Front Door
- **Google Cloud**: Cloud Storage, App Engine, Cloud Run, Cloud Functions
- **CDN Providers**: Cloudflare, Fastly, Akamai, KeyCDN
- **Platforms**: GitHub Pages, Netlify, Vercel, Heroku

**Example Output:**
```json
{
  "domain": "api.example.com",
  "dns_records": {
    "CNAME": "d123abc.cloudfront.net",
    "CLOUD_SERVICE": "AWS-CloudFront",
    "CLOUD_DNS": "AWS-Route53"
  }
}
```

### Geographic DNS Resolution

SubScope can detect geo-specific subdomains that only resolve from certain geographic regions - a capability unique among subdomain enumeration tools.

#### How It Works
1. **EDNS Client Subnet**: Uses RFC 7871 extension to simulate queries from different geographic locations
2. **HTTP DNS APIs**: Leverages Google DNS API with geographic IP simulation
3. **Multi-Region Analysis**: Compares responses across 6 global regions
4. **Difference Detection**: Identifies subdomains that resolve differently by region

#### Supported Regions
- **US West Coast** (California) - `8.8.8.8`
- **US East Coast** (New York) - `4.2.2.2`
- **Western Europe** (Amsterdam) - `85.10.10.10`
- **Eastern Europe** (Warsaw) - `195.46.39.39`
- **Asia Pacific** (Singapore) - `180.76.76.76`
- **East Asia** (Hong Kong) - `114.114.114.114`

#### Technical Implementation
```bash
# Example: Geographic DNS query simulation
# From US West Coast perspective
curl "https://dns.google/resolve?name=cdn.example.com&edns_client_subnet=8.8.8.8/24"
# Returns: us-west-1.cloudfront.net

# From Europe perspective  
curl "https://dns.google/resolve?name=cdn.example.com&edns_client_subnet=85.10.10.10/24"
# Returns: eu-west-1.cloudfront.net
```

#### Usage
Geographic DNS analysis can be enabled with the dedicated `-g/--geo` flag or as part of the complete analysis with `-a/--all`:

```bash
# Enable geographic analysis only (faster)
subscope -d example.com -g
subscope --domain example.com --geo

# Enable geographic analysis as part of complete pipeline
subscope -d example.com -a
subscope --domain example.com --all

# Output includes geographic differences:
# Phase 2.8: Geographic DNS analysis...
# Querying example.com from US-West (US West Coast)...
# Querying example.com from Europe-West (Western Europe)...
# 
# ============================================================
#                 GEOGRAPHIC DNS ANALYSIS
# ============================================================
# 
# 🌍 Results by Region:
#    US-West             : 15 domains
#    Europe-West         : 12 domains
#    Asia-Pacific        : 18 domains
# 
# 🎯 Geographic Differences Detected:
#    cdn-eu.example.com     : [Europe-West, Asia-Pacific]
#    api-us.example.com     : [US-West, US-East]
```

#### Benefits
- **Complete Coverage**: Catches CDN edge domains specific to regions
- **Geo-blocked Content**: Discovers region-restricted subdomains
- **CDN Intelligence**: Maps global CDN distribution patterns
- **Security Testing**: Identifies region-specific attack surfaces

### Rate Limit Profiles

SubScope includes three built-in rate limit profiles to balance speed and stealth:

#### Stealth Profile (`--profile stealth`)
- **Rate**: 5 requests/second with jitter
- **Delays**: 1-3 second random delays between requests
- **Use Case**: Sensitive targets, avoid detection
- **Features**: User-agent rotation, request jitter, conservative timeouts

#### Normal Profile (`--profile normal`) 
- **Rate**: 20 requests/second 
- **Delays**: 100-500ms random delays
- **Use Case**: Standard authorized testing
- **Features**: Balanced performance and respect for target infrastructure

#### Aggressive Profile (`--profile aggressive`)
- **Rate**: 100 requests/second with burst capability
- **Delays**: No artificial delays
- **Use Case**: Internal testing, authorized high-speed scans
- **Features**: Maximum concurrency, shorter timeouts

```bash
# Example usage
subscope -d example.com --profile stealth --progress
subscope -d example.com --profile aggressive -a
```

### DNS Zone Transfer Detection

SubScope attempts DNS zone transfers (AXFR) early in the enumeration process:

```bash
# Example successful zone transfer
Phase 1.1: Zone transfer (AXFR) attempt...
Attempting zone transfer (AXFR) for zonetransfer.me...
Found 2 name servers for zonetransfer.me
Zone transfer successful from nsztm2.digi.ninja - found 35 domains
```

**Features:**
- Tests all authoritative name servers
- Proper error handling for REFUSED responses
- Rate limiting integration
- Early detection in enumeration pipeline

### Rate Limiting
Configure global rate limits in the config file:
```yaml
rate_limit:
  global: 10  # requests per second
  jitter: true
```

### Stealth Options
```yaml
stealth:
  user_agents:
    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36..."
    - "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36..."
  random_delay_ms: 100
  request_jitter: true
```

### AlterX Configuration
```yaml
alterx:
  max_permutations: 10000
  enable_enrichment: true
  patterns:
    - "{{word}}-api"
    - "{{word}}-dev"
```

## Security Considerations

- SubScope is designed for authorized security testing only
- Always ensure you have permission to test target domains
- The tool implements rate limiting and delays to be respectful to target infrastructure
- User-agent rotation helps avoid detection but should not be used for malicious purposes

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built on top of excellent tools from [ProjectDiscovery](https://github.com/projectdiscovery)
- Inspired by the need for comprehensive subdomain enumeration with intelligent filtering
- Thanks to the security community for feedback and suggestions