# XSSForge

**Version 1.0** - A general-purpose XSS vulnerability scanner for security researchers and bug bounty hunters.

## Overview

XSSForge is an automated Cross-Site Scripting (XSS) vulnerability scanner designed to detect XSS vulnerabilities across different contexts and bypass common Web Application Firewalls (WAFs). It combines a comprehensive payload library with intelligent context detection and smart filter analysis.

## Testing & Validation

This scanner has been tested against public XSS challenges to validate its detection capabilities:

- **Google XSS Game**: 6/6 levels detected (100%)
- **sudo.co.il XSS Challenges**: 16/20 levels detected (80%)
- **Overall**: 22/26 public challenges successfully identified

These results demonstrate the scanner's ability to:
- Detect XSS in various contexts (HTML, JavaScript, attributes, URLs)
- Identify DOM-based XSS vulnerabilities
- Bypass basic to intermediate filtering mechanisms
- Handle different reflection patterns

## Realistic Use Cases

### Bug Bounty Hunting
```bash
# Test a single search endpoint
xssforge scan -u "https://target.com/search?q=test"

# Scan multiple URLs from recon
cat discovered_urls.txt | xssforge scan --format json > findings.json

# Deep scan with DOM XSS detection on a web application
xssforge scan -u "https://app.target.com" --dom
```

**Typical Scenarios:**
- Testing search functionality on e-commerce sites
- Finding XSS in user profile fields
- Detecting DOM-based XSS in single-page applications (SPAs)
- Testing comment sections, feedback forms, and chat features

### Penetration Testing
```bash
# Full smart scan during web application assessment
xssforge scan -u "https://client-app.com" --smart

# Pipeline integration with other recon tools
subfinder -d target.com | httpx -silent | xssforge scan --format json
```

**Typical Scenarios:**
- Internal application security assessments
- Pre-deployment security testing
- Third-party application reviews
- Security regression testing

### Security Research
```bash
# Test external JavaScript libraries for DOM XSS
xssforge scan -u "https://analytics.example.com/tracker.js" --dom

# Bulk testing of API endpoints
cat api_endpoints.txt | xssforge scan --format jsonl
```

**Typical Scenarios:**
- Analyzing third-party widgets and plugins
- Testing analytics and tracking scripts
- Researching common vulnerability patterns
- Building PoCs for security advisories

## Key Features

### 1. Comprehensive Payload Library
- **533+ XSS payloads** covering various contexts
- HTML, JavaScript, attribute, and URL injection vectors
- Event handlers, SVG vectors, and polyglot payloads
- WAF bypass techniques and encoding variations

### 2. Smart Context Detection
Automatically identifies injection context:
- HTML body context
- JavaScript string contexts (single/double quotes)
- HTML attribute contexts (quoted/unquoted)
- Event handler contexts
- URL/href contexts

### 3. DOM XSS Detection
- Analyzes JavaScript code for client-side vulnerabilities
- Tracks data flow from sources (location.hash, URL params) to sinks (innerHTML, eval)
- Detects external script vulnerabilities
- Identifies client-side storage XSS (localStorage, sessionStorage)

### 4. WAF Evasion
Built-in evasion techniques for:
- Cloudflare
- Akamai
- AWS WAF
- Imperva
- ModSecurity
- Other common WAFs

### 5. Smart Parameter Mining
- Automatically discovers hidden parameters
- Extracts parameter names from JavaScript variables
- Tests parameters found in HTML comments
- Tries common parameter variations

### 6. External Script Analysis
- Fetches and analyzes external JavaScript files
- Prioritizes scripts from untrusted domains (dev, staging, analytics)
- Detects vulnerabilities in third-party libraries
- Identifies URL construction patterns in tracking code

## Installation

### Requirements
- Python 3.10 or higher
- pip package manager

### Install from GitHub
```bash
git clone https://github.com/ds-sec162/xssforge.git
cd xssforge
pip install -e .
```

### Optional: Browser Verification
For advanced DOM XSS verification with browser simulation:
```bash
pip install -e ".[browser]"
playwright install chromium
```

## Usage

### Basic Scanning
```bash
# Scan a single URL
xssforge scan -u "https://example.com/search?q=test"

# Scan from a file
xssforge scan -l urls.txt

# Scan from stdin (pipeline)
cat targets.txt | xssforge scan
```

### Advanced Options
```bash
# Smart mode (DOM XSS + parameter mining + external scripts)
xssforge scan -u "https://example.com" --smart

# DOM XSS scanning only
xssforge scan -u "https://example.com" --dom

# Output formats
xssforge scan -u "https://example.com" --format json -o results.json
xssforge scan -l targets.txt --format jsonl > findings.jsonl

# Browser verification (requires playwright)
xssforge scan -u "https://example.com" --browser

# Adjust scan intensity
xssforge scan -u "https://example.com" --preset quick      # Fast scan
xssforge scan -u "https://example.com" --preset standard   # Default
xssforge scan -u "https://example.com" --preset thorough   # Deep scan
```

### Pipeline Integration
```bash
# With subfinder and httpx
subfinder -d target.com | httpx -silent | xssforge scan --format json

# With waybackurls
waybackurls target.com | grep "=" | xssforge scan

# With nuclei
xssforge scan -l targets.txt --format json | jq -r '.[] | .url' | nuclei -t xss
```

## Limitations & Responsible Use

### Known Limitations
1. **Not a silver bullet**: Some advanced XSS (especially those requiring complex user interaction or specific browser behaviors) may not be detected
2. **False negatives**: Heavily obfuscated or custom-filtered inputs might bypass detection
3. **Context-specific payloads**: Some modern frameworks with strict CSP or sanitization may block common payloads
4. **Rate limiting**: Scanning too aggressively may trigger rate limits or IP blocks

### Responsible Disclosure
- **Always obtain written authorization** before testing any application you don't own
- Respect bug bounty program rules and scope
- Follow responsible disclosure practices
- Never exploit vulnerabilities beyond proof-of-concept
- Don't scan production systems without permission

### Legal Notice
This tool is provided for educational purposes and authorized security testing only. Users are responsible for complying with applicable laws and regulations. Unauthorized access to computer systems is illegal.

## How It Works

### Detection Flow
1. **Context Analysis**: Determines where the input is reflected (HTML, JS, attribute, etc.)
2. **Filter Detection**: Tests which characters and strings are blocked
3. **Smart Payload Selection**: Chooses payloads likely to work based on context and filters
4. **Verification**: Confirms payload is executable (not just reflected but sanitized)
5. **DOM Analysis**: Scans JavaScript for client-side XSS patterns

### Example Detection
```bash
$ xssforge scan -u "https://example.com/search?q=test" --verbose

[*] XSSForge v1.0 (533 payloads)
[*] Preset: standard
[WAF] example.com: Cloudflare detected
[FILTER] Analyzing q parameter...
[CONTEXT] Detected: HTML body context
[*] Found 1 XSS vulnerability
[HIGH] https://example.com/search?q=%3Csvg+onload%3Dalert(1)%3E | q=<svg onload=alert(1)>
```

## Output Formats

### Text (default)
```
[HIGH] https://target.com/search?q=<svg+onload=alert(1)> | q=<svg onload=alert(1)>
```

### JSON
```json
{
  "url": "https://target.com/search",
  "param": "q",
  "payload": "<svg onload=alert(1)>",
  "context": "html",
  "severity": "high",
  "verified": true
}
```

## Contributing

Contributions are welcome! Please ensure:
- Code follows existing style
- New payloads are tested and effective
- Documentation is updated
- No malicious code or backdoors

## License

MIT License - see LICENSE file for details

## Disclaimer

This tool is for authorized security testing only. The authors are not responsible for misuse or illegal activities. Always obtain proper authorization before testing any systems you don't own.

## Support

For bug reports and feature requests, please open an issue on GitHub:
https://github.com/ds-sec162/xssforge/issues

---

**Author**: Dennis
**Version**: 1.0.0
**Last Updated**: February 2026
