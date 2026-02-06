# XSSForge

Professional XSS Scanner v2.1

A general-purpose XSS vulnerability scanner with advanced detection capabilities.

## Features

- 533+ universal XSS payloads
- Smart context detection (HTML, JavaScript, URL, event handlers)
- External script analysis with DOM XSS detection
- URL construction pattern detection
- Smart parameter mining
- WAF evasion (Cloudflare, Akamai, AWS, etc.)
- Pipeline support (stdin, file, JSON output)

## Installation

```bash
git clone https://github.com/ds-sec162/xssforge.git
cd xssforge
pip install -e .
```

## Usage

```bash
# Basic scan
xssforge scan -u https://target.com/search?q=test

# Smart mode (DOM XSS, external scripts, param mining)
xssforge scan -u https://target.com --smart

# Pipeline mode
cat urls.txt | xssforge scan --format json > results.json
```

## Detection Rate

- Google XSS Game: 6/6 (100%)
- sudo.co.il challenges: 16/20 (80%)
- Overall: 22/26 (84%)

## License

MIT

