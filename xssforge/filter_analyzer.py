"""
XSSForge Filter Analyzer - Magic Character Testing

Pre-scan filter detection to understand what characters and strings
pass through the target's filters. This allows smart payload selection
by eliminating payloads that cannot possibly work.

Inspired by Dalfox's Magic Char testing.
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

try:
    import httpx
except ImportError:
    httpx = None


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class FilterProfile:
    """Profile of what the target's filters block/allow."""

    # Characters that are completely removed or blocked
    blocked_chars: set[str] = field(default_factory=set)

    # Characters that are HTML-encoded (< becomes &lt;)
    encoded_chars: set[str] = field(default_factory=set)

    # Characters that pass through unchanged
    allowed_chars: set[str] = field(default_factory=set)

    # Strings that are blocked or removed
    blocked_strings: set[str] = field(default_factory=set)

    # Strings that are modified but not blocked
    modified_strings: dict[str, str] = field(default_factory=dict)

    # Strings that pass through unchanged
    allowed_strings: set[str] = field(default_factory=set)

    # Additional metadata
    uses_waf: bool = False
    waf_name: str = ""
    uses_sanitizer: bool = False
    sanitizer_hints: list[str] = field(default_factory=list)

    def is_char_blocked(self, char: str) -> bool:
        """Check if a character is blocked."""
        return char in self.blocked_chars

    def is_char_encoded(self, char: str) -> bool:
        """Check if a character gets HTML-encoded."""
        return char in self.encoded_chars

    def is_string_blocked(self, string: str) -> bool:
        """Check if a string is blocked."""
        return string.lower() in {s.lower() for s in self.blocked_strings}

    def can_payload_work(self, payload: str) -> bool:
        """Check if a payload has a chance of working given the filter profile."""
        # Check for blocked characters
        for char in self.blocked_chars:
            if char in payload:
                return False

        # Check for blocked strings
        for blocked in self.blocked_strings:
            if blocked.lower() in payload.lower():
                return False

        return True

    def get_severity(self) -> str:
        """Estimate filter severity based on what's blocked."""
        blocked_critical = {"<", ">", '"', "'", "(", ")"}
        blocked_count = len(self.blocked_chars & blocked_critical)

        if blocked_count >= 5:
            return "strict"
        elif blocked_count >= 3:
            return "moderate"
        elif blocked_count >= 1:
            return "light"
        return "none"

    def summary(self) -> str:
        """Generate a human-readable summary."""
        lines = [
            f"Filter Profile Summary:",
            f"  Severity: {self.get_severity()}",
            f"  Blocked chars: {', '.join(sorted(self.blocked_chars)) or 'none'}",
            f"  Encoded chars: {', '.join(sorted(self.encoded_chars)) or 'none'}",
            f"  Blocked strings: {', '.join(sorted(self.blocked_strings)) or 'none'}",
        ]
        if self.waf_name:
            lines.append(f"  WAF detected: {self.waf_name}")
        if self.sanitizer_hints:
            lines.append(f"  Sanitizer hints: {', '.join(self.sanitizer_hints)}")
        return "\n".join(lines)


# ============================================================================
# Filter Analyzer
# ============================================================================

class FilterAnalyzer:
    """
    Analyze target filters by testing magic characters and strings.

    This pre-scan phase determines what characters and strings pass through
    the target's filters, enabling smart payload selection.
    """

    # Magic characters to test - these are critical for XSS
    MAGIC_CHARS: list[str] = [
        "<", ">",           # Tag delimiters
        '"', "'",           # Quote characters
        "/",                # Tag close / comment
        "\\",               # Escape character
        "(", ")",           # Function calls
        "=",                # Attribute assignment
        ";",                # Statement terminator
        "{", "}",           # Code blocks
        "`",                # Template literals
        "$",                # Template expressions
        "[", "]",           # Array/property access
        "&",                # HTML entities
        "#",                # Fragment / color
        "%",                # URL encoding
        "+",                # String concatenation
        " ",                # Space (whitespace handling)
        "\t",               # Tab
        "\n",               # Newline
        "\r",               # Carriage return
    ]

    # Magic strings to test - common XSS keywords
    MAGIC_STRINGS: list[str] = [
        "<script",          # Script tag
        "script>",          # Script close
        "</script",         # Script close tag
        "onerror",          # Event handler
        "onload",           # Event handler
        "onclick",          # Event handler
        "onmouseover",      # Event handler
        "onfocus",          # Event handler
        "javascript:",      # Protocol handler
        "data:",            # Data URI
        "alert(",           # Common XSS function
        "alert`",           # Template literal call
        "eval(",            # Eval function
        "document",         # DOM access
        "window",           # Window object
        "location",         # Location object
        "cookie",           # Cookie access
        ".innerHTML",       # DOM manipulation
        "constructor",      # Constructor access
        "fromCharCode",     # String bypass
    ]

    # HTML encoding map for detection
    HTML_ENCODE_MAP: dict[str, list[str]] = {
        "<": ["&lt;", "&#60;", "&#x3c;", "&#x3C;"],
        ">": ["&gt;", "&#62;", "&#x3e;", "&#x3E;"],
        '"': ["&quot;", "&#34;", "&#x22;"],
        "'": ["&#39;", "&#x27;", "&apos;"],
        "&": ["&amp;", "&#38;", "&#x26;"],
        "/": ["&#47;", "&#x2f;", "&#x2F;"],
        "(": ["&#40;", "&#x28;", "&lpar;"],
        ")": ["&#41;", "&#x29;", "&rpar;"],
        "=": ["&#61;", "&#x3d;", "&#x3D;"],
    }

    def __init__(self, timeout: float = 10.0, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self._canary_counter = 0

    async def analyze(
        self,
        client: "httpx.AsyncClient",
        url: str,
        param: str
    ) -> FilterProfile:
        """
        Analyze filters for a specific URL parameter.

        Args:
            client: httpx async client
            url: Target URL
            param: Parameter to test

        Returns:
            FilterProfile with analysis results
        """
        profile = FilterProfile()

        # Test magic characters
        char_results = await self._test_chars(client, url, param)
        for char, result in char_results.items():
            if result == "blocked":
                profile.blocked_chars.add(char)
            elif result == "encoded":
                profile.encoded_chars.add(char)
            else:
                profile.allowed_chars.add(char)

        # Test magic strings
        string_results = await self._test_strings(client, url, param)
        for string, result in string_results.items():
            if result == "blocked":
                profile.blocked_strings.add(string)
            elif result == "allowed":
                profile.allowed_strings.add(string)
            elif isinstance(result, str) and result.startswith("modified:"):
                profile.modified_strings[string] = result[9:]

        # Detect WAF/sanitizer signatures
        await self._detect_signatures(client, url, param, profile)

        return profile

    async def _test_chars(
        self,
        client: "httpx.AsyncClient",
        url: str,
        param: str
    ) -> dict[str, str]:
        """Test magic characters and return results."""
        results = {}

        # Test chars in batches for efficiency
        batch_size = 5
        for i in range(0, len(self.MAGIC_CHARS), batch_size):
            batch = self.MAGIC_CHARS[i:i + batch_size]
            tasks = [
                self._test_single_char(client, url, param, char)
                for char in batch
            ]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            for char, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    results[char] = "error"
                else:
                    results[char] = result

        return results

    async def _test_single_char(
        self,
        client: "httpx.AsyncClient",
        url: str,
        param: str,
        char: str
    ) -> str:
        """Test a single character and return 'blocked', 'encoded', or 'allowed'."""
        canary = self._generate_canary()
        test_value = f"{canary}{char}{canary}"

        try:
            test_url = self._inject_param(url, param, test_value)
            response = await client.get(test_url, timeout=self.timeout)
            body = response.text.lower()

            # Check if entire canary+char+canary appears (allowed)
            if test_value.lower() in body:
                return "allowed"

            # Check if character was HTML-encoded
            if char in self.HTML_ENCODE_MAP:
                for encoded in self.HTML_ENCODE_MAP[char]:
                    encoded_value = f"{canary}{encoded}{canary}"
                    if encoded_value.lower() in body:
                        return "encoded"

            # Check if canaries appear but char doesn't (blocked)
            if canary.lower() in body:
                # Canary present but char not found - likely blocked
                return "blocked"

            # Nothing found - completely blocked or not reflected
            return "blocked"

        except Exception as e:
            if self.verbose:
                print(f"Error testing char '{char}': {e}")
            return "error"

    async def _test_strings(
        self,
        client: "httpx.AsyncClient",
        url: str,
        param: str
    ) -> dict[str, str]:
        """Test magic strings and return results."""
        results = {}

        for string in self.MAGIC_STRINGS:
            result = await self._test_single_string(client, url, param, string)
            results[string] = result

        return results

    async def _test_single_string(
        self,
        client: "httpx.AsyncClient",
        url: str,
        param: str,
        string: str
    ) -> str:
        """Test a single string and return result."""
        canary = self._generate_canary()
        test_value = f"{canary}{string}{canary}"

        try:
            test_url = self._inject_param(url, param, test_value)
            response = await client.get(test_url, timeout=self.timeout)
            body = response.text

            # Check if string appears exactly (allowed)
            if test_value in body:
                return "allowed"

            # Check case-insensitive match
            if test_value.lower() in body.lower():
                return "allowed"

            # Check if canaries present but string modified
            if canary in body or canary.lower() in body.lower():
                # Find what's between the canaries
                pattern = f"{canary}(.*?){canary}"
                match = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
                if match:
                    found = match.group(1)
                    if found.lower() != string.lower():
                        return f"modified:{found}"
                return "blocked"

            # Nothing found
            return "blocked"

        except Exception as e:
            if self.verbose:
                print(f"Error testing string '{string}': {e}")
            return "error"

    async def _detect_signatures(
        self,
        client: "httpx.AsyncClient",
        url: str,
        param: str,
        profile: FilterProfile
    ) -> None:
        """Detect WAF and sanitizer signatures."""

        # WAF detection probe
        waf_probe = "<script>alert(1)</script>"
        try:
            test_url = self._inject_param(url, param, waf_probe)
            response = await client.get(test_url, timeout=self.timeout)

            # Check headers for WAF signatures
            headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}

            waf_signatures = {
                "cloudflare": ["cf-ray", "cloudflare"],
                "akamai": ["akamai", "x-akamai"],
                "aws": ["awswaf", "x-amzn"],
                "imperva": ["incap_ses", "visid_incap"],
                "sucuri": ["sucuri", "x-sucuri"],
                "modsecurity": ["mod_security"],
                "f5": ["bigip", "f5-ltm"],
                "fortinet": ["fortigate", "fortiweb"],
                "barracuda": ["barracuda"],
            }

            for waf, sigs in waf_signatures.items():
                for sig in sigs:
                    for v in headers_lower.values():
                        if sig in v:
                            profile.uses_waf = True
                            profile.waf_name = waf
                            break
                    if profile.waf_name:
                        break

            # Check body for WAF block pages
            body_lower = response.text.lower()
            if any(kw in body_lower for kw in ["blocked", "forbidden", "denied", "firewall"]):
                if not profile.waf_name:
                    profile.uses_waf = True
                    profile.waf_name = "generic"

            # Sanitizer detection hints
            sanitizer_hints = []
            if "dompurify" in body_lower:
                sanitizer_hints.append("dompurify")
            if "angular" in body_lower:
                sanitizer_hints.append("angular")
            if "react" in body_lower:
                sanitizer_hints.append("react")
            if "vue" in body_lower:
                sanitizer_hints.append("vue")

            if sanitizer_hints:
                profile.uses_sanitizer = True
                profile.sanitizer_hints = sanitizer_hints

        except Exception as e:
            if self.verbose:
                print(f"Error in WAF detection: {e}")

    def _generate_canary(self) -> str:
        """Generate a unique canary string."""
        self._canary_counter += 1
        return f"xsf{self._canary_counter}xsf"

    def _inject_param(self, url: str, param: str, value: str) -> str:
        """Inject value into URL parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))


# ============================================================================
# Quick Filter Analysis
# ============================================================================

async def quick_analyze(
    url: str,
    param: str,
    timeout: float = 10.0
) -> FilterProfile:
    """
    Quick filter analysis for a URL parameter.

    Args:
        url: Target URL
        param: Parameter to test
        timeout: Request timeout

    Returns:
        FilterProfile with analysis results
    """
    if httpx is None:
        raise ImportError("httpx is required for filter analysis")

    analyzer = FilterAnalyzer(timeout=timeout)

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
    ) as client:
        return await analyzer.analyze(client, url, param)


def analyze_sync(url: str, param: str, timeout: float = 10.0) -> FilterProfile:
    """Synchronous wrapper for filter analysis."""
    return asyncio.run(quick_analyze(url, param, timeout))


# ============================================================================
# Payload Filtering Based on Profile
# ============================================================================

def filter_payloads_for_profile(
    payloads: list[str],
    profile: FilterProfile
) -> list[str]:
    """
    Filter payloads based on the analyzed filter profile.

    Removes payloads that cannot possibly work given the target's filters.

    Args:
        payloads: List of XSS payloads to filter
        profile: FilterProfile from analysis

    Returns:
        List of payloads that have a chance of working
    """
    viable = []
    for payload in payloads:
        if profile.can_payload_work(payload):
            viable.append(payload)
    return viable


def prioritize_payloads_for_profile(
    payloads: list[str],
    profile: FilterProfile
) -> list[str]:
    """
    Prioritize payloads based on filter profile.

    Moves payloads more likely to succeed to the front.

    Args:
        payloads: List of XSS payloads
        profile: FilterProfile from analysis

    Returns:
        Prioritized list of payloads
    """
    def score_payload(payload: str) -> float:
        score = 0.0

        # Penalize for blocked chars
        for char in profile.blocked_chars:
            if char in payload:
                score -= 10.0

        # Penalize for blocked strings
        for string in profile.blocked_strings:
            if string.lower() in payload.lower():
                score -= 10.0

        # Slight penalty for encoded chars (still might work)
        for char in profile.encoded_chars:
            if char in payload:
                score -= 2.0

        # Bonus for using allowed chars only
        uses_only_allowed = all(
            c in profile.allowed_chars or c.isalnum()
            for c in payload
        )
        if uses_only_allowed:
            score += 5.0

        # Bonus for shorter payloads (less likely to hit filters)
        score += max(0, (100 - len(payload)) / 20)

        return score

    # Filter impossible payloads first
    viable = filter_payloads_for_profile(payloads, profile)

    # Sort by score (highest first)
    return sorted(viable, key=score_payload, reverse=True)


# ============================================================================
# CLI / Testing
# ============================================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python filter_analyzer.py <url> <param>")
        print("Example: python filter_analyzer.py 'https://example.com?q=test' q")
        sys.exit(1)

    url = sys.argv[1]
    param = sys.argv[2]

    print(f"Analyzing filters for {url} (param: {param})...")
    profile = analyze_sync(url, param)
    print()
    print(profile.summary())
