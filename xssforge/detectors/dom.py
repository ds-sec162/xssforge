"""
DOM XSS detector for XSSForge.

Detects DOM-based XSS vulnerabilities using static and dynamic analysis.
"""

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, parse_qs

from xssforge.utils.http import HTTPClient, HTTPConfig
from xssforge.detectors.reflected import XSSFinding, ScanConfig
from xssforge.payloads.generator import XSSContext
from xssforge.waf.fingerprint import WAFType


@dataclass
class DOMSink:
    """Represents a dangerous DOM sink."""
    name: str
    pattern: re.Pattern
    severity: str
    description: str
    example: str


@dataclass
class DOMSource:
    """Represents a DOM source of user input."""
    name: str
    pattern: re.Pattern
    description: str


@dataclass
class DOMVulnerability:
    """Represents a potential DOM XSS vulnerability."""
    source: str
    sink: str
    code_snippet: str
    line_number: int
    severity: str
    confidence: float


class DOMXSSDetector:
    """Detects DOM-based XSS vulnerabilities."""

    # Dangerous sinks that can execute code
    SINKS: list[DOMSink] = [
        DOMSink(
            name="innerHTML",
            pattern=re.compile(r'\.innerHTML\s*=', re.I),
            severity="high",
            description="Direct HTML injection",
            example="element.innerHTML = userInput",
        ),
        DOMSink(
            name="outerHTML",
            pattern=re.compile(r'\.outerHTML\s*=', re.I),
            severity="high",
            description="Direct HTML injection",
            example="element.outerHTML = userInput",
        ),
        DOMSink(
            name="document.write",
            pattern=re.compile(r'document\.write\s*\(', re.I),
            severity="high",
            description="Document write injection",
            example="document.write(userInput)",
        ),
        DOMSink(
            name="document.writeln",
            pattern=re.compile(r'document\.writeln\s*\(', re.I),
            severity="high",
            description="Document write injection",
            example="document.writeln(userInput)",
        ),
        DOMSink(
            name="eval",
            pattern=re.compile(r'\beval\s*\(', re.I),
            severity="critical",
            description="Code execution",
            example="eval(userInput)",
        ),
        DOMSink(
            name="setTimeout",
            pattern=re.compile(r'setTimeout\s*\(\s*[\'"`]?[^,)]+', re.I),
            severity="high",
            description="Delayed code execution",
            example="setTimeout(userInput, 1000)",
        ),
        DOMSink(
            name="setInterval",
            pattern=re.compile(r'setInterval\s*\(\s*[\'"`]?[^,)]+', re.I),
            severity="high",
            description="Repeated code execution",
            example="setInterval(userInput, 1000)",
        ),
        DOMSink(
            name="Function",
            pattern=re.compile(r'\bFunction\s*\(', re.I),
            severity="critical",
            description="Dynamic function creation",
            example="new Function(userInput)()",
        ),
        DOMSink(
            name="location",
            pattern=re.compile(r'(location|location\.href|location\.replace|location\.assign)\s*=', re.I),
            severity="medium",
            description="URL redirection",
            example="location = userInput",
        ),
        DOMSink(
            name="src",
            pattern=re.compile(r'\.src\s*=', re.I),
            severity="medium",
            description="Resource loading",
            example="img.src = userInput",
        ),
        DOMSink(
            name="href",
            pattern=re.compile(r'\.href\s*=', re.I),
            severity="medium",
            description="Link manipulation",
            example="a.href = userInput",
        ),
        DOMSink(
            name="jQuery.html",
            pattern=re.compile(r'\$\([^)]+\)\.html\s*\(', re.I),
            severity="high",
            description="jQuery HTML injection",
            example="$(el).html(userInput)",
        ),
        DOMSink(
            name="jQuery.append",
            pattern=re.compile(r'\$\([^)]+\)\.append\s*\(', re.I),
            severity="high",
            description="jQuery DOM append",
            example="$(el).append(userInput)",
        ),
        DOMSink(
            name="jQuery.prepend",
            pattern=re.compile(r'\$\([^)]+\)\.prepend\s*\(', re.I),
            severity="high",
            description="jQuery DOM prepend",
            example="$(el).prepend(userInput)",
        ),
        DOMSink(
            name="insertAdjacentHTML",
            pattern=re.compile(r'\.insertAdjacentHTML\s*\(', re.I),
            severity="high",
            description="Adjacent HTML insertion",
            example="element.insertAdjacentHTML('beforeend', userInput)",
        ),
    ]

    # Sources of user-controlled input
    SOURCES: list[DOMSource] = [
        DOMSource(
            name="location.hash",
            pattern=re.compile(r'location\.hash', re.I),
            description="URL fragment",
        ),
        DOMSource(
            name="location.search",
            pattern=re.compile(r'location\.search', re.I),
            description="URL query string",
        ),
        DOMSource(
            name="location.href",
            pattern=re.compile(r'location\.href', re.I),
            description="Full URL",
        ),
        DOMSource(
            name="document.URL",
            pattern=re.compile(r'document\.URL', re.I),
            description="Document URL",
        ),
        DOMSource(
            name="document.documentURI",
            pattern=re.compile(r'document\.documentURI', re.I),
            description="Document URI",
        ),
        DOMSource(
            name="document.referrer",
            pattern=re.compile(r'document\.referrer', re.I),
            description="Referrer URL",
        ),
        DOMSource(
            name="document.cookie",
            pattern=re.compile(r'document\.cookie', re.I),
            description="Cookies",
        ),
        DOMSource(
            name="window.name",
            pattern=re.compile(r'window\.name', re.I),
            description="Window name",
        ),
        DOMSource(
            name="localStorage",
            pattern=re.compile(r'localStorage\.(getItem|get|\[)', re.I),
            description="Local storage",
        ),
        DOMSource(
            name="sessionStorage",
            pattern=re.compile(r'sessionStorage\.(getItem|get|\[)', re.I),
            description="Session storage",
        ),
        DOMSource(
            name="postMessage",
            pattern=re.compile(r'\.addEventListener\s*\(\s*[\'"]message[\'"]', re.I),
            description="postMessage handler",
        ),
        DOMSource(
            name="URLSearchParams",
            pattern=re.compile(r'URLSearchParams\s*\(', re.I),
            description="URL parameter parsing",
        ),
    ]

    def __init__(self, config: ScanConfig | None = None):
        self.config = config or ScanConfig()
        self._http_client: HTTPClient | None = None

    async def __aenter__(self):
        await self._init_client()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def _init_client(self):
        """Initialize HTTP client."""
        http_config = HTTPConfig(
            timeout=self.config.timeout,
            proxy=self.config.proxy,
            headers=self.config.custom_headers,
            cookies=self.config.cookies,
        )
        self._http_client = HTTPClient(http_config)
        await self._http_client._init_client()

    async def close(self):
        """Close HTTP client."""
        if self._http_client:
            await self._http_client.close()

    async def scan_url(self, url: str) -> list[XSSFinding]:
        """
        Scan a URL for DOM XSS vulnerabilities.

        This performs static analysis of JavaScript code.
        For dynamic analysis, use a headless browser.
        """
        if not self._http_client:
            await self._init_client()

        findings = []

        try:
            response = await self._http_client.get(url)
        except Exception:
            return findings

        # Extract all JavaScript code
        js_code = self._extract_javascript(response.body)

        # Analyze for DOM XSS patterns
        vulnerabilities = self._analyze_javascript(js_code)

        # Convert to findings
        for vuln in vulnerabilities:
            findings.append(XSSFinding(
                url=url,
                parameter=vuln.source,
                payload=f"<DOM XSS via {vuln.source} -> {vuln.sink}>",
                context=XSSContext.JAVASCRIPT_CODE,
                xss_type="dom",
                severity=vuln.severity,
                evidence=vuln.code_snippet,
                waf_detected=WAFType.NONE,
                waf_bypassed=False,
                confidence=vuln.confidence,
                remediation=(
                    f"Avoid using {vuln.sink} with user-controlled input. "
                    "Use textContent or innerText for text content. "
                    "Sanitize HTML with a trusted library like DOMPurify."
                ),
            ))

        return findings

    def _extract_javascript(self, html: str) -> str:
        """Extract all JavaScript code from HTML."""
        js_code = []

        # Inline scripts
        script_pattern = re.compile(
            r'<script[^>]*>(.*?)</script>',
            re.DOTALL | re.I
        )
        for match in script_pattern.finditer(html):
            # Skip external scripts
            script_tag = match.group(0)
            if 'src=' not in script_tag.lower():
                js_code.append(match.group(1))

        # Event handlers
        event_pattern = re.compile(
            r'on\w+\s*=\s*["\']([^"\']+)["\']',
            re.I
        )
        for match in event_pattern.finditer(html):
            js_code.append(match.group(1))

        # javascript: URLs
        js_url_pattern = re.compile(
            r'javascript:\s*([^"\']+)',
            re.I
        )
        for match in js_url_pattern.finditer(html):
            js_code.append(match.group(1))

        return '\n'.join(js_code)

    def _analyze_javascript(self, js_code: str) -> list[DOMVulnerability]:
        """Analyze JavaScript for DOM XSS patterns."""
        vulnerabilities = []
        lines = js_code.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Find sources in this line
            sources_found = []
            for source in self.SOURCES:
                if source.pattern.search(line):
                    sources_found.append(source.name)

            # Find sinks in this line
            for sink in self.SINKS:
                if sink.pattern.search(line):
                    # Check if any source flows to this sink
                    # This is a simplified check - real taint analysis would be more complex
                    for source_name in sources_found:
                        vulnerabilities.append(DOMVulnerability(
                            source=source_name,
                            sink=sink.name,
                            code_snippet=line.strip()[:200],
                            line_number=line_num,
                            severity=sink.severity,
                            confidence=0.7,  # Medium confidence for static analysis
                        ))

            # Also check for indirect patterns
            # e.g., var x = location.hash; ... innerHTML = x
            if not sources_found:
                # Check for common variable patterns that might contain user input
                for sink in self.SINKS:
                    if sink.pattern.search(line):
                        # Look for suspicious variable names
                        suspicious_vars = [
                            'input', 'param', 'query', 'hash', 'url', 'data',
                            'user', 'value', 'content', 'text', 'html'
                        ]
                        for var in suspicious_vars:
                            if re.search(rf'\b{var}\b', line, re.I):
                                vulnerabilities.append(DOMVulnerability(
                                    source=f"variable ({var})",
                                    sink=sink.name,
                                    code_snippet=line.strip()[:200],
                                    line_number=line_num,
                                    severity=sink.severity,
                                    confidence=0.4,  # Lower confidence
                                ))
                                break

        return vulnerabilities

    def get_dom_payloads(self, source_type: str = "hash") -> list[str]:
        """Get payloads optimized for DOM XSS testing."""
        base_payloads = [
            "#<img src=x onerror=alert(1)>",
            "#<svg onload=alert(1)>",
            "#javascript:alert(1)",
            "#\"><img src=x onerror=alert(1)>",
            "#'-alert(1)-'",
            "#\";alert(1)//",
        ]

        if source_type == "hash":
            return base_payloads
        elif source_type == "search":
            return [p.replace("#", "?test=") for p in base_payloads]
        else:
            return [p.lstrip("#") for p in base_payloads]


async def scan_for_dom_xss(
    url: str,
    config: ScanConfig | None = None,
) -> list[XSSFinding]:
    """Convenience function to scan for DOM XSS."""
    async with DOMXSSDetector(config) as detector:
        return await detector.scan_url(url)
