"""
Reflected XSS detector for XSSForge.

Detects reflected XSS vulnerabilities by injecting payloads and analyzing responses.
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from xssforge.utils.http import HTTPClient, HTTPConfig, HTTPResponse
from xssforge.context import ContextAnalyzer, Reflection, XSSContext
from xssforge.payloads.generator import PayloadGenerator, PayloadConfig, FilteredChars
from xssforge.waf.fingerprint import WAFDetector, WAFType


@dataclass
class XSSFinding:
    """Represents a confirmed XSS vulnerability."""
    url: str
    parameter: str
    payload: str
    context: XSSContext
    xss_type: str = "reflected"
    severity: str = "high"
    evidence: str = ""
    waf_detected: WAFType = WAFType.NONE
    waf_bypassed: bool = False
    confidence: float = 1.0
    remediation: str = "Implement proper input validation and output encoding."
    raw_request: str = ""
    raw_response: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "context": self.context.value,
            "type": self.xss_type,
            "severity": self.severity,
            "evidence": self.evidence,
            "waf_detected": self.waf_detected.value,
            "waf_bypassed": self.waf_bypassed,
            "confidence": self.confidence,
            "remediation": self.remediation,
        }


@dataclass
class ScanConfig:
    """Configuration for XSS scanning."""
    follow_redirects: bool = True
    test_all_params: bool = True
    max_payloads_per_context: int = 30
    timeout: float = 30.0
    delay_between_requests: float = 0.0
    waf_bypass_mode: bool = True
    verify_execution: bool = False  # Requires browser
    custom_headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None


class ReflectedXSSDetector:
    """Detects reflected XSS vulnerabilities."""

    def __init__(self, config: ScanConfig | None = None):
        self.config = config or ScanConfig()
        self.context_analyzer = ContextAnalyzer()
        self.payload_generator = PayloadGenerator()
        self.waf_detector = WAFDetector()
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
            rate_limit=1.0 / max(self.config.delay_between_requests, 0.1) if self.config.delay_between_requests > 0 else 0,
        )
        self._http_client = HTTPClient(http_config)
        await self._http_client._init_client()

    async def close(self):
        """Close HTTP client."""
        if self._http_client:
            await self._http_client.close()

    async def scan_url(self, url: str) -> list[XSSFinding]:
        """Scan a URL for reflected XSS vulnerabilities."""
        if not self._http_client:
            await self._init_client()

        findings = []

        # Parse URL and extract parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            # No parameters to test
            return findings

        # Test each parameter
        for param_name in params:
            param_findings = await self._test_parameter(url, param_name)
            findings.extend(param_findings)

            if not self.config.test_all_params and findings:
                break  # Stop after first finding if not testing all

        return findings

    async def _test_parameter(self, url: str, param_name: str) -> list[XSSFinding]:
        """Test a single parameter for XSS."""
        findings = []

        # Step 1: Inject canary and analyze reflection
        canary = self.context_analyzer.generate_canary()
        canary_url = self._inject_param(url, param_name, canary)

        try:
            response = await self._http_client.get(canary_url)
        except Exception as e:
            return findings

        # Check for WAF
        waf_result = self.waf_detector.detect(
            response.status_code,
            response.headers,
            response.body,
        )

        # Analyze reflections
        analysis = self.context_analyzer.analyze(response.body, canary)

        if not analysis.reflections:
            return findings  # No reflection found

        # Step 2: Detect filters by testing special chars
        filters = await self._detect_filters(url, param_name, canary)

        # Step 3: Generate and test payloads for each reflection context
        for reflection in analysis.reflections:
            # Generate context-aware payloads
            payload_config = PayloadConfig(
                context=reflection.context,
                filters=filters,
                waf=waf_result.waf_type.value if waf_result.detected else None,
                auto_trigger_only=True,
                max_payloads=self.config.max_payloads_per_context,
                include_bypasses=self.config.waf_bypass_mode,
            )

            payloads = self.payload_generator.generate(payload_config)

            # Test payloads
            for payload in payloads:
                finding = await self._test_payload(
                    url, param_name, payload, reflection.context, waf_result.waf_type
                )
                if finding:
                    findings.append(finding)
                    break  # One finding per context is enough

        return findings

    async def _detect_filters(
        self, url: str, param_name: str, canary: str
    ) -> FilteredChars:
        """Detect which characters are being filtered."""
        filters = FilteredChars()
        test_chars = ['<', '>', '"', "'", '/', '(', ')', '=', '`']

        for char in test_chars:
            test_value = f"{canary}{char}test"
            test_url = self._inject_param(url, param_name, test_value)

            try:
                response = await self._http_client.get(test_url)
                if char not in response.body:
                    filters.blocked_chars.add(char)
                elif f"&lt;" in response.body and char == "<":
                    filters.encoded_chars["<"] = "&lt;"
                elif f"&gt;" in response.body and char == ">":
                    filters.encoded_chars[">"] = "&gt;"
                elif f"&quot;" in response.body and char == '"':
                    filters.encoded_chars['"'] = "&quot;"
            except Exception:
                pass

        # Test common blocked strings
        blocked_strings = ["script", "onerror", "onload", "javascript", "alert"]
        for string in blocked_strings:
            test_value = f"{canary}{string}test"
            test_url = self._inject_param(url, param_name, test_value)

            try:
                response = await self._http_client.get(test_url)
                if string not in response.body.lower():
                    filters.blocked_strings.add(string)
            except Exception:
                pass

        return filters

    async def _test_payload(
        self,
        url: str,
        param_name: str,
        payload: str,
        context: XSSContext,
        waf_type: WAFType,
    ) -> XSSFinding | None:
        """Test a single XSS payload."""
        test_url = self._inject_param(url, param_name, payload)

        try:
            response = await self._http_client.get(test_url)
        except Exception:
            return None

        # Check if payload is reflected unmodified
        if self._is_payload_reflected(payload, response.body):
            # Check if it looks executable
            if self._verify_executable(payload, response.body):
                evidence = self._extract_evidence(payload, response.body)

                return XSSFinding(
                    url=url,
                    parameter=param_name,
                    payload=payload,
                    context=context,
                    xss_type="reflected",
                    severity="high",
                    evidence=evidence,
                    waf_detected=waf_type,
                    waf_bypassed=waf_type != WAFType.NONE,
                    confidence=0.9,
                    raw_request=f"GET {test_url}",
                    raw_response=response.body[:1000],
                )

        return None

    def _inject_param(self, url: str, param_name: str, value: str) -> str:
        """Inject a value into a URL parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Replace the parameter value
        params[param_name] = [value]

        # Rebuild query string
        new_query = urlencode(params, doseq=True)
        new_parsed = parsed._replace(query=new_query)

        return urlunparse(new_parsed)

    def _is_payload_reflected(self, payload: str, body: str) -> bool:
        """Check if payload appears in response body."""
        # Check exact match
        if payload in body:
            return True

        # Check case-insensitive for tags
        if payload.lower() in body.lower():
            # Verify the case-insensitive match is actually exploitable
            return True

        return False

    def _verify_executable(self, payload: str, body: str) -> bool:
        """Verify the reflected payload appears executable."""
        # Find the payload in body
        payload_lower = payload.lower()
        body_lower = body.lower()

        if payload_lower not in body_lower:
            return False

        # Check it's not inside a text node that would escape it
        pos = body_lower.find(payload_lower)
        if pos == -1:
            return False

        # Get context around the payload
        context_start = max(0, pos - 100)
        context_end = min(len(body), pos + len(payload) + 100)
        context = body[context_start:context_end]

        # Check for signs it's executable
        # 1. Not inside a <textarea>, <title>, or similar
        non_exec_tags = ["<textarea", "<title", "<noscript", "<plaintext"]
        for tag in non_exec_tags:
            tag_pos = context.lower().rfind(tag)
            if tag_pos != -1:
                # Check if tag is closed before payload
                close_tag = f"</{tag[1:]}"
                if close_tag not in context[tag_pos:].lower():
                    return False

        # 2. Check payload structure is intact
        if "<" in payload and ">" in payload:
            # Tag-based payload
            if "<" in body[pos:pos+len(payload)] and ">" in body[pos:pos+len(payload)]:
                return True

        # 3. Check for event handlers
        event_pattern = r'on\w+\s*='
        if re.search(event_pattern, payload, re.I):
            if re.search(event_pattern, body[pos:pos+len(payload)+10], re.I):
                return True

        # 4. Check for javascript: protocol
        if "javascript:" in payload.lower():
            if "javascript:" in body[pos:pos+len(payload)+10].lower():
                return True

        return True  # Default to true if checks pass

    def _extract_evidence(self, payload: str, body: str, context_size: int = 200) -> str:
        """Extract evidence snippet showing the reflected payload."""
        pos = body.lower().find(payload.lower())
        if pos == -1:
            return ""

        start = max(0, pos - context_size // 2)
        end = min(len(body), pos + len(payload) + context_size // 2)

        snippet = body[start:end]

        # Highlight the payload
        snippet = snippet.replace(payload, f">>>{payload}<<<")

        return snippet


async def scan_for_reflected_xss(
    url: str,
    config: ScanConfig | None = None,
) -> list[XSSFinding]:
    """Convenience function to scan for reflected XSS."""
    async with ReflectedXSSDetector(config) as detector:
        return await detector.scan_url(url)
