"""
Main XSS scanner for XSSForge.

Orchestrates all scanning components.
"""

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from xssforge.detectors.reflected import ReflectedXSSDetector, ScanConfig, XSSFinding
from xssforge.detectors.stored import StoredXSSDetector, StoredXSSConfig
from xssforge.detectors.dom import DOMXSSDetector
from xssforge.waf.fingerprint import WAFDetector
from xssforge.reporter.json_report import JSONReporter
from xssforge.reporter.html_report import HTMLReporter
from xssforge.reporter.markdown_report import MarkdownReporter


@dataclass
class XSSScanResult:
    """Result of an XSS scan."""
    target: str
    findings: list[XSSFinding]
    scan_time: float
    urls_scanned: int
    parameters_tested: int
    waf_detected: str | None = None


@dataclass
class XSSScannerConfig:
    """Configuration for the XSS scanner."""
    # HTTP settings
    timeout: float = 30.0
    delay: float = 0.0
    max_concurrent: int = 10
    proxy: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

    # Scan settings
    scan_reflected: bool = True
    scan_stored: bool = False
    scan_dom: bool = True
    waf_bypass_mode: bool = True
    max_payloads: int = 30
    follow_redirects: bool = True

    # Stored XSS settings (if enabled)
    stored_submit_url: str = ""
    stored_submit_param: str = ""
    stored_view_urls: list[str] = field(default_factory=list)

    # Output settings
    output_format: str = "json"  # json, html, markdown
    output_file: str | None = None
    verbose: bool = False


class XSSScanner:
    """Main XSS scanner that orchestrates all detection methods."""

    def __init__(self, config: XSSScannerConfig | None = None):
        self.config = config or XSSScannerConfig()
        self.findings: list[XSSFinding] = []
        self._on_finding: Callable[[XSSFinding], None] | None = None
        self._on_progress: Callable[[str, int, int], None] | None = None

    def on_finding(self, callback: Callable[[XSSFinding], None]):
        """Set callback for when a finding is discovered."""
        self._on_finding = callback

    def on_progress(self, callback: Callable[[str, int, int], None]):
        """Set callback for progress updates (message, current, total)."""
        self._on_progress = callback

    async def scan(self, targets: list[str]) -> XSSScanResult:
        """
        Scan multiple targets for XSS vulnerabilities.

        Args:
            targets: List of URLs to scan

        Returns:
            XSSScanResult with all findings
        """
        start_time = time.time()
        self.findings = []
        urls_scanned = 0
        params_tested = 0

        # Create scan config for detectors
        scan_config = ScanConfig(
            timeout=self.config.timeout,
            delay_between_requests=self.config.delay,
            proxy=self.config.proxy,
            custom_headers=self.config.headers,
            cookies=self.config.cookies,
            waf_bypass_mode=self.config.waf_bypass_mode,
            max_payloads_per_context=self.config.max_payloads,
            follow_redirects=self.config.follow_redirects,
        )

        # Process targets
        for i, target in enumerate(targets):
            if self._on_progress:
                self._on_progress(f"Scanning {target}", i + 1, len(targets))

            # Scan for reflected XSS
            if self.config.scan_reflected:
                async with ReflectedXSSDetector(scan_config) as detector:
                    findings = await detector.scan_url(target)
                    for finding in findings:
                        self.findings.append(finding)
                        if self._on_finding:
                            self._on_finding(finding)

            # Scan for DOM XSS
            if self.config.scan_dom:
                async with DOMXSSDetector(scan_config) as detector:
                    findings = await detector.scan_url(target)
                    for finding in findings:
                        self.findings.append(finding)
                        if self._on_finding:
                            self._on_finding(finding)

            urls_scanned += 1

        # Scan for stored XSS if configured
        if self.config.scan_stored and self.config.stored_submit_url:
            stored_config = StoredXSSConfig(
                timeout=self.config.timeout,
                proxy=self.config.proxy,
                custom_headers=self.config.headers,
                cookies=self.config.cookies,
            )
            async with StoredXSSDetector(stored_config) as detector:
                findings = await detector.scan(
                    submit_url=self.config.stored_submit_url,
                    submit_param=self.config.stored_submit_param,
                    view_urls=self.config.stored_view_urls,
                )
                for finding in findings:
                    self.findings.append(finding)
                    if self._on_finding:
                        self._on_finding(finding)

        scan_time = time.time() - start_time

        # Determine WAF if any was detected
        waf_detected = None
        for finding in self.findings:
            if finding.waf_detected.value != "none":
                waf_detected = finding.waf_detected.value
                break

        result = XSSScanResult(
            target=targets[0] if len(targets) == 1 else f"{len(targets)} targets",
            findings=self.findings,
            scan_time=scan_time,
            urls_scanned=urls_scanned,
            parameters_tested=params_tested,
            waf_detected=waf_detected,
        )

        # Generate report if output file specified
        if self.config.output_file:
            self._save_report(result)

        return result

    async def scan_url(self, url: str) -> XSSScanResult:
        """Scan a single URL."""
        return await self.scan([url])

    async def scan_file(self, filepath: str | Path) -> XSSScanResult:
        """Scan URLs from a file (one per line)."""
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        urls = []
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)

        return await self.scan(urls)

    def _save_report(self, result: XSSScanResult):
        """Save scan report to file."""
        output_file = Path(self.config.output_file)

        if self.config.output_format == "json":
            reporter = JSONReporter(result.findings)
            reporter.set_metadata(
                target=result.target,
                scan_time=result.scan_time,
            )
            reporter.save(output_file)

        elif self.config.output_format == "html":
            reporter = HTMLReporter(result.findings)
            reporter.set_metadata(
                target=result.target,
                scan_time=result.scan_time,
            )
            reporter.save(output_file)

        elif self.config.output_format == "markdown":
            reporter = MarkdownReporter(result.findings)
            reporter.set_metadata(
                target=result.target,
                scan_time=result.scan_time,
            )
            reporter.save(output_file)

    def get_json_report(self) -> str:
        """Get JSON report of current findings."""
        reporter = JSONReporter(self.findings)
        return reporter.to_json()

    def get_html_report(self) -> str:
        """Get HTML report of current findings."""
        reporter = HTMLReporter(self.findings)
        return reporter.generate()

    def get_markdown_report(self) -> str:
        """Get Markdown report of current findings."""
        reporter = MarkdownReporter(self.findings)
        return reporter.generate()


async def quick_scan(url: str, **kwargs) -> list[XSSFinding]:
    """Quick scan a URL for XSS vulnerabilities."""
    config = XSSScannerConfig(**kwargs)
    scanner = XSSScanner(config)
    result = await scanner.scan_url(url)
    return result.findings


def scan_sync(url: str, **kwargs) -> list[XSSFinding]:
    """Synchronous wrapper for quick_scan."""
    return asyncio.run(quick_scan(url, **kwargs))
