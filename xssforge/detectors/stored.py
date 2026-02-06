"""
Stored XSS detector for XSSForge.

Detects stored/persistent XSS vulnerabilities.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from xssforge.utils.http import HTTPClient, HTTPConfig
from xssforge.context import ContextAnalyzer
from xssforge.payloads.generator import PayloadGenerator, PayloadConfig
from xssforge.detectors.reflected import XSSFinding, ScanConfig
from xssforge.waf.fingerprint import WAFType


@dataclass
class StoredXSSConfig(ScanConfig):
    """Configuration for stored XSS scanning."""
    submit_url: str = ""  # URL to submit payload
    submit_method: str = "POST"  # POST or GET
    submit_param: str = ""  # Parameter name for payload
    view_urls: list[str] = field(default_factory=list)  # URLs where payload renders
    form_data: dict[str, str] = field(default_factory=dict)  # Additional form data
    wait_time: float = 2.0  # Time to wait between submit and check


class StoredXSSDetector:
    """Detects stored XSS vulnerabilities."""

    def __init__(self, config: StoredXSSConfig | None = None):
        self.config = config or StoredXSSConfig()
        self.context_analyzer = ContextAnalyzer()
        self.payload_generator = PayloadGenerator()
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

    async def scan(
        self,
        submit_url: str,
        submit_param: str,
        view_urls: list[str],
        method: str = "POST",
        form_data: dict[str, str] | None = None,
    ) -> list[XSSFinding]:
        """
        Scan for stored XSS.

        Args:
            submit_url: URL where payload is submitted
            submit_param: Parameter name for the payload
            view_urls: URLs where the payload might be rendered
            method: HTTP method for submission
            form_data: Additional form data

        Returns:
            List of XSSFinding objects
        """
        if not self._http_client:
            await self._init_client()

        findings = []

        # Generate payloads - use a unique identifier to track
        base_payloads = self.payload_generator.quick_payloads()

        for i, payload in enumerate(base_payloads):
            # Create unique payload with tracker
            tracker = f"xssforge{i:03d}"
            tracked_payload = payload.replace("alert(1)", f"alert('{tracker}')")
            tracked_payload = tracked_payload.replace("alert`1`", f"alert`{tracker}`")

            # Submit payload
            submitted = await self._submit_payload(
                submit_url, submit_param, tracked_payload, method, form_data or {}
            )

            if not submitted:
                continue

            # Wait for processing
            await asyncio.sleep(self.config.wait_time)

            # Check view URLs for reflection
            for view_url in view_urls:
                finding = await self._check_reflection(
                    view_url, tracked_payload, submit_url, submit_param
                )
                if finding:
                    findings.append(finding)
                    break  # Found in one view URL is enough

            if findings:
                break  # Stop after first confirmed finding

        return findings

    async def _submit_payload(
        self,
        url: str,
        param: str,
        payload: str,
        method: str,
        form_data: dict[str, str],
    ) -> bool:
        """Submit payload to the target."""
        try:
            data = form_data.copy()
            data[param] = payload

            if method.upper() == "POST":
                response = await self._http_client.post(url, data=data)
            else:
                response = await self._http_client.get(url, params=data)

            # Check for success (not blocked)
            return response.status_code < 400

        except Exception:
            return False

    async def _check_reflection(
        self,
        view_url: str,
        payload: str,
        submit_url: str,
        submit_param: str,
    ) -> XSSFinding | None:
        """Check if payload is reflected in view URL."""
        try:
            response = await self._http_client.get(view_url)
        except Exception:
            return None

        # Check if payload appears in response
        if payload in response.body or payload.lower() in response.body.lower():
            # Analyze context
            canary = payload[:20]  # Use start of payload as identifier
            analysis = self.context_analyzer.analyze(response.body, canary)

            context = analysis.reflections[0].context if analysis.reflections else None

            # Extract evidence
            pos = response.body.lower().find(payload.lower())
            evidence = response.body[max(0, pos-100):pos+len(payload)+100] if pos != -1 else ""

            return XSSFinding(
                url=view_url,
                parameter=submit_param,
                payload=payload,
                context=context,
                xss_type="stored",
                severity="critical",  # Stored XSS is critical
                evidence=evidence,
                waf_detected=WAFType.NONE,
                waf_bypassed=False,
                confidence=0.95,
                remediation=(
                    "Implement proper input validation and output encoding. "
                    "Store data safely and encode when rendering."
                ),
            )

        return None

    async def scan_comment_form(
        self,
        form_url: str,
        view_url: str,
        comment_param: str = "comment",
        additional_params: dict[str, str] | None = None,
    ) -> list[XSSFinding]:
        """
        Convenience method to scan a typical comment form.

        Args:
            form_url: URL of the comment submission form
            view_url: URL where comments are displayed
            comment_param: Name of the comment parameter
            additional_params: Other required form fields

        Returns:
            List of XSSFinding objects
        """
        return await self.scan(
            submit_url=form_url,
            submit_param=comment_param,
            view_urls=[view_url],
            method="POST",
            form_data=additional_params,
        )


async def scan_for_stored_xss(
    submit_url: str,
    submit_param: str,
    view_urls: list[str],
    method: str = "POST",
    form_data: dict[str, str] | None = None,
    config: StoredXSSConfig | None = None,
) -> list[XSSFinding]:
    """Convenience function to scan for stored XSS."""
    async with StoredXSSDetector(config) as detector:
        return await detector.scan(
            submit_url, submit_param, view_urls, method, form_data
        )
