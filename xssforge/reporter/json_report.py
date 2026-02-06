"""
JSON report generator for XSSForge.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from xssforge.detectors.reflected import XSSFinding


class JSONReporter:
    """Generates JSON reports for XSS findings."""

    def __init__(self, findings: list[XSSFinding]):
        self.findings = findings
        self.metadata: dict[str, Any] = {}

    def set_metadata(
        self,
        target: str = "",
        scan_time: float = 0.0,
        scan_type: str = "full",
        scanner_version: str = "1.0.0",
    ):
        """Set report metadata."""
        self.metadata = {
            "target": target,
            "scan_time_seconds": scan_time,
            "scan_type": scan_type,
            "scanner": "xssforge",
            "scanner_version": scanner_version,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "total_findings": len(self.findings),
        }

    def generate(self) -> dict[str, Any]:
        """Generate the JSON report structure."""
        # Calculate severity counts
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            severity = finding.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        return {
            "metadata": self.metadata,
            "summary": {
                "total_vulnerabilities": len(self.findings),
                "by_severity": severity_counts,
                "by_type": self._count_by_type(),
            },
            "findings": [self._finding_to_dict(f) for f in self.findings],
        }

    def _count_by_type(self) -> dict[str, int]:
        """Count findings by XSS type."""
        counts = {"reflected": 0, "stored": 0, "dom": 0}
        for finding in self.findings:
            xss_type = finding.xss_type.lower()
            if xss_type in counts:
                counts[xss_type] += 1
        return counts

    def _finding_to_dict(self, finding: XSSFinding) -> dict[str, Any]:
        """Convert finding to dictionary with additional fields."""
        return {
            "id": f"XSS-{hash(finding.url + finding.parameter + finding.payload) % 100000:05d}",
            "url": finding.url,
            "parameter": finding.parameter,
            "payload": finding.payload,
            "context": finding.context.value if finding.context else "unknown",
            "type": finding.xss_type,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "evidence": finding.evidence,
            "waf": {
                "detected": finding.waf_detected.value,
                "bypassed": finding.waf_bypassed,
            },
            "remediation": finding.remediation,
            "raw_request": finding.raw_request,
            "raw_response": finding.raw_response[:500] if finding.raw_response else "",
        }

    def to_json(self, indent: int = 2) -> str:
        """Generate JSON string."""
        return json.dumps(self.generate(), indent=indent, default=str)

    def save(self, filepath: str | Path):
        """Save report to file."""
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, "w") as f:
            f.write(self.to_json())


def generate_json_report(
    findings: list[XSSFinding],
    target: str = "",
    scan_time: float = 0.0,
) -> str:
    """Convenience function to generate JSON report."""
    reporter = JSONReporter(findings)
    reporter.set_metadata(target=target, scan_time=scan_time)
    return reporter.to_json()
