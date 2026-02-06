"""
HTML report generator for XSSForge.

Generates professional pentest-style HTML reports.
"""

import html
from datetime import datetime
from pathlib import Path
from typing import Any

from xssforge.detectors.reflected import XSSFinding


def get_html_template() -> str:
    """Return the HTML template with proper escaping."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSSForge Security Report</title>
    <style>
        :root {{
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --bg-card: #0f3460;
            --text-primary: #eaeaea;
            --text-secondary: #a0a0a0;
            --accent: #e94560;
            --success: #00d26a;
            --warning: #ffc107;
            --info: #17a2b8;
            --critical: #dc3545;
            --high: #e94560;
            --medium: #ffc107;
            --low: #17a2b8;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}

        header {{
            background: var(--bg-secondary);
            padding: 30px 0;
            border-bottom: 3px solid var(--accent);
        }}

        header h1 {{
            font-size: 2.5rem;
            color: var(--accent);
        }}

        header p {{
            color: var(--text-secondary);
            margin-top: 10px;
        }}

        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}

        .summary-card {{
            background: var(--bg-card);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }}

        .summary-card h3 {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
        }}

        .summary-card .number {{
            font-size: 2.5rem;
            font-weight: bold;
            margin: 10px 0;
        }}

        .severity-critical {{ color: var(--critical); }}
        .severity-high {{ color: var(--high); }}
        .severity-medium {{ color: var(--medium); }}
        .severity-low {{ color: var(--low); }}

        .findings {{
            margin-top: 40px;
        }}

        .finding {{
            background: var(--bg-secondary);
            border-radius: 10px;
            margin-bottom: 20px;
            overflow: hidden;
            border-left: 4px solid var(--accent);
        }}

        .finding-header {{
            background: var(--bg-card);
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .finding-header h3 {{
            font-size: 1.1rem;
        }}

        .badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
        }}

        .badge-critical {{ background: var(--critical); }}
        .badge-high {{ background: var(--high); }}
        .badge-medium {{ background: var(--medium); color: #000; }}
        .badge-low {{ background: var(--low); }}

        .finding-body {{
            padding: 20px;
        }}

        .finding-row {{
            display: grid;
            grid-template-columns: 150px 1fr;
            gap: 10px;
            margin-bottom: 15px;
        }}

        .finding-label {{
            color: var(--text-secondary);
            font-weight: bold;
        }}

        .finding-value {{
            word-break: break-all;
        }}

        .payload {{
            background: #000;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
            color: #0f0;
        }}

        .evidence {{
            background: #1a1a1a;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
            white-space: pre-wrap;
            font-size: 0.85rem;
        }}

        .remediation {{
            background: rgba(0, 210, 106, 0.1);
            border: 1px solid var(--success);
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
        }}

        .type-badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 3px;
            font-size: 0.75rem;
            margin-left: 10px;
        }}

        .type-reflected {{ background: #6c5ce7; }}
        .type-stored {{ background: #d63031; }}
        .type-dom {{ background: #00b894; }}

        footer {{
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            border-top: 1px solid var(--bg-card);
            margin-top: 40px;
        }}

        @media (max-width: 768px) {{
            .finding-row {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>XSSForge Security Report</h1>
            <p>Generated on {timestamp}</p>
            <p>Target: {target}</p>
        </div>
    </header>

    <main class="container">
        <section class="summary">
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="number">{total_findings}</div>
            </div>
            <div class="summary-card">
                <h3>Critical</h3>
                <div class="number severity-critical">{critical_count}</div>
            </div>
            <div class="summary-card">
                <h3>High</h3>
                <div class="number severity-high">{high_count}</div>
            </div>
            <div class="summary-card">
                <h3>Medium</h3>
                <div class="number severity-medium">{medium_count}</div>
            </div>
            <div class="summary-card">
                <h3>Low</h3>
                <div class="number severity-low">{low_count}</div>
            </div>
        </section>

        <section class="findings">
            <h2>Vulnerability Details</h2>
            {findings_html}
        </section>
    </main>

    <footer>
        <p>Generated by XSSForge v1.0.0</p>
        <p>Professional XSS Scanner</p>
    </footer>
</body>
</html>
"""


def get_finding_template() -> str:
    """Return the finding template."""
    return """
<div class="finding">
    <div class="finding-header">
        <h3>
            {finding_id}
            <span class="type-badge type-{xss_type}">{xss_type}</span>
        </h3>
        <span class="badge badge-{severity}">{severity}</span>
    </div>
    <div class="finding-body">
        <div class="finding-row">
            <span class="finding-label">URL:</span>
            <span class="finding-value">{url}</span>
        </div>
        <div class="finding-row">
            <span class="finding-label">Parameter:</span>
            <span class="finding-value">{parameter}</span>
        </div>
        <div class="finding-row">
            <span class="finding-label">Context:</span>
            <span class="finding-value">{context}</span>
        </div>
        <div class="finding-row">
            <span class="finding-label">Confidence:</span>
            <span class="finding-value">{confidence}%</span>
        </div>
        <div class="finding-row">
            <span class="finding-label">WAF Detected:</span>
            <span class="finding-value">{waf_info}</span>
        </div>
        <div class="finding-row">
            <span class="finding-label">Payload:</span>
            <div class="payload">{payload}</div>
        </div>
        {evidence_section}
        <div class="remediation">
            <strong>Remediation:</strong> {remediation}
        </div>
    </div>
</div>
"""


class HTMLReporter:
    """Generates HTML reports for XSS findings."""

    def __init__(self, findings: list[XSSFinding]):
        self.findings = findings
        self.target = ""
        self.scan_time = 0.0

    def set_metadata(self, target: str = "", scan_time: float = 0.0):
        """Set report metadata."""
        self.target = target
        self.scan_time = scan_time

    def generate(self) -> str:
        """Generate the HTML report."""
        # Count severities
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            severity = finding.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Generate findings HTML
        findings_html = ""
        for i, finding in enumerate(self.findings, 1):
            findings_html += self._render_finding(finding, i)

        # Render template
        return get_html_template().format(
            timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            target=html.escape(self.target) or "Multiple targets",
            total_findings=len(self.findings),
            critical_count=severity_counts["critical"],
            high_count=severity_counts["high"],
            medium_count=severity_counts["medium"],
            low_count=severity_counts["low"],
            findings_html=findings_html,
        )

    def _render_finding(self, finding: XSSFinding, index: int) -> str:
        """Render a single finding to HTML."""
        # Evidence section
        evidence_section = ""
        if finding.evidence:
            evidence_section = f"""
            <div class="finding-row">
                <span class="finding-label">Evidence:</span>
                <div class="evidence">{html.escape(finding.evidence)}</div>
            </div>
            """

        # WAF info
        waf_info = finding.waf_detected.value
        if finding.waf_bypassed:
            waf_info += " (bypassed)"

        return get_finding_template().format(
            finding_id=f"XSS-{index:03d}",
            xss_type=finding.xss_type,
            severity=finding.severity.lower(),
            url=html.escape(finding.url),
            parameter=html.escape(finding.parameter),
            context=finding.context.value if finding.context else "unknown",
            confidence=int(finding.confidence * 100),
            waf_info=waf_info,
            payload=html.escape(finding.payload),
            evidence_section=evidence_section,
            remediation=html.escape(finding.remediation),
        )

    def save(self, filepath: str | Path):
        """Save report to file."""
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, "w") as f:
            f.write(self.generate())


def generate_html_report(
    findings: list[XSSFinding],
    target: str = "",
    scan_time: float = 0.0,
) -> str:
    """Convenience function to generate HTML report."""
    reporter = HTMLReporter(findings)
    reporter.set_metadata(target=target, scan_time=scan_time)
    return reporter.generate()
