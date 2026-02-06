"""
Encoding utilities for XSS payloads.

Provides various encoding methods for WAF bypass and payload obfuscation.
"""

import html
import urllib.parse
from typing import Callable


class Encoder:
    """Handles various encoding schemes for XSS payloads."""

    @staticmethod
    def url_encode(payload: str, safe: str = "") -> str:
        """URL encode a payload."""
        return urllib.parse.quote(payload, safe=safe)

    @staticmethod
    def url_decode(payload: str) -> str:
        """URL decode a payload."""
        return urllib.parse.unquote(payload)

    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encode for bypassing filters."""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")

    @staticmethod
    def html_encode(payload: str) -> str:
        """HTML entity encode a payload."""
        return html.escape(payload)

    @staticmethod
    def html_decode(payload: str) -> str:
        """HTML entity decode a payload."""
        return html.unescape(payload)

    @staticmethod
    def hex_encode_html(payload: str) -> str:
        """Convert to HTML hex entities (&#xHH;)."""
        return "".join(f"&#x{ord(c):02x};" for c in payload)

    @staticmethod
    def decimal_encode_html(payload: str) -> str:
        """Convert to HTML decimal entities (&#DD;)."""
        return "".join(f"&#{ord(c)};" for c in payload)

    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Convert to JavaScript Unicode escapes (\\uHHHH)."""
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def hex_encode_js(payload: str) -> str:
        """Convert to JavaScript hex escapes (\\xHH)."""
        return "".join(f"\\x{ord(c):02x}" for c in payload)

    @staticmethod
    def mixed_case(payload: str) -> str:
        """Randomize case for WAF bypass."""
        import random
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)

    @staticmethod
    def insert_null_bytes(payload: str, position: str = "middle") -> str:
        """Insert null bytes for filter bypass."""
        if position == "middle":
            mid = len(payload) // 2
            return payload[:mid] + "%00" + payload[mid:]
        elif position == "start":
            return "%00" + payload
        else:
            return payload + "%00"

    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64 encode a payload."""
        import base64
        return base64.b64encode(payload.encode()).decode()

    @classmethod
    def get_all_encodings(cls, payload: str) -> dict[str, str]:
        """Get all encoding variants of a payload."""
        return {
            "original": payload,
            "url_encoded": cls.url_encode(payload),
            "double_url": cls.double_url_encode(payload),
            "html_encoded": cls.html_encode(payload),
            "hex_html": cls.hex_encode_html(payload),
            "decimal_html": cls.decimal_encode_html(payload),
            "unicode_js": cls.unicode_encode(payload),
            "hex_js": cls.hex_encode_js(payload),
            "mixed_case": cls.mixed_case(payload),
        }

    @classmethod
    def generate_bypass_variants(cls, payload: str) -> list[str]:
        """Generate multiple encoding variants for WAF bypass."""
        variants = [payload]

        # URL encoding variants
        variants.append(cls.url_encode(payload))
        variants.append(cls.double_url_encode(payload))

        # HTML entity variants
        variants.append(cls.html_encode(payload))
        variants.append(cls.hex_encode_html(payload))
        variants.append(cls.decimal_encode_html(payload))

        # JavaScript encoding
        variants.append(cls.unicode_encode(payload))

        # Mixed case
        variants.append(cls.mixed_case(payload))

        # Null byte insertion
        variants.append(cls.insert_null_bytes(payload))

        return list(set(variants))  # Remove duplicates
