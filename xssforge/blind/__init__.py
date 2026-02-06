"""
Blind XSS module for XSSForge.

Provides callback server and payload generation for blind XSS testing.
"""

from xssforge.blind.server import BlindXSSServer, CallbackResult
from xssforge.blind.payloads import BlindPayloadGenerator, get_blind_payload

__all__ = [
    "BlindXSSServer",
    "CallbackResult",
    "BlindPayloadGenerator",
    "get_blind_payload",
]
