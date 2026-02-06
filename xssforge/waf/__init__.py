"""WAF detection and bypass for XSSForge."""

from xssforge.waf.fingerprint import WAFDetector
from xssforge.waf.bypass import WAFBypass

__all__ = ["WAFDetector", "WAFBypass"]
