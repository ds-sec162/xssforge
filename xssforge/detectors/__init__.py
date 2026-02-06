"""XSS detection modules for XSSForge."""

from xssforge.detectors.reflected import ReflectedXSSDetector
from xssforge.detectors.stored import StoredXSSDetector
from xssforge.detectors.dom import DOMXSSDetector

__all__ = ["ReflectedXSSDetector", "StoredXSSDetector", "DOMXSSDetector"]
