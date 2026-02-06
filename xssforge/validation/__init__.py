"""
XSSForge Validation Framework

Real-world validation against known vulnerable targets:
- Google Firing Range
- DVWA (all security levels)
- sudo.co.il XSS challenges
- PortSwigger labs
- prompt.ml challenges

Tracks: True Positives, False Positives, False Negatives
Compares against Dalfox for side-by-side benchmarking
"""

from .firing_range import FiringRangeValidator
from .dvwa import DVWAValidator
from .sudo_xss import SudoXSSValidator
from .benchmark import BenchmarkRunner, BenchmarkResult

__all__ = [
    "FiringRangeValidator",
    "DVWAValidator",
    "SudoXSSValidator",
    "BenchmarkRunner",
    "BenchmarkResult",
]
