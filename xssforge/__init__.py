"""
XSSForge - Professional-grade XSS scanning tool.

A comprehensive cross-site scripting (XSS) vulnerability scanner with:
- Full PortSwigger XSS cheat sheet payload database
- Context-aware payload generation
- WAF detection and bypass
- Adaptive filter probing and payload generation
- Browser verification via Playwright
- Integrated blind XSS callback server
- CSP analysis and bypass
- Mutation XSS (mXSS) and sanitizer bypass
- DOM clobbering attacks
- Multiple output formats (JSON, HTML, Markdown)

Beats Dalfox by:
1. Headless browser verification (not just reflection detection)
2. Dynamic payload adaptation based on filter probing
3. Real DOM analysis with Playwright
4. Integrated blind XSS callback server
5. CSP-aware payload selection
6. Payloads that work in modern Chrome/Firefox
"""

__version__ = "2.1.0"
__author__ = "XSSForge Team"

# Core scanner
from xssforge.scanner import XSSScanner, XSSScannerConfig, XSSScanResult

# Adaptive scanner (the main power feature)
from xssforge.adaptive_scanner import (
    AdaptiveXSSScanner,
    AdaptiveScanConfig,
    VerifiedXSS,
    adaptive_scan,
    adaptive_scan_sync,
)

# Context analysis
from xssforge.context import ContextAnalyzer, XSSContext, ReflectionType

# Payload generation
from xssforge.payloads.generator import PayloadGenerator, PayloadConfig

# Game/challenge solver
from xssforge.game_solver import XSSGameSolver, GameLevel

# Bypass techniques
from xssforge.bypasses import FilterEvasion, CSPBypass, DOMClobbering, MutationXSS

# Hunter - the main tool
from xssforge.hunter import XSSHunter, HunterConfig, XSSVuln, hunt, hunt_many

__all__ = [
    # Core
    "XSSScanner",
    "XSSScannerConfig",
    "XSSScanResult",
    # Adaptive (main feature)
    "AdaptiveXSSScanner",
    "AdaptiveScanConfig",
    "VerifiedXSS",
    "adaptive_scan",
    "adaptive_scan_sync",
    # Context
    "ContextAnalyzer",
    "XSSContext",
    "ReflectionType",
    # Payloads
    "PayloadGenerator",
    "PayloadConfig",
    # Game solver
    "XSSGameSolver",
    "GameLevel",
    # Bypasses
    "FilterEvasion",
    "CSPBypass",
    "DOMClobbering",
    "MutationXSS",
    # Hunter - THE MAIN TOOL
    "XSSHunter",
    "HunterConfig",
    "XSSVuln",
    "hunt",
    "hunt_many",
    # Meta
    "__version__",
]
