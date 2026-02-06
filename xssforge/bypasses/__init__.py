"""
Advanced XSS bypass techniques for XSSForge.

Includes:
- Filter evasion (encoding, case mixing, null bytes)
- CSP bypass (AngularJS, JSONP, base tag)
- DOM clobbering
- Mutation XSS (mXSS)
- DOMPurify bypasses
"""

from xssforge.bypasses.filters import FilterEvasion
from xssforge.bypasses.csp import CSPBypass
from xssforge.bypasses.dom_clobbering import DOMClobbering
from xssforge.bypasses.mxss import MutationXSS

__all__ = [
    "FilterEvasion",
    "CSPBypass",
    "DOMClobbering",
    "MutationXSS",
]
