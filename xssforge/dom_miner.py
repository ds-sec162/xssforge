#!/usr/bin/env python3
"""
XSSForge DOM Parameter Mining Module

Discovers hidden parameters through:
- HTML form analysis
- JavaScript source analysis
- URL pattern extraction
- Common parameter dictionary attack
- DOM sink/source analysis for DOM XSS

This addresses Dalfox's --mining-dom feature.
"""

import re
from dataclasses import dataclass, field
from typing import Optional
from bs4 import BeautifulSoup


@dataclass
class MinedParameter:
    """Discovered parameter."""
    name: str
    source: str  # form, js, url, dict, dom
    context: str = ""  # Additional context
    confidence: str = "medium"  # low, medium, high


@dataclass
class DOMFlow:
    """DOM XSS taint flow (source -> sink)."""
    source: str
    sink: str
    code_snippet: str
    dangerous: bool = True


# ============================================================================
# Common Parameter Wordlist (GF-Patterns style)
# ============================================================================

COMMON_PARAMS = [
    # XSS-prone parameters
    "q", "s", "search", "query", "keyword", "id", "page", "name",
    "url", "uri", "path", "redirect", "return", "returnUrl", "return_url",
    "next", "goto", "dest", "destination", "redir", "redirect_uri",
    "callback", "cb", "jsonp", "html", "text", "content", "body",
    "msg", "message", "error", "err", "title", "subject", "data",
    "input", "output", "out", "result", "value", "val", "param",
    "file", "filename", "filepath", "path", "folder", "dir",
    "template", "tpl", "view", "action", "do", "func", "function",
    "lang", "language", "locale", "ref", "referer", "referrer",
    "src", "source", "target", "to", "from", "email", "user",
    "username", "login", "password", "pass", "pwd", "token",
    "key", "api", "apikey", "api_key", "secret", "auth",
    "sort", "order", "orderby", "sortby", "filter", "type", "category",
    "cat", "tag", "tags", "format", "style", "theme", "mode",
    "debug", "test", "dev", "preview", "draft", "version", "v",
    "year", "month", "day", "date", "time", "start", "end",
    "limit", "offset", "count", "num", "number", "size", "width", "height",
    "x", "y", "z", "lat", "lng", "lon", "location", "address",
    "phone", "tel", "mobile", "fax", "zip", "postal", "country", "city",
    "state", "region", "area", "domain", "host", "port", "server",
    "client", "session", "sid", "ssid", "cookie", "csrf", "nonce",
    "hash", "checksum", "signature", "sign", "verify", "confirm",
    "captcha", "code", "otp", "pin", "answer", "response", "reply",
    "comment", "review", "rating", "score", "rank", "level", "grade",
    "status", "state", "active", "enabled", "disabled", "hidden", "visible",
    "public", "private", "admin", "root", "super", "moderator", "mod",
    "role", "permission", "access", "allow", "deny", "grant", "revoke",
    "include", "require", "import", "load", "fetch", "get", "post",
    "put", "delete", "patch", "update", "create", "new", "add", "edit",
    "modify", "change", "remove", "drop", "clear", "reset", "init",
    "config", "setting", "option", "preference", "pref", "env",
    "log", "trace", "dump", "export", "download", "upload", "attach",
    "image", "img", "photo", "pic", "picture", "icon", "avatar", "logo",
    "video", "audio", "media", "document", "doc", "pdf", "report",
    # API-specific
    "fields", "select", "include", "exclude", "expand", "embed",
    "populate", "join", "with", "without", "only", "except",
    "where", "having", "group", "aggregate", "sum", "avg", "min", "max",
]

# ============================================================================
# DOM XSS Sources and Sinks
# ============================================================================

# Sources - where attacker input enters
DOM_SOURCES = [
    "document.URL",
    "document.documentURI",
    "document.URLUnencoded",
    "document.baseURI",
    "document.referrer",
    "document.cookie",
    "document.domain",
    "location",
    "location.href",
    "location.search",
    "location.hash",
    "location.pathname",
    "location.origin",
    "window.name",
    "window.location",
    "history.pushState",
    "history.replaceState",
    "localStorage",
    "sessionStorage",
    "IndexedDB",
    "XMLHttpRequest",
    "fetch",
    "WebSocket",
    "postMessage",
]

# Sinks - where code execution occurs
DOM_SINKS = {
    "critical": [
        "eval(",
        "Function(",
        "setTimeout(",
        "setInterval(",
        "setImmediate(",
        "execScript(",
        "crypto.generateCRMFRequest(",
        "ScriptElement.src",
        "ScriptElement.text",
        "ScriptElement.textContent",
        "ScriptElement.innerText",
    ],
    "high": [
        ".innerHTML",
        ".outerHTML",
        "document.write(",
        "document.writeln(",
        "DOMParser.parseFromString(",
        "Range.createContextualFragment(",
        ".insertAdjacentHTML(",
    ],
    "medium": [
        ".src",
        ".href",
        ".action",
        ".formAction",
        ".data",
        ".location",
        ".open(",
        "anchor.href",
        "area.href",
        "form.action",
        "input.formAction",
        "button.formAction",
        "embed.src",
        "object.data",
        "frame.src",
        "iframe.src",
        "iframe.srcdoc",
        "link.href",
        "base.href",
        "image.src",
        "video.src",
        "audio.src",
        "source.src",
        "track.src",
        "script.src",
    ],
    "low": [
        ".textContent",
        ".innerText",
        ".value",
        ".className",
        ".setAttribute(",
        ".style",
        "element.style.cssText",
    ],
}


# ============================================================================
# Parameter Mining Class
# ============================================================================

class DOMMiner:
    """
    Mine parameters from HTML and JavaScript.

    Features:
    - Form parameter extraction
    - JavaScript variable/parameter detection
    - URL pattern analysis
    - DOM sink/source analysis
    - Dictionary-based parameter discovery
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.discovered_params: list[MinedParameter] = []
        self.dom_flows: list[DOMFlow] = []

    def mine_html(self, html: str) -> list[MinedParameter]:
        """Extract parameters from HTML forms and links."""
        params = []

        try:
            soup = BeautifulSoup(html, "lxml")
        except:
            try:
                soup = BeautifulSoup(html, "html.parser")
            except:
                return params

        # Mine form inputs
        for form in soup.find_all("form"):
            form_action = form.get("action", "")
            for inp in form.find_all(["input", "select", "textarea"]):
                name = inp.get("name") or inp.get("id")
                if name:
                    params.append(MinedParameter(
                        name=name,
                        source="form",
                        context=f"form action={form_action[:50]}",
                        confidence="high",
                    ))

        # Mine links with query parameters
        for link in soup.find_all("a", href=True):
            href = link.get("href", "")
            if "?" in href:
                query = href.split("?", 1)[1].split("#")[0]
                for part in query.split("&"):
                    if "=" in part:
                        name = part.split("=")[0]
                        if name and not name.startswith("utm_"):
                            params.append(MinedParameter(
                                name=name,
                                source="url",
                                context=f"link href",
                                confidence="medium",
                            ))

        # Mine data attributes
        for elem in soup.find_all(attrs={"data-param": True}):
            params.append(MinedParameter(
                name=elem.get("data-param"),
                source="data-attr",
                confidence="medium",
            ))

        # Mine hidden inputs specifically (often contain CSRF or state)
        for hidden in soup.find_all("input", type="hidden"):
            name = hidden.get("name")
            if name:
                params.append(MinedParameter(
                    name=name,
                    source="hidden-input",
                    confidence="high",
                ))

        return self._deduplicate(params)

    def mine_javascript(self, js_content: str) -> list[MinedParameter]:
        """Extract parameters from JavaScript code."""
        params = []

        # URL parameter patterns
        url_param_patterns = [
            r'[?&](\w+)=',  # ?param= or &param=
            r'getParameter\(["\'](\w+)["\']',  # getParameter('param')
            r'URLSearchParams.*get\(["\'](\w+)["\']',  # URLSearchParams.get('param')
            r'params\[["\'](\w+)["\']',  # params['param']
            r'query\[["\'](\w+)["\']',  # query['param']
            r'req\.query\.(\w+)',  # req.query.param
            r'req\.params\.(\w+)',  # req.params.param
            r'request\.getParameter\(["\'](\w+)["\']',  # Java style
            r'\$_GET\[["\'](\w+)["\']',  # PHP style
            r'\$_POST\[["\'](\w+)["\']',  # PHP style
            r'\$_REQUEST\[["\'](\w+)["\']',  # PHP style
        ]

        for pattern in url_param_patterns:
            for match in re.finditer(pattern, js_content):
                name = match.group(1)
                if len(name) > 1 and len(name) < 50:
                    params.append(MinedParameter(
                        name=name,
                        source="javascript",
                        context=f"pattern: {pattern[:30]}",
                        confidence="medium",
                    ))

        # Object property patterns (potential API params)
        object_patterns = [
            r'{\s*(\w+)\s*:',  # { param:
            r',\s*(\w+)\s*:',  # , param:
            r'\.(\w+)\s*=',  # .param =
        ]

        for pattern in object_patterns:
            for match in re.finditer(pattern, js_content):
                name = match.group(1)
                # Filter out common non-params
                skip_names = {"function", "return", "if", "else", "for", "while",
                             "var", "let", "const", "class", "true", "false", "null",
                             "undefined", "this", "new", "try", "catch", "finally"}
                if name.lower() not in skip_names and len(name) > 1 and len(name) < 30:
                    params.append(MinedParameter(
                        name=name,
                        source="javascript",
                        context="object property",
                        confidence="low",
                    ))

        return self._deduplicate(params)

    def find_dom_flows(self, js_content: str) -> list[DOMFlow]:
        """Find potential DOM XSS flows (source -> sink)."""
        flows = []

        # Find all sources used
        used_sources = []
        for source in DOM_SOURCES:
            if source in js_content:
                used_sources.append(source)

        # Find all sinks and check for flows
        for severity, sinks in DOM_SINKS.items():
            for sink in sinks:
                if sink in js_content:
                    # Look for code context around the sink
                    for match in re.finditer(re.escape(sink), js_content):
                        start = max(0, match.start() - 100)
                        end = min(len(js_content), match.end() + 100)
                        context = js_content[start:end]

                        # Check if any source is near this sink
                        for source in used_sources:
                            if source in context:
                                flows.append(DOMFlow(
                                    source=source,
                                    sink=sink,
                                    code_snippet=context[:200],
                                    dangerous=severity in ("critical", "high"),
                                ))

        self.dom_flows = flows
        return flows

    def mine_from_url(self, url: str) -> list[MinedParameter]:
        """Extract existing parameters from URL."""
        params = []

        if "?" not in url:
            return params

        query = url.split("?", 1)[1].split("#")[0]
        for part in query.split("&"):
            if "=" in part:
                name = part.split("=")[0]
                if name:
                    params.append(MinedParameter(
                        name=name,
                        source="url",
                        context="existing param",
                        confidence="high",
                    ))

        return params

    def get_common_params(self, limit: int = 50) -> list[MinedParameter]:
        """Get common parameters from wordlist."""
        return [
            MinedParameter(
                name=param,
                source="dictionary",
                confidence="low",
            )
            for param in COMMON_PARAMS[:limit]
        ]

    async def mine_all(self, client, url: str) -> tuple[list[MinedParameter], list[DOMFlow]]:
        """
        Comprehensive parameter mining.

        1. Fetch the page
        2. Mine HTML forms and links
        3. Mine inline JavaScript
        4. Mine external JavaScript files
        5. Find DOM XSS flows
        """
        params = []
        flows = []

        try:
            # Fetch main page
            r = await client.get(url)
            html = r.text

            # Mine HTML
            params.extend(self.mine_html(html))

            # Mine inline JS
            soup = BeautifulSoup(html, "lxml")
            for script in soup.find_all("script"):
                if script.string:
                    params.extend(self.mine_javascript(script.string))
                    flows.extend(self.find_dom_flows(script.string))

            # Mine external JS files
            for script in soup.find_all("script", src=True):
                js_url = script.get("src")
                if js_url:
                    # Make absolute URL
                    if js_url.startswith("//"):
                        js_url = "https:" + js_url
                    elif js_url.startswith("/"):
                        from urllib.parse import urlparse
                        parsed = urlparse(url)
                        js_url = f"{parsed.scheme}://{parsed.netloc}{js_url}"
                    elif not js_url.startswith("http"):
                        continue  # Skip relative URLs for now

                    try:
                        js_r = await client.get(js_url, timeout=5.0)
                        if js_r.status_code == 200:
                            params.extend(self.mine_javascript(js_r.text))
                            flows.extend(self.find_dom_flows(js_r.text))
                    except:
                        pass

            # Mine existing URL params
            params.extend(self.mine_from_url(url))

        except Exception as e:
            if self.verbose:
                print(f"[DOM-MINER] Error: {e}")

        self.discovered_params = self._deduplicate(params)
        self.dom_flows = flows

        return self.discovered_params, self.dom_flows

    def _deduplicate(self, params: list[MinedParameter]) -> list[MinedParameter]:
        """Remove duplicate parameters, keeping highest confidence."""
        seen = {}
        for p in params:
            if p.name not in seen:
                seen[p.name] = p
            else:
                # Keep higher confidence
                conf_order = {"high": 3, "medium": 2, "low": 1}
                if conf_order.get(p.confidence, 0) > conf_order.get(seen[p.name].confidence, 0):
                    seen[p.name] = p

        return list(seen.values())


# Convenience function
async def mine_parameters(client, url: str, include_common: bool = True) -> list[str]:
    """Quick parameter mining - returns just the parameter names."""
    miner = DOMMiner()
    params, _ = await miner.mine_all(client, url)

    if include_common:
        params.extend(miner.get_common_params(30))

    return list(set(p.name for p in params))
