#!/usr/bin/env python3
"""
XSSForge Remote Payload Fetching Module

Fetches payloads from external sources:
- PortSwigger XSS Cheat Sheet
- PayloadBox XSS Payload List
- Custom remote URLs

This addresses Dalfox's --remote-payloads feature.
"""

import re
import json
import asyncio
from typing import Optional
from pathlib import Path
from datetime import datetime, timedelta


# ============================================================================
# Remote Payload Sources
# ============================================================================

REMOTE_SOURCES = {
    "portswigger": {
        "url": "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet",
        "type": "html",
        "description": "PortSwigger XSS Cheat Sheet - high quality, browser-tested payloads",
    },
    "payloadbox": {
        "url": "https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt",
        "type": "text",
        "description": "PayloadBox XSS Payload List - large collection",
    },
    "payloadallthethings": {
        "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/IntrudersXSS.txt",
        "type": "text",
        "description": "PayloadsAllTheThings XSS Intruder list",
    },
    "seclist_xss": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt",
        "type": "text",
        "description": "SecLists XSS-Jhaddix fuzzing list",
    },
}


# ============================================================================
# Payload Cache
# ============================================================================

class PayloadCache:
    """Cache remote payloads to disk for offline use."""

    def __init__(self, cache_dir: Optional[Path] = None):
        if cache_dir is None:
            cache_dir = Path.home() / ".xssforge" / "cache"
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "remote_payloads.json"
        self.cache_ttl = timedelta(days=7)  # Refresh weekly

    def get(self, source: str) -> Optional[list[str]]:
        """Get cached payloads for source."""
        if not self.cache_file.exists():
            return None

        try:
            with open(self.cache_file) as f:
                cache = json.load(f)

            if source not in cache:
                return None

            # Check TTL
            cached_at = datetime.fromisoformat(cache[source].get("timestamp", "2000-01-01"))
            if datetime.now() - cached_at > self.cache_ttl:
                return None

            return cache[source].get("payloads", [])
        except:
            return None

    def set(self, source: str, payloads: list[str]):
        """Cache payloads for source."""
        cache = {}
        if self.cache_file.exists():
            try:
                with open(self.cache_file) as f:
                    cache = json.load(f)
            except:
                pass

        cache[source] = {
            "payloads": payloads,
            "timestamp": datetime.now().isoformat(),
            "count": len(payloads),
        }

        with open(self.cache_file, "w") as f:
            json.dump(cache, f, indent=2)

    def clear(self):
        """Clear all cached payloads."""
        if self.cache_file.exists():
            self.cache_file.unlink()


# ============================================================================
# Payload Fetcher
# ============================================================================

class RemotePayloadFetcher:
    """
    Fetch XSS payloads from remote sources.

    Supports:
    - PortSwigger XSS Cheat Sheet (HTML parsing)
    - GitHub raw text files
    - Custom URLs

    Usage:
        fetcher = RemotePayloadFetcher()
        payloads = await fetcher.fetch("portswigger")
        payloads = await fetcher.fetch_all()
    """

    def __init__(self, use_cache: bool = True, verbose: bool = False):
        self.use_cache = use_cache
        self.verbose = verbose
        self.cache = PayloadCache()

    async def fetch(self, source: str, client=None) -> list[str]:
        """Fetch payloads from a specific source."""
        # Check cache first
        if self.use_cache:
            cached = self.cache.get(source)
            if cached:
                if self.verbose:
                    print(f"[REMOTE] Using cached payloads for {source} ({len(cached)} payloads)")
                return cached

        # Get source config
        if source not in REMOTE_SOURCES:
            if self.verbose:
                print(f"[REMOTE] Unknown source: {source}")
            return []

        config = REMOTE_SOURCES[source]
        url = config["url"]

        if self.verbose:
            print(f"[REMOTE] Fetching from {source}: {url}")

        payloads = []
        close_client = False

        try:
            if client is None:
                import httpx
                client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)
                close_client = True

            r = await client.get(url)

            if r.status_code == 200:
                if config["type"] == "html":
                    payloads = self._parse_html(r.text, source)
                else:
                    payloads = self._parse_text(r.text)

                # Cache the results
                if self.use_cache and payloads:
                    self.cache.set(source, payloads)

                if self.verbose:
                    print(f"[REMOTE] Fetched {len(payloads)} payloads from {source}")

        except Exception as e:
            if self.verbose:
                print(f"[REMOTE] Error fetching {source}: {e}")
        finally:
            if close_client:
                await client.aclose()

        return payloads

    async def fetch_all(self, sources: list[str] = None, client=None) -> list[str]:
        """Fetch from all sources and combine."""
        if sources is None:
            sources = list(REMOTE_SOURCES.keys())

        all_payloads = []
        for source in sources:
            payloads = await self.fetch(source, client)
            all_payloads.extend(payloads)

        # Deduplicate
        return list(set(all_payloads))

    async def fetch_custom(self, url: str, client=None) -> list[str]:
        """Fetch from a custom URL (text format, one payload per line)."""
        payloads = []
        close_client = False

        try:
            if client is None:
                import httpx
                client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)
                close_client = True

            r = await client.get(url)
            if r.status_code == 200:
                payloads = self._parse_text(r.text)

        except Exception as e:
            if self.verbose:
                print(f"[REMOTE] Error fetching custom URL: {e}")
        finally:
            if close_client:
                await client.aclose()

        return payloads

    def _parse_html(self, html: str, source: str) -> list[str]:
        """Parse payloads from HTML (source-specific)."""
        payloads = []

        if source == "portswigger":
            # PortSwigger uses <td class="copy-to-clipboard"> for payloads
            # Pattern: data-clipboard-text="payload"
            pattern = r'data-clipboard-text="([^"]+)"'
            for match in re.finditer(pattern, html):
                payload = match.group(1)
                # Decode HTML entities
                payload = self._decode_html_entities(payload)
                if payload and "<" in payload or "javascript:" in payload.lower():
                    payloads.append(payload)

            # Also try code/pre blocks
            code_pattern = r'<code[^>]*>([^<]+)</code>'
            for match in re.finditer(code_pattern, html):
                payload = self._decode_html_entities(match.group(1))
                if payload and "<" in payload:
                    payloads.append(payload)

        return list(set(payloads))

    def _parse_text(self, text: str) -> list[str]:
        """Parse payloads from text (one per line)."""
        payloads = []
        for line in text.split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                # Basic validation - should look like XSS
                if any(c in line for c in ["<", ">", "javascript:", "on", "="]):
                    payloads.append(line)
        return payloads

    def _decode_html_entities(self, text: str) -> str:
        """Decode HTML entities."""
        import html
        return html.unescape(text)


# ============================================================================
# Convenience Functions
# ============================================================================

async def fetch_remote_payloads(
    sources: list[str] = None,
    use_cache: bool = True,
    verbose: bool = False
) -> list[str]:
    """
    Quick function to fetch remote payloads.

    Args:
        sources: List of source names (portswigger, payloadbox, etc.)
                 Use None for all sources.
        use_cache: Whether to use/update local cache
        verbose: Print status messages

    Returns:
        List of XSS payloads
    """
    fetcher = RemotePayloadFetcher(use_cache=use_cache, verbose=verbose)
    return await fetcher.fetch_all(sources)


def get_available_sources() -> dict:
    """Get information about available remote sources."""
    return {
        name: {
            "url": config["url"],
            "description": config["description"],
        }
        for name, config in REMOTE_SOURCES.items()
    }


def clear_cache():
    """Clear the payload cache."""
    cache = PayloadCache()
    cache.clear()


# ============================================================================
# CLI for testing
# ============================================================================

if __name__ == "__main__":
    import sys

    async def main():
        print("Available sources:")
        for name, info in get_available_sources().items():
            print(f"  {name}: {info['description']}")

        print("\nFetching payloads...")
        payloads = await fetch_remote_payloads(verbose=True)
        print(f"\nTotal: {len(payloads)} unique payloads")

        if len(sys.argv) > 1 and sys.argv[1] == "--show":
            print("\nSample payloads:")
            for p in payloads[:10]:
                print(f"  {p}")

    asyncio.run(main())
