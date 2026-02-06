"""
Web Crawler for XSSForge.

Async crawler for discovering URLs, parameters, and forms on target websites.
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from collections import deque

from bs4 import BeautifulSoup

from xssforge.utils.http import HTTPClient, HTTPConfig


@dataclass
class CrawledURL:
    """Represents a discovered URL with its parameters."""
    url: str
    method: str = "GET"
    parameters: dict[str, str] = field(default_factory=dict)
    source: str = ""  # Where this URL was found
    depth: int = 0


@dataclass
class FormData:
    """Represents a discovered form."""
    action: str
    method: str
    inputs: dict[str, str]  # name -> type/value
    source_url: str


@dataclass
class CrawlResult:
    """Results from crawling a target."""
    base_url: str
    urls_found: list[CrawledURL] = field(default_factory=list)
    forms_found: list[FormData] = field(default_factory=list)
    parameters_found: set[str] = field(default_factory=set)
    js_endpoints: list[str] = field(default_factory=list)
    total_requests: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class CrawlerConfig:
    """Configuration for the web crawler."""
    max_depth: int = 3
    max_urls: int = 500
    max_concurrent: int = 20
    timeout: float = 10.0
    delay: float = 0.5  # Delay between requests (rate limiting)
    follow_external: bool = False
    scope_pattern: str | None = None  # e.g., "*.example.com"
    skip_extensions: set[str] = field(default_factory=lambda: {
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz",
        ".mp3", ".mp4", ".avi", ".mov", ".webm", ".ogg"
    })
    proxy: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)


class WebCrawler:
    """
    Async web crawler for discovering attack surface.

    Features:
    - Async crawling with rate limiting
    - Link extraction from HTML
    - Form discovery with parameter extraction
    - JavaScript endpoint parsing
    - Scope enforcement
    """

    # Regex patterns for JS endpoint extraction
    JS_ENDPOINT_PATTERNS = [
        r'["\'](/api/[^"\']+)["\']',
        r'["\'](/v\d+/[^"\']+)["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
        r'\.ajax\s*\(\s*{\s*url:\s*["\']([^"\']+)["\']',
        r'XMLHttpRequest.*?\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
        r'endpoint["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'baseUrl["\']?\s*[:=]\s*["\']([^"\']+)["\']',
    ]

    def __init__(self, config: CrawlerConfig | None = None):
        self.config = config or CrawlerConfig()
        self._http_client: HTTPClient | None = None
        self._visited: set[str] = set()
        self._queue: deque[tuple[str, int]] = deque()  # (url, depth)
        self._semaphore: asyncio.Semaphore | None = None
        self._progress_callback: Callable | None = None

    async def __aenter__(self):
        await self._init_client()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def _init_client(self):
        """Initialize HTTP client."""
        http_config = HTTPConfig(
            timeout=self.config.timeout,
            proxy=self.config.proxy,
            headers=self.config.headers,
            cookies=self.config.cookies,
            verify_ssl=False,
        )
        self._http_client = HTTPClient(http_config)
        await self._http_client._init_client()
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent)

    async def close(self):
        """Close HTTP client."""
        if self._http_client:
            await self._http_client.close()

    def on_progress(self, callback: Callable):
        """Set progress callback."""
        self._progress_callback = callback

    async def crawl(self, base_url: str) -> CrawlResult:
        """
        Crawl a website starting from base_url.

        Args:
            base_url: Starting URL for crawling

        Returns:
            CrawlResult with discovered URLs, forms, and parameters
        """
        if not self._http_client:
            await self._init_client()

        # Parse base URL for scope enforcement
        parsed_base = urlparse(base_url)
        base_domain = parsed_base.netloc

        result = CrawlResult(base_url=base_url)
        self._visited.clear()
        self._queue.clear()
        self._queue.append((base_url, 0))

        while self._queue and len(result.urls_found) < self.config.max_urls:
            # Get batch of URLs to crawl in parallel
            batch = []
            while self._queue and len(batch) < self.config.max_concurrent:
                url, depth = self._queue.popleft()
                if url not in self._visited and depth <= self.config.max_depth:
                    batch.append((url, depth))
                    self._visited.add(url)

            if not batch:
                break

            # Crawl batch in parallel
            tasks = [
                self._crawl_url(url, depth, base_domain, result)
                for url, depth in batch
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

            # Progress callback
            if self._progress_callback:
                self._progress_callback(
                    f"Crawling... ({len(result.urls_found)} URLs found)",
                    len(result.urls_found),
                    self.config.max_urls,
                )

        return result

    async def _crawl_url(
        self,
        url: str,
        depth: int,
        base_domain: str,
        result: CrawlResult,
    ):
        """Crawl a single URL and extract links/forms."""
        async with self._semaphore:
            # Rate limiting
            if self.config.delay > 0:
                await asyncio.sleep(self.config.delay)

            try:
                response = await self._http_client.get(url)
                result.total_requests += 1
            except Exception as e:
                result.errors.append(f"{url}: {str(e)}")
                return

            # Skip non-HTML responses
            content_type = response.headers.get("content-type", "")
            if "text/html" not in content_type.lower():
                # But still check for API endpoints in JS files
                if "javascript" in content_type.lower():
                    endpoints = self._extract_js_endpoints(response.body, url)
                    result.js_endpoints.extend(endpoints)
                return

            # Parse HTML
            soup = BeautifulSoup(response.body, "lxml")

            # Extract URL parameters from current URL
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            if params:
                crawled_url = CrawledURL(
                    url=url,
                    method="GET",
                    parameters={k: v[0] if v else "" for k, v in params.items()},
                    source="url",
                    depth=depth,
                )
                result.urls_found.append(crawled_url)
                result.parameters_found.update(params.keys())

            # Extract links
            links = self._extract_links(soup, url, base_domain)
            for link_url in links:
                if link_url not in self._visited:
                    self._queue.append((link_url, depth + 1))

            # Extract forms
            forms = self._extract_forms(soup, url)
            for form in forms:
                result.forms_found.append(form)
                result.parameters_found.update(form.inputs.keys())
                # Add form action as crawled URL
                result.urls_found.append(CrawledURL(
                    url=form.action,
                    method=form.method,
                    parameters=form.inputs,
                    source="form",
                    depth=depth,
                ))

            # Extract JS endpoints
            endpoints = self._extract_js_endpoints(response.body, url)
            result.js_endpoints.extend(endpoints)

            # Extract inline script endpoints
            for script in soup.find_all("script"):
                if script.string:
                    inline_endpoints = self._extract_js_endpoints(script.string, url)
                    result.js_endpoints.extend(inline_endpoints)

    def _extract_links(
        self,
        soup: BeautifulSoup,
        current_url: str,
        base_domain: str,
    ) -> list[str]:
        """Extract all links from HTML."""
        links = []

        # Get all anchor tags
        for a in soup.find_all("a", href=True):
            href = a["href"]
            full_url = urljoin(current_url, href)

            if self._is_in_scope(full_url, base_domain):
                # Normalize URL (remove fragment)
                parsed = urlparse(full_url)
                normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if parsed.query:
                    normalized += f"?{parsed.query}"

                # Skip static files
                if not self._should_skip(normalized):
                    links.append(normalized)

        # Get script src for external JS
        for script in soup.find_all("script", src=True):
            src = script["src"]
            full_url = urljoin(current_url, src)
            if self._is_in_scope(full_url, base_domain):
                links.append(full_url)

        # Get iframe src
        for iframe in soup.find_all("iframe", src=True):
            src = iframe["src"]
            full_url = urljoin(current_url, src)
            if self._is_in_scope(full_url, base_domain):
                links.append(full_url)

        return list(set(links))  # Deduplicate

    def _extract_forms(self, soup: BeautifulSoup, current_url: str) -> list[FormData]:
        """Extract all forms with their inputs."""
        forms = []

        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()

            # Resolve action URL
            if action:
                action_url = urljoin(current_url, action)
            else:
                action_url = current_url

            # Extract inputs
            inputs = {}

            # Input elements
            for inp in form.find_all("input"):
                name = inp.get("name")
                if name:
                    inp_type = inp.get("type", "text")
                    value = inp.get("value", "")
                    inputs[name] = value or f"<{inp_type}>"

            # Textarea elements
            for textarea in form.find_all("textarea"):
                name = textarea.get("name")
                if name:
                    inputs[name] = textarea.string or ""

            # Select elements
            for select in form.find_all("select"):
                name = select.get("name")
                if name:
                    # Get first option value
                    option = select.find("option")
                    value = option.get("value", "") if option else ""
                    inputs[name] = value

            if inputs:  # Only add forms with inputs
                forms.append(FormData(
                    action=action_url,
                    method=method,
                    inputs=inputs,
                    source_url=current_url,
                ))

        return forms

    def _extract_js_endpoints(self, content: str, base_url: str) -> list[str]:
        """Extract API endpoints from JavaScript code."""
        endpoints = []

        for pattern in self.JS_ENDPOINT_PATTERNS:
            matches = re.findall(pattern, content, re.I)
            for match in matches:
                # Handle tuple from groups
                endpoint = match[-1] if isinstance(match, tuple) else match

                if endpoint and not endpoint.startswith(("http://", "https://")):
                    # Relative URL
                    endpoint = urljoin(base_url, endpoint)

                if endpoint and self._is_valid_url(endpoint):
                    endpoints.append(endpoint)

        return list(set(endpoints))

    def _is_in_scope(self, url: str, base_domain: str) -> bool:
        """Check if URL is within crawling scope."""
        try:
            parsed = urlparse(url)

            # Must be HTTP/HTTPS
            if parsed.scheme not in ("http", "https"):
                return False

            domain = parsed.netloc

            # Custom scope pattern
            if self.config.scope_pattern:
                import fnmatch
                return fnmatch.fnmatch(domain, self.config.scope_pattern)

            # Default: same domain or subdomains
            if not self.config.follow_external:
                return domain == base_domain or domain.endswith(f".{base_domain}")

            return True

        except Exception:
            return False

    def _should_skip(self, url: str) -> bool:
        """Check if URL should be skipped (static files, etc.)."""
        parsed = urlparse(url)
        path = parsed.path.lower()

        for ext in self.config.skip_extensions:
            if path.endswith(ext):
                return True

        return False

    def _is_valid_url(self, url: str) -> bool:
        """Check if URL is valid."""
        try:
            parsed = urlparse(url)
            return parsed.scheme in ("http", "https") and parsed.netloc
        except Exception:
            return False


async def crawl_target(
    url: str,
    depth: int = 3,
    config: CrawlerConfig | None = None,
) -> CrawlResult:
    """Convenience function to crawl a target."""
    if config is None:
        config = CrawlerConfig(max_depth=depth)
    else:
        config.max_depth = depth

    async with WebCrawler(config) as crawler:
        return await crawler.crawl(url)


def get_testable_urls(result: CrawlResult) -> list[str]:
    """
    Extract all testable URLs from crawl result.

    Returns URLs with parameters that can be tested for XSS.
    """
    testable = []
    seen = set()

    for crawled_url in result.urls_found:
        if crawled_url.parameters:
            # Reconstruct URL with parameters
            parsed = urlparse(crawled_url.url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            # For GET requests, include query string
            if crawled_url.method == "GET" and crawled_url.parameters:
                query = urlencode(crawled_url.parameters)
                full_url = f"{base}?{query}"
            else:
                full_url = base

            if full_url not in seen:
                testable.append(full_url)
                seen.add(full_url)

    # Add JS endpoints
    for endpoint in result.js_endpoints:
        if endpoint not in seen:
            testable.append(endpoint)
            seen.add(endpoint)

    return testable
