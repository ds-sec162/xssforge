"""
HTTP client utilities for XSSForge.

Provides async HTTP client with proxy support, rate limiting, and session handling.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import httpx


@dataclass
class HTTPResponse:
    """Wrapper for HTTP response data."""
    url: str
    status_code: int
    headers: dict[str, str]
    body: str
    elapsed: float
    request_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class HTTPConfig:
    """HTTP client configuration."""
    timeout: float = 30.0
    max_redirects: int = 5
    verify_ssl: bool = False
    proxy: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    rate_limit: float = 0.0  # Requests per second (0 = unlimited)
    max_retries: int = 3
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


class HTTPClient:
    """Async HTTP client with rate limiting and retry logic."""

    def __init__(self, config: HTTPConfig | None = None):
        self.config = config or HTTPConfig()
        self._last_request_time = 0.0
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self):
        await self._init_client()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def _init_client(self):
        """Initialize the async HTTP client."""
        default_headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        default_headers.update(self.config.headers)

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.timeout),
            follow_redirects=True,
            max_redirects=self.config.max_redirects,
            verify=self.config.verify_ssl,
            proxy=self.config.proxy,
            headers=default_headers,
            cookies=self.config.cookies,
        )

    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _rate_limit(self):
        """Apply rate limiting between requests."""
        if self.config.rate_limit > 0:
            min_interval = 1.0 / self.config.rate_limit
            elapsed = time.time() - self._last_request_time
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
        self._last_request_time = time.time()

    async def get(
        self,
        url: str,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HTTPResponse:
        """Perform GET request."""
        return await self._request("GET", url, params=params, headers=headers)

    async def post(
        self,
        url: str,
        data: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HTTPResponse:
        """Perform POST request."""
        return await self._request("POST", url, data=data, json=json, headers=headers)

    async def _request(
        self,
        method: str,
        url: str,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HTTPResponse:
        """Perform HTTP request with retry logic."""
        if not self._client:
            await self._init_client()

        await self._rate_limit()

        last_error = None
        for attempt in range(self.config.max_retries):
            try:
                response = await self._client.request(
                    method,
                    url,
                    params=params,
                    data=data,
                    json=json,
                    headers=headers,
                )

                return HTTPResponse(
                    url=str(response.url),
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=response.text,
                    elapsed=response.elapsed.total_seconds(),
                    request_headers=dict(response.request.headers),
                )

            except httpx.TimeoutException as e:
                last_error = e
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
            except httpx.HTTPError as e:
                last_error = e
                break  # Don't retry on HTTP errors

        raise last_error or Exception("Request failed")


def parse_url_params(url: str) -> dict[str, list[str]]:
    """Extract query parameters from URL."""
    parsed = urlparse(url)
    return parse_qs(parsed.query)


def build_url_with_params(url: str, params: dict[str, str]) -> str:
    """Build URL with query parameters."""
    parsed = urlparse(url)
    # Merge existing params with new ones
    existing_params = parse_qs(parsed.query)
    merged = {k: v[0] if len(v) == 1 else v for k, v in existing_params.items()}
    merged.update(params)

    new_query = urlencode(merged, doseq=True)
    new_parsed = parsed._replace(query=new_query)
    return urlunparse(new_parsed)


def get_base_url(url: str) -> str:
    """Get base URL without path and query."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def normalize_url(url: str) -> str:
    """Normalize URL for comparison."""
    parsed = urlparse(url)
    # Remove default ports
    netloc = parsed.netloc
    if parsed.scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif parsed.scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]

    # Normalize path
    path = parsed.path or "/"
    if not path.endswith("/") and "." not in path.split("/")[-1]:
        path += "/"

    return f"{parsed.scheme}://{netloc}{path}"
