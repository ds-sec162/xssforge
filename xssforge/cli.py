#!/usr/bin/env python3
"""
XSSForge CLI - The Ultimate XSS Scanner.

Usage:
    xssforge <url>                    # Hunt for XSS (simplest)
    xssforge hunt -u URL [options]    # Hunt with options
    xssforge payloads [options]       # Generate payloads

Examples:
    xssforge "https://example.com/page?id=1"
    xssforge hunt -u "https://example.com/search?q=test" --browser
"""

import asyncio
import sys
import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.syntax import Syntax

from xssforge import __version__

console = Console()

# Known subcommands
COMMANDS = {"hunt", "scan", "payloads", "solve", "version", "recon"}


def print_banner():
    """Print the XSSForge banner."""
    banner = """
██╗  ██╗███████╗███████╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
╚██╗██╔╝██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
 ╚███╔╝ ███████╗███████╗█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
 ██╔██╗ ╚════██║╚════██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
██╔╝ ██╗███████║███████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
╚═╝  ╚═╝╚══════╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
    """
    console.print(Panel(banner, title=f"[bold red]XSSForge v{__version__}[/]", subtitle="The Ultimate XSS Scanner"))


def run_hunt(url: str, verbose: bool = False, browser: bool = False, proxy: str = None):
    """Run the hunter on a URL."""
    from xssforge.hunter import XSSHunter, HunterConfig

    config = HunterConfig(
        verbose=verbose,
        use_browser=browser,
        proxy=proxy,
        max_payloads=50,
    )

    hunter = XSSHunter(config)

    with console.status("[bold cyan]Hunting for XSS...[/]"):
        findings = hunter.hunt(url)

    return findings


def display_findings(findings):
    """Display findings in a nice format."""
    if findings:
        console.print(f"\n[bold green][+] Found {len(findings)} XSS vulnerabilities![/]\n")

        for i, vuln in enumerate(findings, 1):
            severity_colors = {
                "critical": "red",
                "high": "orange1",
                "medium": "yellow",
                "low": "blue",
            }
            color = severity_colors.get(vuln.severity.value, "white")

            console.print(f"[bold {color}]#{i} [{vuln.severity.value.upper()}] {vuln.xss_type.upper()} XSS[/]")
            console.print(f"  [cyan]URL:[/] {vuln.url}")
            console.print(f"  [cyan]Parameter:[/] {vuln.parameter}")
            console.print(f"  [cyan]Context:[/] {vuln.context}")
            console.print(f"  [cyan]Payload:[/] [yellow]{vuln.payload}[/]")

            if vuln.verified:
                console.print(f"  [green]✓ Browser verified[/]")
            if vuln.techniques_used:
                console.print(f"  [cyan]Techniques:[/] {', '.join(vuln.techniques_used)}")
            console.print()

        return True
    else:
        console.print("\n[yellow][-] No XSS vulnerabilities found.[/]")
        console.print("[dim]Try --browser for DOM XSS verification[/]")
        return False


# ============================================================================
# Direct URL scanning (xssforge <url>)
# ============================================================================

@click.command()
@click.argument("url")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("--browser", is_flag=True, help="Use browser for verification")
@click.option("--proxy", help="Proxy URL")
def scan_url(url, verbose, browser, proxy):
    """Scan a URL directly for XSS."""
    print_banner()
    console.print(f"\n[bold cyan]Target:[/] {url}")
    console.print(f"[cyan]Mode:[/] Adaptive (auto-detects filters, CSP, sanitizers)")
    console.print()

    findings = run_hunt(url, verbose=verbose, browser=browser, proxy=proxy)
    found = display_findings(findings)
    sys.exit(1 if found else 0)


# ============================================================================
# CLI Group (subcommands)
# ============================================================================

@click.group()
@click.version_option(version=__version__)
def cli():
    """XSSForge - The Ultimate XSS Scanner.

    Simply run: xssforge <url> to hunt for XSS.

    Or use subcommands: hunt, payloads, solve
    """
    pass


@cli.command()
@click.option("-u", "--url", required=True, help="Target URL")
@click.option("-f", "--file", "file_path", type=click.Path(exists=True), help="File with URLs")
@click.option("--proxy", help="Proxy URL")
@click.option("--timeout", default=15.0, help="Request timeout")
@click.option("--max-payloads", default=50, help="Max payloads per parameter")
@click.option("--browser", is_flag=True, help="Verify with headless browser")
@click.option("-o", "--output", help="Output file (JSON)")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def hunt(url, file_path, proxy, timeout, max_payloads, browser, output, verbose):
    """Hunt for XSS - the smart adaptive scanner."""
    from xssforge.hunter import XSSHunter, HunterConfig

    print_banner()

    # Collect URLs
    urls = []
    if url:
        urls.append(url)
    if file_path:
        with open(file_path) as f:
            urls.extend(line.strip() for line in f if line.strip() and not line.startswith("#"))

    if not urls:
        console.print("[red]Error: No URLs specified[/]")
        sys.exit(1)

    console.print(f"\n[bold cyan]Targets:[/] {len(urls)}")
    console.print(f"[cyan]Mode:[/] Adaptive (auto-detects filters, CSP, sanitizers)")
    console.print(f"[cyan]Browser:[/] {'Enabled' if browser else 'Disabled'}")
    console.print()

    config = HunterConfig(
        max_payloads=max_payloads,
        timeout=timeout,
        use_browser=browser,
        proxy=proxy,
        verbose=verbose,
    )

    hunter_instance = XSSHunter(config)
    all_findings = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Hunting...", total=len(urls))

        for target_url in urls:
            progress.update(task, description=f"Hunting {target_url[:40]}...")
            findings = hunter_instance.hunt(target_url)
            all_findings.extend(findings)
            progress.advance(task)

    # Display results
    display_findings(all_findings)

    # Save to file if requested
    if output and all_findings:
        results = [
            {
                "url": f.url,
                "parameter": f.parameter,
                "payload": f.payload,
                "context": f.context,
                "xss_type": f.xss_type,
                "severity": f.severity.value,
                "verified": f.verified,
                "techniques": f.techniques_used,
            }
            for f in all_findings
        ]
        with open(output, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"\n[green]Results saved to {output}[/]")

    sys.exit(1 if all_findings else 0)


@cli.command()
@click.option("--context", type=click.Choice([
    "html_body", "html_attribute", "javascript_string", "url_href"
]), default="html_body", help="Injection context")
@click.option("--max", "max_count", default=20, help="Maximum payloads")
@click.option("--mxss", is_flag=True, help="Include mXSS/sanitizer bypass payloads")
@click.option("--csp", is_flag=True, help="Include CSP bypass payloads")
def payloads(context, max_count, mxss, csp):
    """Generate XSS payloads."""
    from xssforge.payloads.generator import PayloadGenerator

    print_banner()

    generator = PayloadGenerator()

    console.print(f"\n[cyan]Context:[/] {context}")
    console.print()

    if mxss:
        console.print("[bold]mXSS / Sanitizer Bypass Payloads:[/]")
        for p in generator.get_mxss_payloads()[:max_count]:
            console.print(f"  {p}")
        return

    if csp:
        console.print("[bold]CSP Bypass Payloads:[/]")
        for p in generator.get_csp_bypass_payloads()[:max_count]:
            console.print(f"  {p}")
        return

    # Default: context-specific payloads
    console.print(f"[bold]Payloads for {context}:[/]")
    all_payloads = generator.ultimate_payload_set()[:max_count]
    for p in all_payloads:
        console.print(Syntax(p, "html", theme="monokai", word_wrap=True))


@cli.command()
@click.option("--game", type=click.Choice(["google"]), default="google", help="XSS game to solve")
def solve(game):
    """Solve XSS game challenges."""
    from xssforge.game_solver import XSSGameSolver

    print_banner()

    console.print(f"\n[bold cyan]Solving {game.title()} XSS Game[/]\n")

    async def run_solver():
        async with XSSGameSolver() as solver:
            return await solver.solve_google_xss_game()

    results = asyncio.run(run_solver())

    # Display results
    solved = sum(1 for r in results if r.success)
    total = len(results)

    table = Table(title="XSS Game Results")
    table.add_column("Level", style="cyan")
    table.add_column("Type", style="blue")
    table.add_column("Payload", style="yellow")
    table.add_column("Status", style="green")

    for r in results:
        status = "[green]✓ SOLVED[/]" if r.success else "[red]✗ FAILED[/]"
        table.add_row(
            r.name.split(" - ")[0] if " - " in r.name else r.name,
            r.xss_type,
            r.payload[:35] + "..." if len(r.payload) > 35 else r.payload,
            status
        )

    console.print(table)
    console.print(f"\n[bold]Solved {solved}/{total} levels[/]")

    if solved == total:
        console.print("[bold green]ALL LEVELS COMPLETED![/]")


@cli.command()
@click.option("-u", "--url", help="Single URL to scan")
@click.option("-l", "--list", "file_path", type=click.Path(exists=True), help="File with URLs")
@click.option("-o", "--output", help="Output file (JSON)")
@click.option("-t", "--timeout", default=10.0, help="Request timeout")
@click.option("--delay", default=0.0, help="Delay between requests")
@click.option("--max-payloads", default=50, help="Max payloads per param")
@click.option("--preset", type=click.Choice(["quick", "standard", "thorough", "comprehensive"]),
              default="standard", help="Scan preset (quick=20, standard=50, thorough=200, comprehensive=500 payloads)")
@click.option("--browser", is_flag=True, help="Verify with headless browser (requires playwright)")
@click.option("--no-waf-evasion", is_flag=True, help="Disable WAF evasion")
@click.option("--no-smart-filter", is_flag=True, help="Disable smart filter analysis (faster but less accurate)")
@click.option("--format", "output_format", type=click.Choice(["text", "json", "jsonl"]),
              default="text", help="Output format")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("-s", "--silent", is_flag=True, help="Only output findings")
# Dalfox-equivalent options
@click.option("-b", "--blind", "blind_callback", help="Blind XSS callback URL (e.g., https://your.xss.ht)")
@click.option("-d", "--data", "post_data", help="POST data (e.g., 'name=test&email=test@test.com')")
@click.option("-H", "--header", "headers", multiple=True, help="Custom header (can be used multiple times)")
@click.option("-C", "--cookie", "cookies", help="Custom cookies")
@click.option("-X", "--method", default="GET", help="HTTP method (GET/POST)")
@click.option("--custom-payload", "custom_payloads", type=click.Path(exists=True), help="Custom payloads file")
@click.option("-w", "--workers", default=10, help="Number of concurrent workers")
# NEW: Enhanced features that beat Dalfox
@click.option("--use-bav", is_flag=True, help="Enable BAV testing (SQLi, SSTI, Open Redirect, CRLF)")
@click.option("--mine-params", is_flag=True, help="Mine parameters from HTML/JS (DOM mining)")
@click.option("--remote-payloads", help="Fetch remote payloads (portswigger,payloadbox,all)")
@click.option("--deep-dom-xss", is_flag=True, help="Enhanced DOM XSS analysis")
@click.option("--skip-json/--include-json", default=True, help="Skip JSON responses (fixes false positives)")
# SMART MODE: Comprehensive automated scanning
@click.option("--smart", is_flag=True, help="SMART MODE: Auto-discover subdomains, forms, APIs, DOM XSS (COMPREHENSIVE)")
@click.option("--scan-subdomains", is_flag=True, help="Find dev/staging subdomains (weaker WAF)")
@click.option("--scan-forms", is_flag=True, help="Discover and test POST forms")
@click.option("--scan-api", is_flag=True, help="Discover API endpoints")
@click.option("--scan-dom", is_flag=True, help="Scan for DOM XSS (WAF can't block!)")
def scan(url, file_path, output, timeout, delay, max_payloads, preset, browser,
         no_waf_evasion, no_smart_filter, output_format, verbose, silent,
         blind_callback, post_data, headers, cookies, method, custom_payloads, workers,
         use_bav, mine_params, remote_payloads, deep_dom_xss, skip_json,
         smart, scan_subdomains, scan_forms, scan_api, scan_dom):
    """XSSForge v2.1 - Ultimate XSS Scanner (beats Dalfox!)

    508+ payloads | BAV Testing | DOM Mining | Remote Payloads | Deep DOM XSS

    Presets:
        quick        - Fast scan (~20 payloads, no filter analysis)
        standard     - Balanced (~50 payloads, smart filtering)
        thorough     - Deep scan (~200 payloads, full analysis)
        comprehensive - Maximum coverage (~500 payloads)

    Basic Examples:
        xssforge scan -u "https://target.com/search?q=test"
        cat urls.txt | xssforge scan --preset thorough
        xssforge scan -l urls.txt -o results.json

    Blind XSS (stored XSS detection):
        xssforge scan -u URL -b "https://your.xss.ht"

    POST Form Testing:
        xssforge scan -u URL -X POST -d "name=test&q=test"

    Authenticated Testing:
        xssforge scan -u URL -H "Authorization: Bearer token" -C "session=abc123"

    Advanced Features (beats Dalfox):
        xssforge scan -u URL --use-bav              # Test SQLi, SSTI, Open Redirect
        xssforge scan -u URL --mine-params          # Discover hidden parameters
        xssforge scan -u URL --remote-payloads all  # Fetch latest payloads
        xssforge scan -u URL --deep-dom-xss         # Advanced DOM XSS analysis
    """
    from xssforge.xscan import XScan, ULTIMATE_AVAILABLE, BROWSER_AVAILABLE
    import asyncio

    # Collect URLs
    urls = []
    if url:
        urls.append(url)
    if file_path:
        with open(file_path) as f:
            urls.extend(line.strip() for line in f if line.strip() and not line.startswith('#'))
    if not urls and not sys.stdin.isatty():
        urls = [line.strip() for line in sys.stdin if line.strip() and not line.startswith('#')]

    if not urls:
        console.print("[red]Error: No URLs provided. Use -u, -l, or pipe URLs to stdin.[/]")
        sys.exit(1)

    # Check browser availability
    if browser and not BROWSER_AVAILABLE:
        console.print("[yellow]Warning: Browser verification unavailable. Install: pip install playwright && playwright install chromium[/]")
        browser = False

    # Parse headers into dict
    headers_dict = {}
    for h in headers:
        if ":" in h:
            key, value = h.split(":", 1)
            headers_dict[key.strip()] = value.strip()

    if not silent:
        try:
            from xssforge.payloads.ultimate import get_payload_count
            payload_count = get_payload_count()
        except ImportError:
            payload_count = "~60"
        console.print(f"[cyan]XSSForge v2.1 - {len(urls)} target(s) - {payload_count} payloads[/]")
        console.print(f"[cyan]Preset: {preset}[/]")
        features = []
        if browser:
            features.append("Browser")
        if blind_callback:
            features.append(f"Blind({blind_callback[:20]}...)")
        if use_bav:
            features.append("BAV")
        if mine_params:
            features.append("Mining")
        if remote_payloads:
            features.append("Remote")
        if deep_dom_xss:
            features.append("DeepDOM")
        if smart:
            features.append("SMART MODE")
        if scan_subdomains:
            features.append("Subdomains")
        if scan_forms:
            features.append("Forms")
        if scan_api:
            features.append("API")
        if scan_dom:
            features.append("DOM-XSS")
        if features:
            console.print(f"[cyan]Features: {', '.join(features)}[/]")
        if post_data:
            console.print(f"[cyan]Method: POST | Data: {post_data[:40]}...[/]")
        if smart:
            console.print(f"[bold yellow]🚀 SMART MODE: Auto-discovering subdomains, forms, APIs, DOM XSS...[/]")

    scanner = XScan(
        timeout=timeout,
        delay=delay,
        verbose=verbose,
        waf_evasion=not no_waf_evasion,
        max_payloads=max_payloads,
        preset=preset,
        use_browser=browser,
        smart_filter=not no_smart_filter,
        # Dalfox-equivalent options
        blind_callback=blind_callback or "",
        post_data=post_data or "",
        headers=headers_dict,
        cookies=cookies or "",
        method=method,
        custom_payloads=custom_payloads or "",
        workers=workers,
        # Enhanced features (beat Dalfox)
        use_bav=use_bav,
        mine_params=mine_params,
        remote_payloads=remote_payloads or "",
        deep_dom_xss=deep_dom_xss,
        skip_json=skip_json,
        # SMART MODE
        smart_mode=smart,
        scan_subdomains=scan_subdomains,
        scan_forms=scan_forms,
        scan_api=scan_api,
        scan_dom=scan_dom,
    )

    findings = asyncio.run(scanner.scan(urls))

    if not silent:
        console.print(f"\n[green]Found {len(findings)} XSS vulnerabilities[/]")

    # Output results based on format
    if output_format == "jsonl":
        for f in findings:
            print(json.dumps(f.to_json()))
    elif output and findings:
        with open(output, 'w') as f:
            json.dump([finding.to_json() for finding in findings], f, indent=2)
        console.print(f"[green]Results saved to {output}[/]")

    sys.exit(1 if findings else 0)


@cli.command()
@click.option("-d", "--domain", help="Target domain (e.g., example.com)")
@click.option("-u", "--url", help="Target URL")
@click.option("--full", is_flag=True, help="Enable ALL features (subdomains, forms, API, DOM)")
@click.option("--forms", is_flag=True, help="Discover and test HTML forms")
@click.option("--api", is_flag=True, help="Discover API endpoints")
@click.option("--dom", is_flag=True, help="Scan for DOM XSS (WAF can't block)")
@click.option("--subdomains", is_flag=True, help="Enumerate subdomains (find dev/staging)")
@click.option("-b", "--blind", help="Blind XSS callback URL (e.g., https://your.xss.ht)")
@click.option("-o", "--output", help="Output file (JSON)")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def recon(domain, url, full, forms, api, dom, subdomains, blind, output, verbose):
    """
    Smart Recon - Automated XSS hunting with advanced techniques.

    Automatically performs:

    \b
    1. Subdomain enumeration (find dev/staging - often less protected)
    2. Form discovery and POST testing (stored XSS opportunities)
    3. API endpoint discovery (often lack WAF rules)
    4. DOM XSS scanning (WAF CAN'T block client-side!)
    5. Blind XSS injection (for stored XSS detection)

    \b
    Examples:
        xssforge recon -d target.com --full
        xssforge recon -u https://target.com --forms --dom
        xssforge recon -d target.com --full -b https://your.xss.ht

    \b
    Why this matters:
        - Subdomains: dev/staging often have weaker WAF rules
        - Forms: POST endpoints are often less protected
        - API: Many APIs lack WAF integration
        - DOM XSS: Executed client-side, WAF can't block it!
    """
    if not domain and not url:
        console.print("[red]Error: Provide -d domain or -u url[/]")
        sys.exit(1)

    target = domain or url

    console.print(f"[bold cyan]XSSForge Smart Recon[/] - Target: {target}")

    try:
        from xssforge.smart_hunter import hunt_target, print_hunt_summary

        result = asyncio.run(hunt_target(
            target=target,
            full=full,
            forms=forms,
            api=api,
            dom=dom,
            subdomains=subdomains,
            blind_callback=blind or "",
            verbose=verbose,
            output=output or "",
        ))

        print_hunt_summary(result)

        # Show actionable next steps
        if result.dom_sinks:
            console.print("\n[bold yellow]⚡ DOM XSS FOUND - Test these manually![/]")
            console.print("DOM XSS executes client-side, WAF cannot block it.")

        if result.forms:
            console.print("\n[bold yellow]📝 Forms found - Test with:[/]")
            console.print(f"  xssforge scan -u '{result.forms[0].action}' -X POST -d 'param=test'")

        if result.subdomains:
            dev_subs = [s for s in result.subdomains if any(x in s for x in ["dev", "stag", "test", "qa"])]
            if dev_subs:
                console.print("\n[bold yellow]🎯 Dev/Staging subdomains - Often less protected![/]")
                for sub in dev_subs[:3]:
                    console.print(f"  xssforge scan -u 'https://{sub}/?q=test' --preset thorough")

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
def version():
    """Show version information."""
    console.print(f"XSSForge v{__version__}")
    console.print("The Ultimate XSS Scanner")
    console.print("https://github.com/ds-sec162/xssforge")


# ============================================================================
# Main entry point - smart routing
# ============================================================================

def main():
    """Main entry point with smart argument routing."""
    # If first arg looks like a URL, use direct scan
    # Otherwise, use subcommand group
    if len(sys.argv) > 1:
        first_arg = sys.argv[1]
        # Check if it's a URL (not a command or option)
        if first_arg not in COMMANDS and not first_arg.startswith("-"):
            # Looks like a URL - use direct scan
            return scan_url()

    # Use subcommand group
    return cli()


if __name__ == "__main__":
    main()
