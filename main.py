import click
import json
import os
from core.banner import print_banner
from core.logger import logger
from lab.cracker import crack
from lab.hashcat_runner import run_hashcat


@click.group()
def cli():
    """X-Auth AI — Credential Intelligence Engine"""
    print_banner()


@cli.command()
@click.option("--hash",     "-h", required=True,  help="Hash string to crack")
@click.option("--wordlist", "-w", default=None,    help="Path to wordlist (default: rockyou.txt)")
@click.option("--gpu",      "-g", is_flag=True,    help="Force Hashcat GPU mode")
@click.option("--output",   "-o", default=None,    help="Save result to JSON file")
def crack_cmd(hash, wordlist, gpu, output):
    """Crack a password hash using wordlist + GPU fallback."""
    
    from core.config import WORDLIST_DEFAULT
    wordlist = wordlist or WORDLIST_DEFAULT
    
    if gpu:
        result = run_hashcat(hash, wordlist)
    else:
        result = crack(hash, wordlist)
        if result["status"] == "not_found":
            result = run_hashcat(hash, wordlist)

    if output:
        with open(output, "w") as f:
            json.dump(result, f, indent=2)
        click.echo(f"\nResult saved to {output}")

    return result


@cli.command()
@click.option("--url",    "-u", required=True, help="Target URL to scan")
@click.option("--sqli",         is_flag=True, default=True,  help="Run SQL injection tests")
@click.option("--brute",        is_flag=True, default=True,  help="Run brute force")
@click.option("--ratelimit",    is_flag=True, default=True,  help="Test rate limiting")
@click.option("--max-pages",    default=20,   help="Max pages to crawl")
def scan(url, sqli, brute, ratelimit, max_pages):
    """Full Phase 2 attack scan against a target URL."""

    from rich.console import Console
    console = Console()

    from scout.crawler import crawl
    from scout.form_parser import extract_auth_targets
    from attacker.sqli_engine import test_sqli
    from attacker.brute_force import brute_force
    from attacker.rate_limiter_test import test_rate_limiting

    try:
        from attacker.detective import compile_findings
    except ImportError:
        compile_findings = None

    console.print(f"[bold cyan]Starting scan on:[/bold cyan] {url}\n")

    # Step 1: Recon
    crawl_data = crawl(url, max_pages=max_pages)
    targets = extract_auth_targets(crawl_data)

    if not targets:
        console.print("[yellow]No auth forms found. Exiting.[/yellow]")
        return

    sqli_results  = []
    brute_results = []
    rate_results  = []

    for target in targets:
        console.print(f"\n[bold]Testing target:[/bold] {target}")

        if sqli:
            sqli_results.append(test_sqli(target))

        if brute:
            brute_results.append(brute_force(target))

        if ratelimit:
            rate_results.append(test_rate_limiting(target))

    if compile_findings:
        compile_findings(sqli_results, brute_results, rate_results, url)

    console.print("\n[bold green]Scan completed.[/bold green]")


if __name__ == "__main__":
    cli()