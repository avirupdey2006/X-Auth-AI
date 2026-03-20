import click
import json
import os
from core.banner import print_banner
from core.logger import logger


@click.group()
def cli():
    """X-Auth AI — Credential Intelligence Engine"""
    print_banner()


@cli.command()
@click.option("--hash",     "-h", required=True,  help="Hash string to crack")
@click.option("--wordlist", "-w", default=None,    help="Path to wordlist")
@click.option("--gpu",      "-g", is_flag=True,    help="Force Hashcat GPU mode")
@click.option("--output",   "-o", default=None,    help="Save result to JSON")
def crack_cmd(hash, wordlist, gpu, output):
    """Crack a password hash using wordlist + GPU fallback."""
    from lab.cracker import crack
    from lab.hashcat_runner import run_hashcat
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


@cli.command()
@click.option("--url",         "-u", required=True,  help="Target URL to scan")
@click.option("--company",     "-c", default="",      help="Company name (boosts AI accuracy)")
@click.option("--usernames",   "-U", default="",      help="Comma-separated known usernames")
@click.option("--sqli",              is_flag=True, default=True,  help="Run SQL injection tests")
@click.option("--brute",             is_flag=True, default=True,  help="Run brute force")
@click.option("--ratelimit",         is_flag=True, default=True,  help="Test rate limiting")
@click.option("--ai",                is_flag=True, default=True,  help="Use AI password generation")
@click.option("--db-url",            default="",   help="Database connection string for hash extraction")
@click.option("--no-cache",          is_flag=True, default=False, help="Force fresh AI generation")
@click.option("--max-pages",         default=20,   help="Max pages to crawl")
def scan(url, company, usernames, sqli, brute, ratelimit, ai, db_url, no_cache, max_pages):
    """
    Full X-Auth AI scan — Phases 1+2+3 integrated.

    Example:
      python main.py scan --url http://localhost/login.php --company DVWA --ai
      python main.py scan --url http://target.com -c "Acme Corp" -U "john,jane" --ai
    """
    from rich.console import Console
    from rich.rule import Rule
    console = Console()

    # ── Phase 2 imports ──
    from scout.crawler       import crawl
    from scout.form_parser   import extract_auth_targets
    from attacker.sqli_engine       import test_sqli
    from attacker.brute_force       import brute_force
    from attacker.brute_force       import CREDENTIAL_DATABASE
    from attacker.rate_limiter_test import test_rate_limiting
    from attacker.detective         import compile_findings

    # ── Phase 3 imports ──
    from intelligence.context_builder import build_context
    from intelligence.ai_guesser      import generate_ai_wordlist
    from intelligence.wordlist_merger  import merge_wordlists
    from intelligence.db_bridge       import extract_hashes

    console.print(f"[bold cyan]Starting scan on:[/bold cyan] {url}\n")

    # ── Step 1: Recon ──
    console.print(Rule("[bold]Phase 2 — Reconnaissance[/bold]"))
    crawl_data = crawl(url, max_pages=max_pages)
    targets    = extract_auth_targets(crawl_data)

    if not targets:
        console.print("[yellow]No auth forms found. Exiting.[/yellow]")
        return

    # ── Step 2: Phase 3 — Intelligence ──
    ai_passwords    = []
    extra_cred_list = []

    if ai:
        console.print(Rule("[bold]Phase 3 — Credential Intelligence[/bold]"))

        username_list = [u.strip() for u in usernames.split(",") if u.strip()]

        # Build context from target
        context = build_context(url, company_name=company, usernames=username_list)

        # Generate AI wordlist
        ai_passwords = generate_ai_wordlist(context, use_cache=not no_cache)

        # Merge AI + base credentials
        if ai_passwords:
            extra_cred_list = merge_wordlists(
                ai_passwords=ai_passwords,
                base_credentials=CREDENTIAL_DATABASE,
                usernames=username_list,
            )
        else:
            extra_cred_list = list(CREDENTIAL_DATABASE)

    # DB Bridge (optional — only if --db-url provided)
    db_result = {}
    if db_url:
        console.print(Rule("[bold]Phase 3 — Hash Extraction[/bold]"))
        db_result = extract_hashes(connection_string=db_url)

        # If hashes extracted, crack them with Phase 1
        if db_result.get("status") == "success" and db_result.get("saved_txt"):
            console.print(
                f"\n[bold cyan]Cracking {db_result['count']} extracted hashes "
                f"with Hashcat...[/bold cyan]"
            )
            from lab.cracker import crack
            from lab.hashcat_runner import run_hashcat
            from core.config import WORDLIST_DEFAULT

            crack_results = []
            for hash_record in db_result["hashes"][:50]:   # cap at 50 for demo
                r = crack(hash_record["hash"], WORDLIST_DEFAULT)
                if r["status"] == "not_found":
                    r = run_hashcat(hash_record["hash"], WORDLIST_DEFAULT)
                r["username"] = hash_record["username"]
                crack_results.append(r)
                if r["status"] == "cracked":
                    console.print(
                        f"  [bold red]CRACKED[/bold red]  "
                        f"{hash_record['username']} → [green]{r.get('password', '?')}[/green]"
                    )

    # ── Step 3: Attack ──
    console.print(Rule("[bold]Phase 2 — Attack[/bold]"))

    sqli_results  = []
    brute_results = []
    rate_results  = []

    for target in targets:
        console.print(f"\n[bold]Testing:[/bold] {target['action']}")

        if sqli:
            sqli_results.append(test_sqli(target))

        if brute:
            # Pass AI-merged credentials as extra_credentials
            brute_results.append(
                brute_force(
                    target,
                    extra_credentials=extra_cred_list if extra_cred_list else None,
                )
            )

        if ratelimit:
            rate_results.append(test_rate_limiting(target))

    # ── Step 4: Report ──
    console.print(Rule("[bold]Findings[/bold]"))
    compile_findings(sqli_results, brute_results, rate_results, url)
    console.print("\n[bold green]Scan completed.[/bold green]")


if __name__ == "__main__":
    cli()