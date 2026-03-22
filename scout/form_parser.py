"""
form_parser.py — X-Auth AI  Auth Target Extractor  v2.0

WHAT CHANGED vs v1:
──────────────────────────────────────────────────────────────────────────────
  • extract_auth_targets() now handles BOTH traditional form dicts AND the
    new "synthetic" SPA dicts produced by crawler v2.

  • For SPA targets flagged with playwright_needed=True, the returned target
    dict includes a "playwright_selectors" key so brute_force.py can use
    page.fill() / page.click() instead of HTTP POST.

  • Username field detection is smarter:
      - Checks for "email", "user", "login", "identifier" in field names.
      - Falls back to "email" for Juice-Shop-style JSON endpoints.
      - Falls back to "username" for DVWA-style classic forms.

  • _print_targets_table() shows a "Mode" column:
      Static / SPA-HTTP / SPA-Browser
──────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

console = Console()

# Field name fragments that indicate a username / email input
_USERNAME_HINTS  = ("user", "email", "login", "mail", "identifier", "account", "uname")
_PASSWORD_HINTS  = ("pass", "pwd", "secret", "credential")
_CSRF_HINTS      = ("csrf", "token", "_token", "authenticity")
_IGNORE_TYPES    = ("submit", "button", "image", "reset", "checkbox", "radio", "hidden")


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

def extract_auth_targets(crawl_result: dict) -> list:
    """
    Iterates over all forms in *crawl_result* and returns a list of
    normalised target dicts ready for brute_force.py / sqli_engine.py.

    Target dict schema
    ──────────────────
    {
        "action":               str,   # URL to POST / JS endpoint hint
        "method":               str,   # "POST" | "GET"
        "username_field":       str,   # field name for username/email
        "password_field":       str,   # field name for password
        "extra_fields":         dict,  # hidden / CSRF fields
        "csrf_field":           str | None,
        "source_page":          str,   # page where form was found
        "is_spa":               bool,  # True → JS-rendered
        "playwright_needed":    bool,  # True → use browser-based attack
        "playwright_selectors": dict,  # {username: selector, password: selector, submit: selector}
        "content_type":         str,   # "application/x-www-form-urlencoded" | "application/json"
    }
    """
    targets: list = []

    for form in crawl_result.get("forms", []):
        if not form.get("is_auth"):
            continue

        target = _parse_form(form)
        if target:
            targets.append(target)

    # Deduplicate by action URL — keep the richest entry (most fields)
    targets = _deduplicate(targets)

    _print_targets_table(targets)
    return targets


# ─────────────────────────────────────────────────────────────────────────────
# INTERNAL PARSING
# ─────────────────────────────────────────────────────────────────────────────

def _parse_form(form: dict) -> dict | None:
    inputs = form.get("inputs", [])

    username_field    = None
    username_selector = None
    password_field    = None
    password_selector = None
    submit_selector   = "button[type='submit'], input[type='submit'], button"
    extra_fields: dict = {}
    csrf_field: str | None = None

    for inp in inputs:
        t    = inp.get("type", "text").lower()
        name = inp.get("name", "")
        sel  = inp.get("selector", f"[name='{name}']") if name else None

        if t == "password":
            password_field    = name
            password_selector = sel

        elif t in _IGNORE_TYPES:
            # Capture hidden fields for CSRF etc.
            if t == "hidden":
                extra_fields[name] = inp.get("value", "")
                if any(h in name.lower() for h in _CSRF_HINTS):
                    csrf_field = name
            # skip submit/button for field mapping

        elif t in ("text", "email", "tel") or any(h in name.lower() for h in _USERNAME_HINTS):
            if not username_field:   # first candidate wins
                username_field    = name
                username_selector = sel

    # Must have at least a password field to be a login form
    if not password_field:
        return None

    # Sensible defaults when username field wasn't found in the DOM
    if not username_field:
        # Prefer "email" for JSON / SPA, "username" for classic forms
        username_field = "email" if form.get("is_synthetic") else "username"

    is_spa            = form.get("is_synthetic", False)
    playwright_needed = form.get("playwright_needed", False)

    return {
        "action":   form.get("action", ""),
        "method":   form.get("method", "POST").upper(),

        "username_field":    username_field,
        "password_field":    password_field,
        "extra_fields":      extra_fields,
        "csrf_field":        csrf_field,

        "source_page":    form.get("page_url", ""),
        "is_spa":         is_spa,
        "playwright_needed": playwright_needed,

        # Selectors used by Playwright-based brute forcer
        "playwright_selectors": {
            "username": username_selector or f"input[type='text'], input[type='email'], [name='{username_field}']",
            "password": password_selector or f"input[type='password'], [name='{password_field}']",
            "submit":   submit_selector,
        },

        # Let attacker decide content type
        "content_type": (
            "application/json"
            if is_spa
            else "application/x-www-form-urlencoded"
        ),
    }


def _deduplicate(targets: list) -> list:
    """Keep one target per action URL, preferring the one with more extra_fields."""
    seen: dict = {}
    for t in targets:
        key = t["action"]
        if key not in seen or len(t["extra_fields"]) > len(seen[key]["extra_fields"]):
            seen[key] = t
    return list(seen.values())


# ─────────────────────────────────────────────────────────────────────────────
# DISPLAY
# ─────────────────────────────────────────────────────────────────────────────

def _print_targets_table(targets: list):
    if not targets:
        console.print("\n[bold red]✘  No auth forms detected.[/bold red]")
        console.print(
            "[dim]  Possible causes:\n"
            "   1. Page is a heavy SPA — install playwright:  pip install playwright && playwright install chromium\n"
            "   2. Login is behind another route — try passing the direct login URL.\n"
            "   3. App uses a custom Web Component not recognised by the parser.[/dim]\n"
        )
        return

    table = Table(title="Auth Targets Identified", border_style="bright_blue", show_lines=True)
    table.add_column("Mode",       style="yellow",  no_wrap=True)
    table.add_column("Action URL", style="cyan",    no_wrap=False)
    table.add_column("User Field", style="white")
    table.add_column("Pass Field", style="white")
    table.add_column("CSRF",       style="dim")
    table.add_column("Browser?",   style="magenta")

    for t in targets:
        if t.get("playwright_needed"):
            mode = "SPA-Browser"
        elif t.get("is_spa"):
            mode = "SPA-HTTP"
        else:
            mode = "Static"

        table.add_row(
            mode,
            t["action"],
            t["username_field"],
            t["password_field"],
            t.get("csrf_field") or "—",
            "✔" if t.get("playwright_needed") else "✘",
        )

    console.print(table)
    console.print(
        f"[dim]  {len(targets)} target(s) found. "
        f"'SPA-Browser' targets require Playwright for login interaction.[/dim]\n"
    )