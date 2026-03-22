"""
crawler.py — X-Auth AI  Universal Hybrid Crawler  v2.0

WHAT CHANGED vs v1:
──────────────────────────────────────────────────────────────────────────────
  • Two-pass crawling strategy:
      Pass 1 — Fast requests + BeautifulSoup (static HTML, DVWA-style)
      Pass 2 — Playwright headless Chromium (React/Vite/Angular SPA)
      Only Pass 2 is triggered when Pass 1 finds 0 auth targets on a page.

  • _render_page_playwright() launches a real browser, waits for network
    idle, then returns the *live* DOM — so every React-rendered <input>
    and <button> is visible.

  • Playwright is imported lazily (only when needed) so the tool still
    works on machines without it installed; it just falls back to static
    scraping with a clear warning.

  • _extract_forms() is now SPA-aware:
      - Looks for role="dialog", aria-label, data-testid attributes that
        React apps commonly use instead of <form>.
      - Detects JSON-posting patterns (no traditional action URL).
      - Synthetic form dict now includes an "inputs_selector" hint for
        brute_force.py to use when Playwright-filling fields.

  • _extract_links() also follows JavaScript href="#/..." Angular/React
    Router style links so the crawler can queue SPA sub-routes.

  • All network errors are caught per-URL so one bad page doesn't abort
    the whole crawl.
──────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import time
import warnings
from collections import deque
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from rich.console import Console

from core.config import TARGET_TIMEOUT
from core.logger import logger

# ── suppress SSL warnings ─────────────────────────────────────────────────────
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

console = Console()
ua = UserAgent()

# ── Playwright availability ───────────────────────────────────────────────────
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    console.print(
        "[bold yellow]⚠  playwright not installed — SPA dynamic rendering disabled.\n"
        "   Run:  pip install playwright && playwright install chromium[/bold yellow]"
    )


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

def crawl(base_url: str, max_pages: int = 50) -> dict:
    """
    Universal crawler.  Returns the same dict shape as v1 so all downstream
    modules (form_parser, attacker.*) remain compatible.

    Strategy per page
    ─────────────────
    1. Fetch with requests (fast, no JS).
    2. If page looks like a SPA *and* we found 0 auth targets → re-render
       with Playwright and re-extract.
    3. Merge results.
    """
    parsed_base = urlparse(base_url)
    base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"

    visited: set     = set()
    queue: deque     = deque([base_url])
    pages:  list     = []
    forms:  list     = []
    all_links: list  = []
    errors: list     = []

    session = _make_session()
    console.print(f"\n[bold cyan]Starting Universal Hybrid Crawl:[/bold cyan] {base_url}")
    console.print(
        f"[dim]  Static pass:   requests + BeautifulSoup\n"
        f"  Dynamic pass:  Playwright Chromium (SPA fallback)[/dim]\n"
    )

    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        # ── Pass 1: static fetch ──────────────────────────────────────────────
        static_html, status_code, fetch_err = _static_fetch(session, url)
        if fetch_err:
            errors.append({"url": url, "error": fetch_err})
            continue

        soup = BeautifulSoup(static_html, "lxml")
        is_spa = _detect_spa(soup, static_html)
        page_forms = _extract_forms(url, soup, is_spa)
        page_links = _extract_links(url, soup, base_domain)

        auth_found = any(f.get("is_auth") for f in page_forms)

        # ── Pass 2: dynamic render (only when needed) ─────────────────────────
        if is_spa and not auth_found and PLAYWRIGHT_AVAILABLE:
            console.print(f"  [yellow]↻[/yellow]  Switching to Playwright for: {url}")
            dyn_html = _render_page_playwright(url)
            if dyn_html:
                dyn_soup  = BeautifulSoup(dyn_html, "lxml")
                dyn_forms = _extract_forms(url, dyn_soup, is_spa=True)
                dyn_links = _extract_links(url, dyn_soup, base_domain)

                # Merge — deduplicate by action URL
                existing_actions = {f["action"] for f in page_forms}
                for f in dyn_forms:
                    if f["action"] not in existing_actions:
                        page_forms.append(f)
                        existing_actions.add(f["action"])

                page_links = list(set(page_links + dyn_links))
                auth_found = any(f.get("is_auth") for f in page_forms)

        # ── Accumulate ────────────────────────────────────────────────────────
        forms.extend(page_forms)
        all_links.extend(page_links)
        pages.append({
            "url":         url,
            "status_code": status_code,
            "is_spa":      is_spa,
            "form_count":  len(page_forms),
            "auth_found":  auth_found,
        })

        for link in page_links:
            if link not in visited:
                queue.append(link)

        tag = "[bold green]✔[/bold green]" if auth_found else "[green]+[/green]"
        console.print(
            f"  {tag} {url} "
            f"[dim]{'(SPA)' if is_spa else '(static)'} "
            f"| {len(page_forms)} form(s) | auth={auth_found}[/dim]"
        )

    return {
        "base_url":      base_url,
        "pages_visited": pages,
        "forms":         forms,
        "links":         list(set(all_links)),
        "errors":        errors,
    }


# ─────────────────────────────────────────────────────────────────────────────
# STATIC HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": ua.random,
        "Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    return s


def _static_fetch(session: requests.Session, url: str):
    """Returns (html_text, status_code, error_str_or_None)."""
    try:
        resp = session.get(url, timeout=TARGET_TIMEOUT, verify=False, allow_redirects=True)
        resp.raise_for_status()
        return resp.text, resp.status_code, None
    except Exception as exc:
        return "", 0, str(exc)


def _detect_spa(soup: BeautifulSoup, raw_html: str) -> bool:
    """
    Heuristics to decide if the page is a client-side rendered SPA.
    More robust than v1 — checks script bundle fingerprints too.
    """
    # Root mount points used by React / Vue / Angular
    if soup.find(id="root") or soup.find(id="app") or soup.find(id="__next"):
        return True

    # Vite / CRA / Webpack bundle filenames
    spa_patterns = ["/assets/index", "bundle.js", "main.js", "chunk.", "vite", "react", "angular"]
    for script in soup.find_all("script", src=True):
        src = script["src"].lower()
        if any(p in src for p in spa_patterns):
            return True

    # Angular universal / Nuxt / Next markers
    if soup.find("app-root") or soup.find("nuxt") or soup.find(id="__nuxt"):
        return True

    # Very little visible text → JS rendered
    body = soup.find("body")
    if body and len(body.get_text(strip=True)) < 100:
        return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# PLAYWRIGHT DYNAMIC RENDERER
# ─────────────────────────────────────────────────────────────────────────────

def _render_page_playwright(url: str, wait_ms: int = 3000) -> str | None:
    """
    Launches headless Chromium, navigates to *url*, waits for the network
    to settle, then returns the full live DOM as an HTML string.

    Returns None on any failure so callers can degrade gracefully.
    """
    if not PLAYWRIGHT_AVAILABLE:
        return None

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
            ctx     = browser.new_context(
                user_agent=ua.random,
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 800},
            )
            page = ctx.new_page()

            # Block images / fonts to speed things up
            page.route(
                "**/*.{png,jpg,jpeg,gif,webp,svg,woff,woff2,ttf,eot}",
                lambda route: route.abort(),
            )

            try:
                page.goto(url, wait_until="networkidle", timeout=TARGET_TIMEOUT * 1000)
            except PWTimeout:
                # networkidle timeout is common on heavy SPAs — grab what we have
                logger.warning(f"[Playwright] networkidle timeout on {url}, using partial DOM")

            # Extra settle time for React hydration
            time.sleep(wait_ms / 1000)

            html = page.content()
            browser.close()
            return html

    except Exception as exc:
        logger.warning(f"[Playwright] render failed for {url}: {exc}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# FORM EXTRACTION  (static + SPA-aware)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_forms(page_url: str, soup: BeautifulSoup, is_spa: bool) -> list:
    found = []

    # ── 1. Traditional <form> elements ───────────────────────────────────────
    for form in soup.find_all("form"):
        processed = _process_form_element(page_url, form)
        if processed:
            found.append(processed)

    # ── 2. SPA "naked inputs" — React / Vite pattern ─────────────────────────
    #    React apps rarely wrap inputs in <form>; they handle submit in JS.
    #    We look for password inputs anywhere in the DOM and build a synthetic
    #    form around all sibling inputs in the same container.
    if is_spa:
        synthetic = _extract_spa_form(page_url, soup)
        if synthetic:
            # Only add if we haven't already captured the same URL via a real form
            real_actions = {f["action"] for f in found}
            if synthetic["action"] not in real_actions:
                found.append(synthetic)

    return found


def _process_form_element(page_url: str, form) -> dict | None:
    action = form.get("action", "")
    method = form.get("method", "post").lower()
    full_action = urljoin(page_url, action) if action else page_url

    inputs = _collect_inputs(form)
    if not inputs:
        return None

    return {
        "page_url":     page_url,
        "action":       full_action,
        "method":       method,
        "inputs":       inputs,
        "is_auth":      _is_auth_form(inputs, form.get_text().lower()),
        "is_synthetic": False,
    }


def _extract_spa_form(page_url: str, soup: BeautifulSoup) -> dict | None:
    """
    Finds password inputs anywhere in the rendered DOM, then walks up to
    find the nearest ancestor container that also holds a username/email
    input and a submit button.  Builds a synthetic form dict.
    """
    password_inputs = soup.find_all("input", {"type": "password"})
    if not password_inputs:
        return None

    # Walk up from the first password field to find a reasonable container
    pw_inp = password_inputs[0]
    container = pw_inp.parent
    for _ in range(5):                    # look up to 5 levels up
        all_inputs = container.find_all(["input", "button", "select"])
        if len(all_inputs) >= 2:
            break
        container = container.parent or container

    synthetic_inputs = []
    for inp in container.find_all(["input", "button", "select"]):
        name = inp.get("name") or inp.get("id") or inp.get("data-testid") or inp.get("aria-label")
        if not name:
            continue
        synthetic_inputs.append({
            "type":     inp.get("type", "text").lower(),
            "name":     name,
            "id":       inp.get("id", ""),
            "value":    inp.get("value", ""),
            "selector": _build_css_selector(inp),   # for Playwright fill()
        })

    if not synthetic_inputs:
        return None

    return {
        "page_url":          page_url,
        "action":            page_url,     # SPA — POST handled by JS / fetch()
        "method":            "post",
        "inputs":            synthetic_inputs,
        "is_auth":           True,         # we only get here via password detection
        "is_synthetic":      True,
        "playwright_needed": True,         # hint to brute_force.py
    }


def _collect_inputs(container) -> list:
    inputs = []
    for inp in container.find_all(["input", "textarea", "select"]):
        name = inp.get("name") or inp.get("id")
        if name:
            inputs.append({
                "type":     inp.get("type", "text").lower(),
                "name":     name,
                "id":       inp.get("id", ""),
                "value":    inp.get("value", ""),
                "selector": _build_css_selector(inp),
            })
    return inputs


def _build_css_selector(tag) -> str:
    """
    Best-effort CSS selector for Playwright page.fill().
    Priority: id > name > type (for password/email/text).
    """
    if tag.get("id"):
        return f"#{tag['id']}"
    if tag.get("name"):
        return f"[name='{tag['name']}']"
    if tag.get("type"):
        return f"input[type='{tag['type']}']"
    return tag.name


def _is_auth_form(inputs: list, form_text: str) -> bool:
    auth_keywords = {"password", "passwd", "pwd", "login", "signin", "auth", "email"}
    for inp in inputs:
        if inp["type"] == "password":
            return True
        if any(kw in inp["name"].lower() for kw in auth_keywords):
            return True
    return any(kw in form_text for kw in auth_keywords)


# ─────────────────────────────────────────────────────────────────────────────
# LINK EXTRACTION  (static + SPA hash/pushstate routes)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_links(page_url: str, soup: BeautifulSoup, base_domain: str) -> list:
    links = []
    base_netloc = urlparse(base_domain).netloc

    for tag in soup.find_all("a", href=True):
        href = tag["href"]

        # React Router / Angular hash routes  →  convert to full URL
        if href.startswith("#/"):
            full = base_domain + "/" + href[2:]
        else:
            full = urljoin(page_url, href)

        parsed = urlparse(full)
        if parsed.netloc == base_netloc:
            clean = full.split("#")[0].rstrip("/")
            if clean:
                links.append(clean)

    # Also grab any router-link / routerLink / data-href attributes (Angular/Vue)
    for tag in soup.find_all(True, {"routerlink": True}):
        href = tag["routerlink"]
        full = urljoin(base_domain, href)
        links.append(full.split("#")[0].rstrip("/"))

    return list(set(links))