"""
context_builder.py — Target Intelligence Builder  (X-Auth AI)

Scrapes the target login page and surrounding HTML to extract company
branding, keywords, and technology signals that the AI guesser uses
to generate context-aware password candidates.

KEY FIXES vs original:
  1. All scraped values are sanitised through _safe_text() before being
     stored — eliminates NoneType errors downstream in ai_guesser.
  2. domain_parts filter now rejects single-character strings AND
     common TLD noise ("com", "org", "net", etc.).
  3. Company name auto-detection falls back gracefully when domain_parts
     is empty (e.g. "localhost").
  4. Timeout and SSL errors are caught separately for cleaner log output.
  5. Returns a fully-populated context dict even when every scrape step
     fails (so ai_guesser can still generate COMMON_PASSWORDS).
"""

import requests
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from rich.console import Console

try:
    from core.config import TARGET_TIMEOUT
    from core.logger import logger
except ImportError:
    TARGET_TIMEOUT = 10
    import logging
    logger = logging.getLogger(__name__)

console = Console()
ua      = UserAgent()

# TLD / noise words to exclude from domain_parts
_NOISE = {"com", "org", "net", "io", "co", "uk", "in", "edu", "gov",
          "php", "html", "asp", "aspx", "jsp", "www"}


def _safe_text(val) -> str:
    """Coerce to str and strip whitespace; return '' for None/falsy."""
    return str(val).strip() if val else ""


def build_context(
    target_url:   str,
    company_name: str  = "",
    usernames:    list = None,
) -> dict:
    """
    Builds an intelligence context from the target URL.

    Scrapes for:
      - Company / brand name
      - Domain components
      - Copyright year
      - Meta keywords & description
      - H1/H2 headings (product names)
      - Technology hints (generator meta, script patterns)

    Returns a structured dict consumed by ai_guesser.generate_ai_wordlist().
    Always returns a valid dict even if the request fails.
    """
    usernames = [_safe_text(u) for u in (usernames or []) if u]

    parsed       = urlparse(target_url)
    raw_domain   = parsed.netloc.replace("www.", "").split(":")[0]   # strip port
    domain_parts = [
        p for p in re.split(r"[.\-_]", raw_domain)
        if len(p) > 1 and p.lower() not in _NOISE
    ]

    context = {
        "target_url":     target_url,
        "domain":         raw_domain,
        "domain_parts":   domain_parts,
        "company_name":   _safe_text(company_name),
        "brand_names":    [],
        "product_names":  [],
        "keywords":       [],
        "description":    "",
        "copyright_year": "",
        "usernames":      usernames,
        "technologies":   [],
    }

    try:
        session = requests.Session()
        session.headers["User-Agent"] = ua.random
        resp = session.get(
            target_url,
            timeout=TARGET_TIMEOUT,
            verify=False,
            allow_redirects=True,
        )
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")

        # ── Page title → company/brand name candidate ──────────────────────
        if soup.title and soup.title.string:
            raw_title = _safe_text(soup.title.string)
            # Take the first segment before | or -
            brand_candidate = re.split(r"[|\-–]", raw_title)[0].strip()
            if brand_candidate:
                context["brand_names"].append(brand_candidate)

        # ── og:site_name → authoritative company name ──────────────────────
        og_site = soup.find("meta", {"property": "og:site_name"})
        if og_site:
            val = _safe_text(og_site.get("content"))
            if val and not context["company_name"]:
                context["company_name"] = val

        # ── Meta keywords ───────────────────────────────────────────────────
        meta_kw = soup.find("meta", {"name": re.compile(r"keyword", re.I)})
        if meta_kw:
            content = _safe_text(meta_kw.get("content"))
            if content:
                context["keywords"] = [k.strip() for k in content.split(",")][:10]

        # ── Meta description ────────────────────────────────────────────────
        meta_desc = soup.find("meta", {"name": re.compile(r"description", re.I)})
        if meta_desc:
            context["description"] = _safe_text(meta_desc.get("content"))[:200]

        # ── Copyright year from footer ──────────────────────────────────────
        footer_text = ""
        for tag in soup.find_all(["footer", "div"],
                                  class_=re.compile(r"footer|copyright", re.I)):
            footer_text += tag.get_text()
        year_match = re.search(r"20\d{2}", footer_text)
        if year_match:
            context["copyright_year"] = year_match.group()

        # ── generator meta → technology hint ───────────────────────────────
        gen = soup.find("meta", {"name": "generator"})
        if gen:
            val = _safe_text(gen.get("content"))
            if val:
                context["technologies"].append(val)

        # ── H1/H2 headings → product name candidates ───────────────────────
        for h in soup.find_all(["h1", "h2"])[:5]:
            text = _safe_text(h.get_text())
            if 2 < len(text) < 40:
                context["product_names"].append(text)

        # ── Auto-detect company name from domain if still empty ─────────────
        if not context["company_name"]:
            if domain_parts:
                context["company_name"] = domain_parts[0].capitalize()
            else:
                # localhost or bare IP — use URL host as fallback
                context["company_name"] = parsed.hostname or "target"

        console.print(
            f"[dim]  Context built — company: '{context['company_name']}' | "
            f"domain: {raw_domain} | "
            f"keywords: {len(context['keywords'])} | "
            f"usernames: {usernames}[/dim]"
        )

    except requests.exceptions.Timeout:
        logger.warning(f"[Context] Request timed out for {target_url} — using domain info only")
        _apply_domain_fallback(context, parsed)
    except requests.exceptions.SSLError:
        logger.warning(f"[Context] SSL error for {target_url} — using domain info only")
        _apply_domain_fallback(context, parsed)
    except Exception as exc:
        logger.warning(f"[Context] Scrape failed: {exc} — using domain info only")
        _apply_domain_fallback(context, parsed)

    return context


def _apply_domain_fallback(context: dict, parsed):
    """Fills in the minimum useful context when the HTTP request fails."""
    if not context["company_name"]:
        if context["domain_parts"]:
            context["company_name"] = context["domain_parts"][0].capitalize()
        else:
            context["company_name"] = _safe_text(parsed.hostname) or "target"