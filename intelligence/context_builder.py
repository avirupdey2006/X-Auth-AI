import requests
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from rich.console import Console
from core.config import TARGET_TIMEOUT
from core.logger import logger

console = Console()
ua      = UserAgent()


def build_context(target_url: str, company_name: str = "", usernames: list = None) -> dict:
    """
    Builds an intelligence context from the target URL.
    Scrapes the page for:
      - Company name, brand, product names
      - Domain name components
      - Copyright year
      - Meta keywords and description
      - Any visible proper nouns

    Returns a structured dict that ai_guesser.py turns into passwords.
    """
    usernames = usernames or []
    domain    = urlparse(target_url).netloc.replace("www.", "")
    domain_parts = re.split(r"[.\-_]", domain)

    context = {
        "target_url":    target_url,
        "domain":        domain,
        "domain_parts":  [p for p in domain_parts if len(p) > 2],
        "company_name":  company_name or "",
        "brand_names":   [],
        "product_names": [],
        "keywords":      [],
        "description":   "",
        "copyright_year":"",
        "usernames":     usernames,
        "technologies":  [],
    }

    try:
        session = requests.Session()
        session.headers["User-Agent"] = ua.random
        resp = session.get(target_url, timeout=TARGET_TIMEOUT, verify=False)
        soup = BeautifulSoup(resp.text, "lxml")

        # Page title → often contains company/brand name
        if soup.title and soup.title.string:
            title = soup.title.string.strip()
            context["brand_names"].append(title.split("|")[0].split("-")[0].strip())

        # Meta keywords
        meta_kw = soup.find("meta", {"name": re.compile("keyword", re.I)})
        if meta_kw and meta_kw.get("content"):
            kws = [k.strip() for k in meta_kw["content"].split(",")]
            context["keywords"].extend(kws[:10])

        # Meta description
        meta_desc = soup.find("meta", {"name": re.compile("description", re.I)})
        if meta_desc and meta_desc.get("content"):
            context["description"] = meta_desc["content"][:200]

        # Copyright year from footer
        footer_text = ""
        for tag in soup.find_all(["footer", "div"], class_=re.compile("footer|copyright", re.I)):
            footer_text += tag.get_text()
        year_match = re.search(r"20\d{2}", footer_text)
        if year_match:
            context["copyright_year"] = year_match.group()

        # Company name from meta og:site_name
        og_site = soup.find("meta", {"property": "og:site_name"})
        if og_site and og_site.get("content"):
            context["company_name"] = context["company_name"] or og_site["content"]

        # Detect technologies from meta generator or script src
        generator = soup.find("meta", {"name": "generator"})
        if generator and generator.get("content"):
            context["technologies"].append(generator["content"])

        # H1/H2 headings → product names
        for h in soup.find_all(["h1", "h2"])[:5]:
            text = h.get_text(strip=True)
            if 2 < len(text) < 40:
                context["product_names"].append(text)

        # Auto-detect company name from domain if still empty
        if not context["company_name"] and context["domain_parts"]:
            context["company_name"] = context["domain_parts"][0].capitalize()

        console.print(
            f"[dim]  Context built — company: '{context['company_name']}' | "
            f"domain: {domain} | "
            f"keywords: {len(context['keywords'])}[/dim]"
        )

    except Exception as e:
        logger.warning(f"Context build failed: {e} — using domain info only")

    return context