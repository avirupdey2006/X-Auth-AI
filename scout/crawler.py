import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from fake_useragent import UserAgent
from collections import deque
from rich.console import Console
from rich.progress import track
from core.config import TARGET_TIMEOUT
from core.logger import logger

console = Console()
ua = UserAgent()


def _make_session() -> requests.Session:
    """Creates a randomised-header session to avoid trivial bot detection."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": ua.random,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    })
    return session


def crawl(base_url: str, max_pages: int = 50) -> dict:
    """
    BFS crawl from base_url.
    Returns:
        {
          "base_url": str,
          "pages_visited": [...],
          "forms": [...],          # all discovered forms
          "links": [...],          # all internal links found
          "errors": [...]
        }
    """
    parsed_base = urlparse(base_url)
    base_domain  = f"{parsed_base.scheme}://{parsed_base.netloc}"

    visited  = set()
    queue    = deque([base_url])
    pages    = []
    forms    = []
    all_links = []
    errors   = []

    session = _make_session()

    console.print(f"\n[bold cyan]Starting crawl:[/bold cyan] {base_url}")
    console.print(f"[dim]Max pages: {max_pages} | Timeout: {TARGET_TIMEOUT}s[/dim]\n")

    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = session.get(url, timeout=TARGET_TIMEOUT, verify=False, allow_redirects=True)
            resp.raise_for_status()
        except requests.exceptions.SSLError:
            # Retry without SSL verification for self-signed test certs
            try:
                resp = session.get(url, timeout=TARGET_TIMEOUT, verify=False)
            except Exception as e:
                errors.append({"url": url, "error": str(e)})
                continue
        except Exception as e:
            errors.append({"url": url, "error": str(e)})
            logger.warning(f"Failed to fetch {url}: {e}")
            continue

        soup = BeautifulSoup(resp.text, "lxml")
        page_forms = _extract_forms(url, soup)
        page_links = _extract_links(url, soup, base_domain)

        pages.append({
            "url":         url,
            "status_code": resp.status_code,
            "title":       soup.title.string.strip() if soup.title else "No title",
            "form_count":  len(page_forms),
        })
        forms.extend(page_forms)
        all_links.extend(page_links)

        # Enqueue unvisited internal links
        for link in page_links:
            if link not in visited:
                queue.append(link)

        console.print(f"  [green]+[/green] {url}  "
                      f"[dim]{resp.status_code} | {len(page_forms)} forms[/dim]")

    console.print(f"\n[bold]Crawl complete.[/bold] "
                  f"Pages: {len(pages)} | Forms: {len(forms)} | Errors: {len(errors)}\n")

    return {
        "base_url":      base_url,
        "pages_visited": pages,
        "forms":         forms,
        "links":         list(set(all_links)),
        "errors":        errors,
    }


def _extract_forms(page_url: str, soup: BeautifulSoup) -> list:
    """Extracts all forms and their input fields from a parsed page."""
    found = []
    for form in soup.find_all("form"):
        action  = form.get("action", "")
        method  = form.get("method", "get").lower()
        full_action = urljoin(page_url, action) if action else page_url

        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inp_type = inp.get("type", "text").lower()
            inp_name = inp.get("name", "")
            inp_id   = inp.get("id", "")
            if inp_name or inp_id:
                inputs.append({
                    "type":  inp_type,
                    "name":  inp_name,
                    "id":    inp_id,
                    "value": inp.get("value", ""),
                })

        # Flag auth-related forms immediately
        is_auth = _is_auth_form(inputs, form.get_text().lower())

        found.append({
            "page_url":  page_url,
            "action":    full_action,
            "method":    method,
            "inputs":    inputs,
            "is_auth":   is_auth,
        })

    return found


def _is_auth_form(inputs: list, form_text: str) -> bool:
    """Heuristic — is this a login / authentication form?"""
    auth_keywords = {"password", "passwd", "pwd", "login", "signin", "auth", "credentials"}
    for inp in inputs:
        name_lower = inp["name"].lower()
        type_lower = inp["type"].lower()
        if type_lower == "password":
            return True
        if any(kw in name_lower for kw in auth_keywords):
            return True
    if any(kw in form_text for kw in auth_keywords):
        return True
    return False


def _extract_links(page_url: str, soup: BeautifulSoup, base_domain: str) -> list:
    """Extracts all same-domain internal links."""
    links = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"]
        full = urljoin(page_url, href)
        parsed = urlparse(full)
        # Only keep same-domain, http/https links, no fragments or mailto
        if parsed.scheme in ("http", "https") and parsed.netloc == urlparse(base_domain).netloc:
            clean = full.split("#")[0]  # strip fragments
            if clean:
                links.append(clean)
    return links