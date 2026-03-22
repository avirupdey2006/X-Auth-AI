"""
ai_guesser.py — Local Rule-Based Intelligence Engine  (X-Auth AI)

Fully offline — zero API calls, zero quota issues.
Uses real penetration-testing password-mutation rules to generate
context-aware candidates from scraped target intelligence.

KEY FIXES vs original:
  1. Cache key now includes a version stamp — old cache entries are
     automatically invalidated when AI_PASSWORD_COUNT changes.
  2. _generate_base_tokens() guards against None values in context
     fields that arrived from a failed context_builder scrape.
  3. _mutate_token() deduplicates its own output before returning so
     the global set doesn't waste time re-inserting duplicates.
  4. generate_ai_wordlist() logs what it's doing at each stage so
     the operator can see progress in real time.
  5. DVWA default passwords added explicitly to COMMON_PASSWORDS.
"""

import os
import json
import hashlib
from datetime import datetime
from rich.console import Console
from rich.table import Table

try:
    from core.config import AI_PASSWORD_COUNT, AI_CACHE_DIR
    from core.logger import logger
except ImportError:
    AI_PASSWORD_COUNT = 150
    AI_CACHE_DIR      = "lab/cache"
    import logging
    logger = logging.getLogger(__name__)

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# MUTATION BANKS
# ─────────────────────────────────────────────────────────────────────────────
YEAR_SUFFIXES     = ["2023", "2024", "2025", "2026", "23", "24", "25"]
NUMBER_SUFFIXES   = ["1", "12", "123", "1234", "12345",
                     "0", "01", "007", "111", "000", "99", "100"]
SYMBOL_SUFFIXES   = ["!", "@", "#", "$", "!!", "@123", "#123",
                     "!123", "@2024", "@2025", "!2024", "!2025"]
WORD_SUFFIXES     = ["admin", "root", "pass", "pwd", "login",
                     "web",   "user", "test", "dev", "prod", "india"]
KEYBOARD_PATTERNS = ["qwerty", "qwerty123", "1234", "12345",
                     "123456", "abcd", "abcd1234"]
INDIAN_SUFFIXES   = ["@India", "India123", "@india", "india@123",
                     "India@1", "India@123", "Ind@123"]

# Global fallback / safety-net passwords
# Includes DVWA defaults so they're always in the queue.
COMMON_PASSWORDS = [
    # DVWA defaults (always try these first for lab targets)
    "password", "admin", "gordonb", "abc123", "charley",
    # Generic commons
    "password1",  "password123", "Password1",  "Password@1",
    "welcome1",   "Welcome1",    "Welcome@1",   "changeme",
    "letmein",    "admin123",    "Admin123",    "admin@123",
    "Admin@123",  "root",        "toor",        "pass",
    "test",       "guest",       "qwerty",      "iloveyou",
    "monkey",     "dragon",      "master",      "shadow",
    "123456",     "1234567",     "12345678",    "123456789",
    "1234567890",
]

# Cache version — bump this if mutation logic changes so stale caches
# are automatically rebuilt.
_CACHE_VERSION = "v3"


# ─────────────────────────────────────────────────────────────────────────────
# PRIVATE HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _leet(word: str) -> str:
    """Classic leet-speak substitution."""
    return (word
            .replace("a", "@").replace("A", "@")
            .replace("e", "3").replace("E", "3")
            .replace("i", "1").replace("I", "1")
            .replace("o", "0").replace("O", "0")
            .replace("s", "$").replace("S", "$"))


def _capitalizations(word: str) -> list:
    """Returns common capitalisation variants of a word."""
    if not word:
        return []
    return list({
        word,
        word.lower(),
        word.upper(),
        word.capitalize(),
        word.title(),
        word[0].upper() + word[1:].lower() if len(word) > 1 else word.upper(),
    })


def _safe_str(val) -> str:
    """Coerce any context field safely to str, returning '' on None/falsy."""
    if not val:
        return ""
    return str(val).strip()


def _generate_base_tokens(context: dict):
    """
    Extracts all meaningful tokens from the context dict.
    Returns (sorted token list, year string).
    """
    tokens  = set()
    company = _safe_str(context.get("company_name"))
    domain  = _safe_str(context.get("domain"))
    parts   = [_safe_str(p) for p in (context.get("domain_parts") or []) if p]
    kws     = [_safe_str(k) for k in (context.get("keywords")      or []) if k]
    prods   = [_safe_str(p) for p in (context.get("product_names") or []) if p]
    brands  = [_safe_str(b) for b in (context.get("brand_names")   or []) if b]
    year    = _safe_str(context.get("copyright_year")) or str(datetime.now().year)

    if company:
        for variant in [company, company.lower(), company.upper(),
                        company[:4], company[:6], _leet(company), _leet(company.lower())]:
            if variant:
                tokens.add(variant)

    for part in parts:
        if len(part) > 1:
            tokens.update([part, part.lower(), part.capitalize()])

    if domain:
        base = domain.split(".")[0]
        tokens.update([base, base.capitalize()])

    for kw in (kws + prods + brands):
        clean = kw.split()[0] if kw.split() else ""
        if 2 < len(clean) < 20:
            tokens.update([clean, clean.lower(), clean.capitalize()])

    tokens = {t for t in tokens if t and t.strip()}
    return sorted(tokens), year


def _mutate_token(token: str, year: str) -> list:
    """Applies all real-world password mutation patterns to a single token."""
    results = set()
    caps    = _capitalizations(token)

    for base in caps:
        results.add(base)

        for n in NUMBER_SUFFIXES:
            results.add(base + n)
            results.add(n + base)

        for y in YEAR_SUFFIXES:
            results.add(base + y)
            results.add(base + "@" + y)
            results.add(base + "!" + y)

        for sym in SYMBOL_SUFFIXES:
            results.add(base + sym)

        for w in WORD_SUFFIXES:
            results.add(base + w)
            results.add(base + w.capitalize())
            results.add(base + "_" + w)
            results.add(base + "@" + w)

        for kb in KEYBOARD_PATTERNS:
            results.add(base + kb)

        for ind in INDIAN_SUFFIXES:
            results.add(base + ind)

        for n in ["1", "123", "12"]:
            results.add(base + n + "!")
            results.add(base + n + "@")
            results.add(base + "@" + n)

        if year:
            results.add(base + year)
            results.add(base + "@" + year)
            results.add(base + year + "!")
            results.add(base + year + "@")

    return list(results)


def _generate_username_combos(usernames: list, year: str) -> list:
    """Generates targeted password candidates for known usernames."""
    results = set()
    for user in usernames:
        if not user:
            continue
        for base in _capitalizations(user):
            results.add(base)
            for n in NUMBER_SUFFIXES[:6]:
                results.add(base + n)
            for sym in ["!", "@", "#", "@123", "!123"]:
                results.add(base + sym)
            for y in [year, "2024", "2025"]:
                results.add(base + y)
                results.add(base + "@" + y)
            results.add(base + "_" + base)
            results.add(base + base)
            results.add(base + "123!")
            results.add(base + "@India")
            results.add(base + "India123")
    return list(results)


def _cache_path(context: dict) -> str:
    os.makedirs(AI_CACHE_DIR, exist_ok=True)
    key  = f"{_CACHE_VERSION}:{context.get('company_name', '')}:{context.get('domain', '')}:{AI_PASSWORD_COUNT}"
    ckey = hashlib.md5(key.encode()).hexdigest()[:12]
    return os.path.join(AI_CACHE_DIR, f"ai_wordlist_{ckey}.json")


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────
def generate_ai_wordlist(context: dict, use_cache: bool = True) -> list:
    """
    Local rule-based intelligence engine.
    Generates context-aware password candidates using pentest mutation rules.

    Args:
        context:   dict from context_builder.build_context()
        use_cache: load cached wordlist on repeat runs (invalidated by version)

    Returns:
        list of password strings, sorted by likely effectiveness
    """
    cache_file = _cache_path(context)

    if use_cache and os.path.exists(cache_file):
        try:
            with open(cache_file) as f:
                cached = json.load(f)
            passwords = cached.get("passwords", [])
            console.print(
                f"[dim]  AI wordlist loaded from cache: {len(passwords)} passwords[/dim]"
            )
            return passwords
        except (json.JSONDecodeError, KeyError):
            logger.warning("[AI] Cache corrupt — regenerating.")

    company   = _safe_str(context.get("company_name")) or "target"
    usernames = [_safe_str(u) for u in (context.get("usernames") or []) if u]

    console.print(
        f"\n[bold yellow]AI Guesser:[/bold yellow] "
        f"Local engine for '[cyan]{company}[/cyan]' "
        f"({len(usernames)} known usernames)..."
    )

    tokens, year = _generate_base_tokens(context)
    console.print(f"[dim]  Tokens extracted: {len(tokens)}[/dim]")

    all_passwords: set = set()

    # 1. Mutate every context token
    for token in tokens:
        all_passwords.update(_mutate_token(token, year))
    console.print(f"[dim]  After token mutation: {len(all_passwords)} candidates[/dim]")

    # 2. Username-specific combos
    all_passwords.update(_generate_username_combos(usernames, year))
    console.print(f"[dim]  After username combos: {len(all_passwords)} candidates[/dim]")

    # 3. Global common passwords — always include as safety net
    all_passwords.update(COMMON_PASSWORDS)

    # Filter: non-empty, reasonable length
    cleaned = [p.strip() for p in all_passwords if p and 1 <= len(p.strip()) <= 64]

    # Sort: company variants first, then username variants, then commons, then rest
    company_lower   = company.lower()
    usernames_lower = [u.lower() for u in usernames]

    def _priority(pw: str) -> int:
        pw_l = pw.lower()
        if company_lower and company_lower in pw_l:
            return 0
        if any(u in pw_l for u in usernames_lower):
            return 1
        if pw in COMMON_PASSWORDS:
            return 2
        return 3

    cleaned.sort(key=lambda pw: (_priority(pw), len(pw)))

    # Deduplicate preserving order, cap at AI_PASSWORD_COUNT
    unique = list(dict.fromkeys(cleaned))[:AI_PASSWORD_COUNT]

    # Save to cache
    try:
        with open(cache_file, "w") as f:
            json.dump({
                "context":      company,
                "generated_at": datetime.now().isoformat(),
                "engine":       "local-rule-based",
                "version":      _CACHE_VERSION,
                "passwords":    unique,
            }, f, indent=2)
    except OSError as exc:
        logger.warning(f"[AI] Could not write cache: {exc}")

    _print_ai_results(unique, context)
    return unique


def _print_ai_results(passwords: list, context: dict):
    table = Table(
        title=f"AI-generated wordlist — {context.get('company_name', 'target')}",
        border_style="yellow",
    )
    table.add_column("Sample passwords (first 20)", style="cyan")
    table.add_column("Pattern",                      style="dim")

    company         = _safe_str(context.get("company_name")).lower()
    domain          = _safe_str(context.get("domain")).split(".")[0].lower()
    usernames_lower = [u.lower() for u in (context.get("usernames") or []) if u]

    for pw in passwords[:20]:
        pw_l = pw.lower()
        if company and company in pw_l:
            pattern = "company name variant"
        elif any(u in pw_l for u in usernames_lower):
            pattern = "username variant"
        elif domain and domain in pw_l:
            pattern = "domain-based"
        elif "india" in pw_l:
            pattern = "Indian IT pattern"
        elif any(c in pw for c in "@!#$"):
            pattern = "symbol complexity"
        elif pw.isdigit():
            pattern = "numeric only"
        elif pw and pw[0].isupper():
            pattern = "capitalised"
        else:
            pattern = "common pattern"
        table.add_row(pw, pattern)

    console.print(table)
    console.print(
        f"[bold yellow]  {len(passwords)} passwords generated locally[/bold yellow] "
        f"— will be prepended to brute force queue\n"
    )