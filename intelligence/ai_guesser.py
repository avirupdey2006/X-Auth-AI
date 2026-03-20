import os
import json
import re
import hashlib
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import google.generativeai as genai
from core.config import GEMINI_API_KEY, GEMINI_MODEL, AI_PASSWORD_COUNT, AI_CACHE_DIR
from core.logger import logger

console = Console()


def _configure_gemini():
    if not GEMINI_API_KEY:
        raise ValueError(
            "GEMINI_API_KEY is not set in .env — "
            "get a free key from aistudio.google.com"
        )
    genai.configure(api_key=GEMINI_API_KEY)
    return genai.GenerativeModel(GEMINI_MODEL)


def _cache_path(context: dict) -> str:
    """Generates a cache filename from the context so we don't re-call Gemini."""
    os.makedirs(AI_CACHE_DIR, exist_ok=True)
    key   = f"{context.get('company_name','')}{context.get('domain','')}"
    ckey  = hashlib.md5(key.encode()).hexdigest()[:12]
    return os.path.join(AI_CACHE_DIR, f"ai_wordlist_{ckey}.json")


def _build_prompt(context: dict, count: int) -> str:
    """
    Builds the structured prompt sent to Gemini.
    The prompt is designed to extract the maximum attack surface from context.
    """
    company   = context.get("company_name", "unknown")
    domain    = context.get("domain", "")
    parts     = context.get("domain_parts", [])
    usernames = context.get("usernames", [])
    keywords  = context.get("keywords", [])
    products  = context.get("product_names", [])
    year      = context.get("copyright_year", str(datetime.now().year))
    tech      = context.get("technologies", [])

    username_section = ""
    if usernames:
        username_section = f"""
Known usernames: {', '.join(usernames[:10])}
For each username, generate passwords combining that username with the patterns above.
"""

    return f"""You are a professional penetration tester generating a targeted password wordlist.

Target information:
- Company name: {company}
- Domain: {domain}
- Domain parts: {', '.join(parts)}
- Keywords found on site: {', '.join(keywords[:10])}
- Product/page names: {', '.join(products[:5])}
- Copyright year: {year}
- Technologies detected: {', '.join(tech[:3])}
{username_section}

Generate exactly {count} passwords that employees at this company are MOST LIKELY to use.
Apply these real-world password patterns:

1. Company name variations: {company}, {company.lower()}, {company.upper()}, {company}123, {company}@123, {company}2024, {company}2025, {company}!
2. Domain-based: {parts[0] if parts else company}, {parts[0]+year if parts else ''}, {domain.split('.')[0]}admin
3. Year patterns: append {year}, {int(year)-1 if year.isdigit() else '2024'}, {int(year)+1 if year.isdigit() else '2026'}
4. Common suffixes: @123, #123, !123, _123, .123, 123!, @2024, @2025, Admin, Pass, Login
5. Leet speak: replace a→@, e→3, i→1, o→0, s→$ on company name
6. Capitalization: Title case, ALL CAPS, camelCase combinations
7. Keyboard patterns combined with company: {company}qwerty, {company}1234
8. Service patterns: {company}admin, {company}root, admin{company}, {company}web
9. Short forms: first 4-6 chars of company name + numbers
10. Common Indian IT patterns (if applicable): {company}@India, {company}India123

Return ONLY a valid JSON array of strings. No explanation, no markdown, no backticks.
Example format: ["password1", "password2", "password3"]

Generate {count} passwords now:"""


def _parse_response(text: str) -> list:
    """
    Robustly parses Gemini's response even if it adds markdown or extra text.
    Strips ```json fences, finds the JSON array, and returns clean list.
    """
    # Strip markdown fences
    text = re.sub(r"```(?:json)?", "", text).strip()

    # Find JSON array
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if not match:
        logger.warning("Gemini response did not contain a JSON array")
        return []

    try:
        passwords = json.loads(match.group())
        # Filter: only strings, non-empty, reasonable length
        cleaned = [
            str(p).strip()
            for p in passwords
            if isinstance(p, (str, int)) and 1 <= len(str(p).strip()) <= 64
        ]
        return cleaned
    except json.JSONDecodeError as e:
        logger.warning(f"JSON parse failed: {e}")
        return []


def generate_ai_wordlist(context: dict, use_cache: bool = True) -> list:
    """
    Core Phase 3 function. Calls Gemini with the target context and returns
    a list of context-aware password guesses, deduplicated and sorted by
    likely effectiveness.

    Args:
        context: dict from context_builder.build_context()
        use_cache: if True, skips API call if cached wordlist exists

    Returns:
        list of password strings — empty list if API unavailable
    """
    cache_file = _cache_path(context)

    # Load from cache if available (saves API quota during demos)
    if use_cache and os.path.exists(cache_file):
        with open(cache_file) as f:
            cached = json.load(f)
        console.print(
            f"[dim]  AI wordlist loaded from cache: "
            f"{len(cached['passwords'])} passwords[/dim]"
        )
        return cached["passwords"]

    console.print(
        f"\n[bold yellow]AI Guesser:[/bold yellow] "
        f"Calling Gemini ({GEMINI_MODEL}) for "
        f"'{context.get('company_name', 'unknown')}'..."
    )

    try:
        model  = _configure_gemini()
        prompt = _build_prompt(context, AI_PASSWORD_COUNT)

        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.7,      # some creativity but not random
                max_output_tokens=8192,
            ),
        )

        raw_text  = response.text
        passwords = _parse_response(raw_text)

        if not passwords:
            console.print("[yellow]  AI returned no parseable passwords — using base wordlist only[/yellow]")
            return []

        # Deduplicate preserving order
        seen, unique = set(), []
        for p in passwords:
            if p not in seen:
                seen.add(p)
                unique.append(p)

        # Save to cache
        with open(cache_file, "w") as f:
            json.dump({
                "context":      context.get("company_name"),
                "generated_at": datetime.now().isoformat(),
                "model":        GEMINI_MODEL,
                "passwords":    unique,
            }, f, indent=2)

        _print_ai_results(unique, context)
        return unique

    except Exception as e:
        logger.error(f"Gemini API error: {e}")
        console.print(
            f"[yellow]  AI wordlist unavailable ({e}) — "
            f"falling back to base credential database[/yellow]"
        )
        return []


def _print_ai_results(passwords: list, context: dict):
    """Prints a rich summary of what Gemini generated."""
    table = Table(
        title=f"AI-generated wordlist — {context.get('company_name', 'target')}",
        border_style="yellow",
    )
    table.add_column("Sample passwords (first 20)", style="cyan")
    table.add_column("Pattern detected",             style="dim")

    company = context.get("company_name", "").lower()
    domain  = context.get("domain", "").split(".")[0].lower()

    for pw in passwords[:20]:
        pw_lower = pw.lower()
        if company in pw_lower:
            pattern = "company name variant"
        elif domain in pw_lower:
            pattern = "domain-based"
        elif any(c in pw for c in "@!#$"):
            pattern = "symbol complexity"
        elif pw.isdigit():
            pattern = "numeric only"
        elif pw[0].isupper():
            pattern = "capitalised"
        else:
            pattern = "common pattern"
        table.add_row(pw, pattern)

    console.print(table)
    console.print(
        f"[bold yellow]  {len(passwords)} AI passwords generated[/bold yellow] "
        f"— prepended to brute force queue\n"
    )