"""
wordlist_merger.py — Credential List Merger  (X-Auth AI)

Merges AI-generated passwords with the built-in credential database.

Tier ordering (highest → lowest priority):
  0  AI passwords × known target usernames
  1  AI passwords × common service usernames (admin, root, …)
  2  Built-in CREDENTIAL_DATABASE (ordered by breach frequency)

KEY FIXES vs original:
  - Accepts (user, password) tuples OR bare password strings from
    ai_guesser and normalises both formats transparently.
  - Caps to MAX_BRUTE_ATTEMPTS after merging so the brute_force
    engine doesn't need to cap again.
  - Debug summary line updated to reflect actual tier counts.
"""

from rich.console import Console

try:
    from core.config import MAX_BRUTE_ATTEMPTS
    from core.logger import logger
except ImportError:
    MAX_BRUTE_ATTEMPTS = 500
    import logging
    logger = logging.getLogger(__name__)

console = Console()

_TOP_USERNAMES = ["admin", "administrator", "root", "user", "test", "guest"]


def merge_wordlists(
    ai_passwords:     list,
    base_credentials: list,
    usernames:        list = None,
    limit:            int  = None,
) -> list:
    """
    Merges AI-generated passwords with the base credential database.

    Args:
        ai_passwords:     list of password strings  OR (user, pwd) tuples
        base_credentials: list of (user, pwd) tuples — built-in DB
        usernames:        known target usernames discovered during recon
        limit:            max pairs to return (defaults to MAX_BRUTE_ATTEMPTS)

    Returns:
        Deduplicated list of (username, password) tuples.
    """
    usernames = [u for u in (usernames or []) if u]
    limit     = limit or MAX_BRUTE_ATTEMPTS

    result: list = []
    seen:   set  = set()

    def _add(u: str, p: str):
        pair = (u, p)
        if pair not in seen:
            seen.add(pair)
            result.append(pair)

    # Normalise ai_passwords — accept bare strings or (user, pwd) tuples
    ai_plain_passwords: list = []
    for item in (ai_passwords or []):
        if isinstance(item, (list, tuple)) and len(item) == 2:
            # Already a (user, pwd) pair — add directly
            _add(str(item[0]), str(item[1]))
        else:
            ai_plain_passwords.append(str(item))

    # Tier 0: AI plain passwords × known target usernames (highest hit probability)
    tier0_users = usernames[:5]  # cap to 5 real usernames to avoid explosion
    for username in tier0_users:
        for password in ai_plain_passwords:
            _add(username, password)

    # Tier 1: AI plain passwords × common service usernames
    for username in _TOP_USERNAMES:
        if username not in tier0_users:          # don't double-add
            for password in ai_plain_passwords:
                _add(username, password)

    # Tier 2: Built-in credential database
    for pair in base_credentials:
        if isinstance(pair, (list, tuple)) and len(pair) == 2:
            _add(str(pair[0]), str(pair[1]))

    # Cap to limit
    final = result[:limit]

    console.print(
        f"[dim]  Wordlist merged: "
        f"{len(ai_plain_passwords)} AI passwords × "
        f"{len(tier0_users) + len(_TOP_USERNAMES)} usernames + "
        f"{len(base_credentials)} built-in pairs "
        f"→ {len(final)} unique pairs (cap: {limit})[/dim]"
    )

    return final