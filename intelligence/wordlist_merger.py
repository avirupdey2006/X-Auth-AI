from rich.console import Console

console = Console()


def merge_wordlists(
    ai_passwords:    list,
    base_credentials: list,
    usernames:        list = None,
) -> list:
    """
    Merges AI-generated passwords with the base credential database.

    Strategy:
    1. AI passwords × known usernames go FIRST (highest hit probability)
    2. AI passwords × common usernames (admin, root, etc.) second
    3. Base credential database last as fallback

    Returns deduplicated list of (username, password) tuples.
    """
    usernames = usernames or []
    result    = []
    seen      = set()

    def add(u, p):
        if (u, p) not in seen:
            seen.add((u, p))
            result.append((u, p))

    # Tier 0: AI passwords × usernames found on the target
    if usernames and ai_passwords:
        for username in usernames[:5]:       # cap to 5 real usernames
            for password in ai_passwords:
                add(username, password)

    # Tier 1: AI passwords × top common usernames
    top_usernames = ["admin", "administrator", "root", "user", "test"]
    for username in top_usernames:
        for password in ai_passwords:
            add(username, password)

    # Tier 2: Base credential database (already ordered by breach frequency)
    for pair in base_credentials:
        add(pair[0], pair[1])

    console.print(
        f"[dim]  Wordlist merged: "
        f"{len(ai_passwords)} AI passwords × "
        f"{len(usernames) + len(top_usernames)} usernames + "
        f"{len(base_credentials)} base creds "
        f"= {len(result)} unique pairs[/dim]"
    )

    return result