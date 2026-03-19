from rich.console import Console
from rich.table import Table

console = Console()

def extract_auth_targets(crawl_result: dict) -> list:
    targets = []

    for form in crawl_result.get("forms", []):
        if not form.get("is_auth"):
            continue

        username_field = None
        password_field = None
        extra_fields   = {}
        csrf_field     = None

        for inp in form["inputs"]:
            t = inp["type"].lower()
            n = inp["name"]

            if t == "password":
                password_field = n

            elif t in ("text", "email") and not username_field:
                username_field = n

            elif t == "hidden" and n:
                extra_fields[n] = inp["value"]

                # smarter CSRF detection
                if "token" in n.lower() or "csrf" in n.lower():
                    csrf_field = n

        if password_field:
            targets.append({
                "action":         form["action"],
                "method":         form["method"],
                "username_field": username_field or "username",
                "password_field": password_field,
                "extra_fields":   extra_fields,
                "csrf_field":     csrf_field,
                "source_page":    form["page_url"],
            })

    _print_targets_table(targets)
    return targets


def _print_targets_table(targets: list):
    if not targets:
        console.print("[yellow]No auth forms found.[/yellow]")
        return

    table = Table(title="Auth targets found", border_style="bright_blue")
    table.add_column("Action URL", style="cyan")
    table.add_column("Method")
    table.add_column("User")
    table.add_column("Pass")
    table.add_column("CSRF")

    for t in targets:
        table.add_row(
            t["action"],
            t["method"].upper(),
            t["username_field"],
            t["password_field"],
            t["csrf_field"] or "—",
        )

    console.print(table)