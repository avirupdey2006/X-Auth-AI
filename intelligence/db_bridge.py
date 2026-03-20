import os
import json
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.config import DB_CONNECTION_STRING, RESULTS_DIR
from core.logger import logger

console = Console()


def _get_engine(connection_string: str):
    """Creates SQLAlchemy engine. Supports SQLite, MySQL, PostgreSQL, MSSQL."""
    try:
        from sqlalchemy import create_engine
        return create_engine(connection_string, connect_args={"connect_timeout": 10})
    except ImportError:
        raise ImportError("sqlalchemy not installed — run: pip install sqlalchemy")
    except Exception as e:
        raise ConnectionError(f"Database connection failed: {e}")


def extract_hashes(
    connection_string: str = None,
    table_name:        str = "users",
    hash_column:       str = "password",
    username_column:   str = "username",
    limit:             int = 1000,
) -> dict:
    """
    Connects to a database and extracts username/hash pairs.
    These hashes are fed directly into Phase 1's Hashcat cracker.

    Args:
        connection_string: SQLAlchemy URI — e.g.
            "sqlite:///dvwa.db"
            "mysql+pymysql://root:pass@localhost/dvwa"
            "postgresql://user:pass@localhost/myapp"
        table_name:     table containing credentials (default: users)
        hash_column:    column name for hashed password (default: password)
        username_column:column name for username (default: username)
        limit:          max rows to extract (default: 1000)

    Returns:
        dict with extracted hashes and metadata
    """
    conn_str = connection_string or DB_CONNECTION_STRING

    if not conn_str:
        console.print(
            "[yellow]  DB Bridge: No connection string provided. "
            "Set DB_CONNECTION_STRING in .env or pass it via --db-url[/yellow]"
        )
        return {"status": "skipped", "hashes": [], "count": 0}

    console.print(f"\n[bold blue]DB Bridge:[/bold blue] connecting to database...")

    try:
        engine = _get_engine(conn_str)

        with engine.connect() as conn:
            from sqlalchemy import text

            # Try to auto-discover the password table if not specified
            tables = _discover_tables(conn)
            if table_name not in tables:
                auth_table = _find_auth_table(tables)
                if auth_table:
                    console.print(
                        f"  [dim]Table '{table_name}' not found — "
                        f"auto-detected '{auth_table}'[/dim]"
                    )
                    table_name = auth_table

            query = text(
                f"SELECT {username_column}, {hash_column} "
                f"FROM {table_name} LIMIT :limit"
            )
            rows = conn.execute(query, {"limit": limit}).fetchall()

        if not rows:
            console.print(f"[yellow]  No rows found in {table_name}.{hash_column}[/yellow]")
            return {"status": "empty", "hashes": [], "count": 0}

        hashes = []
        for row in rows:
            username = str(row[0]) if row[0] else "unknown"
            pw_hash  = str(row[1]) if row[1] else ""
            if pw_hash:
                hashes.append({
                    "username": username,
                    "hash":     pw_hash,
                    "table":    table_name,
                    "column":   hash_column,
                })

        # Save extracted hashes to disk for Hashcat
        os.makedirs(RESULTS_DIR, exist_ok=True)
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = os.path.join(RESULTS_DIR, f"extracted_hashes_{ts}.json")
        with open(out_file, "w") as f:
            json.dump(hashes, f, indent=2)

        # Also write plain hash list for Hashcat input
        hash_file = os.path.join(RESULTS_DIR, f"hashes_{ts}.txt")
        with open(hash_file, "w") as f:
            for h in hashes:
                f.write(h["hash"] + "\n")

        _print_hash_summary(hashes, out_file)

        return {
            "status":     "success",
            "hashes":     hashes,
            "count":      len(hashes),
            "saved_json": out_file,
            "saved_txt":  hash_file,
            "table":      table_name,
        }

    except Exception as e:
        logger.error(f"DB extraction failed: {e}")
        console.print(f"[red]  DB Bridge error: {e}[/red]")
        return {"status": "error", "error": str(e), "hashes": [], "count": 0}


def _discover_tables(conn) -> list:
    """Returns all table names in the database."""
    try:
        from sqlalchemy import text, inspect
        inspector = inspect(conn)
        return inspector.get_table_names()
    except Exception:
        return []


def _find_auth_table(tables: list) -> str:
    """Heuristic — finds the most likely auth table by name."""
    auth_names = [
        "users", "user", "accounts", "account", "members", "member",
        "credentials", "auth", "admins", "admin", "logins", "login",
        "customers", "employees", "staff",
    ]
    for name in auth_names:
        if name in [t.lower() for t in tables]:
            return name
    return tables[0] if tables else "users"


def _print_hash_summary(hashes: list, saved_path: str):
    """Prints a rich table of extracted hashes."""
    table = Table(
        title=f"Extracted hashes — {len(hashes)} records",
        border_style="blue",
    )
    table.add_column("Username",  style="cyan",    max_width=20)
    table.add_column("Hash",      style="dim",     max_width=45)
    table.add_column("Type hint", style="yellow")

    for h in hashes[:15]:
        hw    = h["hash"]
        hint  = _guess_hash_type(hw)
        table.add_row(h["username"], hw[:40] + "..." if len(hw) > 40 else hw, hint)

    if len(hashes) > 15:
        table.add_row(f"... +{len(hashes)-15} more", "", "")

    console.print(table)
    console.print(f"[dim]  Saved → {saved_path}[/dim]\n")


def _guess_hash_type(hash_str: str) -> str:
    """Quick pattern-based hash type hint for display."""
    h = hash_str.strip()
    if h.startswith("$2y$") or h.startswith("$2b$") or h.startswith("$2a$"):
        return "bcrypt"
    if h.startswith("$1$"):
        return "MD5-crypt"
    if h.startswith("$6$"):
        return "SHA-512 crypt"
    if h.startswith("$P$"):
        return "phpass (WordPress)"
    if len(h) == 32:
        return "MD5"
    if len(h) == 40:
        return "SHA1"
    if len(h) == 64:
        return "SHA256"
    if len(h) == 128:
        return "SHA512"
    return "unknown"