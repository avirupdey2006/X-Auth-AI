import hashlib
import time
from tqdm import tqdm
from rich.console import Console
from rich.table import Table
from core.config import WORDLIST_DEFAULT
from lab.identifier import identify_hash

console = Console()

def _compute_hash(password: str, hash_type: str) -> str:
    pw_bytes = password.encode("utf-8", errors="ignore")
    if hash_type == "MD5":
        return hashlib.md5(pw_bytes).hexdigest()
    elif hash_type == "SHA1":
        return hashlib.sha1(pw_bytes).hexdigest()
    elif hash_type == "SHA256":
        return hashlib.sha256(pw_bytes).hexdigest()
    elif hash_type == "SHA512":
        return hashlib.sha512(pw_bytes).hexdigest()
    return ""

def crack(hash_str: str, wordlist_path: str = WORDLIST_DEFAULT) -> dict:
    hash_str = hash_str.strip()
    hash_info = identify_hash(hash_str)
    
    console.print(f"\n[bold]Target hash:[/bold] {hash_str}")
    console.print(f"[bold]Detected type:[/bold] [cyan]{hash_info['type']}[/cyan]")
    console.print(f"[bold]Hashcat mode:[/bold] {hash_info['hashcat_mode']}\n")

    start_time = time.time()
    
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except FileNotFoundError:
        console.print(f"[red]Wordlist not found: {wordlist_path}[/red]")
        return {"status": "error", "message": "Wordlist not found"}

    console.print(f"[dim]Scanning {len(lines):,} passwords...[/dim]")
    
    for password in tqdm(lines, desc="Cracking", unit="pw", colour="cyan"):
        password = password.strip()
        if not password:
            continue
        candidate_hash = _compute_hash(password, hash_info["type"])
        if candidate_hash == hash_str.lower():
            elapsed = time.time() - start_time
            result = {
                "status":    "cracked",
                "hash":      hash_str,
                "type":      hash_info["type"],
                "password":  password,
                "time_sec":  round(elapsed, 2),
                "method":    "wordlist"
            }
            console.print(f"\n[bold green]CRACKED![/bold green]  Password: [bold]{password}[/bold]  ({elapsed:.2f}s)")
            return result
    
    elapsed = time.time() - start_time
    console.print(f"\n[yellow]Not found in wordlist.[/yellow] Elapsed: {elapsed:.1f}s → escalating to Hashcat GPU...")
    return {"status": "not_found", "hash": hash_str, "type": hash_info["type"], "method": "wordlist"}