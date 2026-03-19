import subprocess
import os
import uuid
from rich.console import Console
from core.config import HASHCAT_PATH, WORDLIST_DEFAULT, RESULTS_DIR
from lab.identifier import identify_hash

console = Console()

def run_hashcat(hash_str: str, wordlist: str = WORDLIST_DEFAULT, rules: bool = True) -> dict:
    hash_info = identify_hash(hash_str)
    mode = str(hash_info.get("hashcat_mode"))

    if not mode:
        return {"status": "error", "message": "Unknown hash type"}

    os.makedirs(RESULTS_DIR, exist_ok=True)

    # Unique filenames (important)
    session_id = str(uuid.uuid4())[:8]
    hash_file = os.path.join(RESULTS_DIR, f"hash_{session_id}.txt")
    outfile = os.path.join(RESULTS_DIR, f"cracked_{session_id}.txt")

    # Write hash to file (CRITICAL FIX)
    with open(hash_file, "w") as f:
        f.write(hash_str + "\n")

    cmd = [
        HASHCAT_PATH,
        "-m", mode,
        "-a", "0",
        hash_file,
        wordlist,
        "-o", outfile,
        "-O",                 # optimized kernel
        "-d", "1",            # GPU only
        "--status",
        "--status-timer=5",
        "--quiet"
    ]

    # Add rules
    if rules:
        rules_path = os.path.join(os.path.dirname(HASHCAT_PATH), "rules", "best64.rule")
        if os.path.exists(rules_path):
            cmd.extend(["-r", rules_path])

    console.print(f"[bold cyan]Launching Hashcat GPU engine...[/bold cyan]")
    console.print(f"[dim]{' '.join(cmd)}[/dim]\n")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        # Debug logs (VERY useful)
        if result.stderr:
            console.print(f"[red]{result.stderr}[/red]")

        # Check result
        if os.path.exists(outfile):
            with open(outfile) as f:
                for line in f:
                    if ":" in line:
                        cracked_pw = line.strip().split(":")[-1]
                        return {
                            "status": "cracked",
                            "password": cracked_pw,
                            "method": "hashcat_gpu",
                            "session": session_id
                        }

    except subprocess.TimeoutExpired:
        return {"status": "timeout", "message": "Hashcat timed out"}
    except FileNotFoundError:
        return {"status": "error", "message": f"Hashcat not found at {HASHCAT_PATH}"}

    return {"status": "not_found", "method": "hashcat_gpu", "session": session_id}