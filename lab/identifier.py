import hashlib
import re
from rich.console import Console

console = Console()

HASH_PATTERNS = {
    "MD5":     (r"^[a-f0-9]{32}$",   "0"),   # Hashcat mode 0
    "SHA1":    (r"^[a-f0-9]{40}$",   "100"),
    "SHA256":  (r"^[a-f0-9]{64}$",   "1400"),
    "SHA512":  (r"^[a-f0-9]{128}$",  "1700"),
    "NTLM":    (r"^[a-f0-9]{32}$",   "1000"),  # same pattern as MD5, context matters
    "bcrypt":  (r"^\$2[ayb]\$.{56}$","3200"),
    "MD5crypt":(r"^\$1\$.{8}\$.{22}$","500"),
    "SHA512crypt":(r"^\$6\$.+\$.{86}$","1800"),
}

def identify_hash(hash_str: str) -> dict:
    """Returns hash type name and Hashcat mode number."""
    hash_str = hash_str.strip()
    matches = []
    for name, (pattern, mode) in HASH_PATTERNS.items():
        if re.match(pattern, hash_str, re.IGNORECASE):
            matches.append({"type": name, "hashcat_mode": mode})
    
    if not matches:
        return {"type": "UNKNOWN", "hashcat_mode": None}
    
    return matches[0]  # Return best match