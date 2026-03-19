import os
from dotenv import load_dotenv

load_dotenv()

# Phase 1
HASHCAT_PATH     = os.getenv("HASHCAT_PATH", r"D:/D Downloads/hashcat-7.1.2/hashcat-7.1.2/hashcat.exe")
WORDLIST_DEFAULT = os.getenv("WORDLIST_DEFAULT", "lab/wordlists/rockyou.txt")
RESULTS_DIR      = os.getenv("RESULTS_DIR", "lab/results")
PROJECT_NAME     = os.getenv("PROJECT_NAME", "X-Auth-AI")

# Phase 2 — Scout
TARGET_TIMEOUT    = int(os.getenv("TARGET_TIMEOUT", 10))
MAX_THREADS       = int(os.getenv("MAX_THREADS", 10))

# Phase 2 — Attacker
MAX_BRUTE_ATTEMPTS = int(os.getenv("MAX_BRUTE_ATTEMPTS", 500))
RATE_LIMIT_REQUESTS  = int(os.getenv("RATE_LIMIT_REQUESTS", 100))
RATE_LIMIT_SECONDS   = float(os.getenv("RATE_LIMIT_SECONDS", 1))
SESSION_DELAY        = float(os.getenv("SESSION_DELAY", 0.3))

# Shared output
FINDINGS_DIR = "lab/results/findings"