import os
from dotenv import load_dotenv

load_dotenv()

# ── Phase 1 ──
HASHCAT_PATH      = os.getenv("HASHCAT_PATH", r"D:/D Downloads/hashcat-7.1.2/hashcat-7.1.2/hashcat.exe")
WORDLIST_DEFAULT  = os.getenv("WORDLIST_DEFAULT", "lab/wordlists/rockyou.txt")
RESULTS_DIR       = os.getenv("RESULTS_DIR", "lab/results")
PROJECT_NAME      = os.getenv("PROJECT_NAME", "X-Auth-AI")

# ── Phase 2 ──
TARGET_TIMEOUT       = int(os.getenv("TARGET_TIMEOUT", 10))
MAX_THREADS          = int(os.getenv("MAX_THREADS", 10))
MAX_BRUTE_ATTEMPTS   = int(os.getenv("MAX_BRUTE_ATTEMPTS", 500))
RATE_LIMIT_REQUESTS  = int(os.getenv("RATE_LIMIT_REQUESTS", 100))
RATE_LIMIT_SECONDS   = float(os.getenv("RATE_LIMIT_SECONDS", 1))
SESSION_DELAY        = float(os.getenv("SESSION_DELAY", 0.3))

# ── Phase 3 ──
GEMINI_API_KEY        = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL          = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
AI_PASSWORD_COUNT     = int(os.getenv("AI_PASSWORD_COUNT", 150))
DB_CONNECTION_STRING  = os.getenv("DB_CONNECTION_STRING", "")

# ── Shared output ──
FINDINGS_DIR = "lab/results/findings"
AI_CACHE_DIR = "lab/results/ai_cache"

# Add this at the end of core/config.py
if not GEMINI_API_KEY:
    print("⚠️  DEBUG: GEMINI_API_KEY is EMPTY in config.py")
else:
    print(f"✅ DEBUG: GEMINI_API_KEY loaded (Starts with: {GEMINI_API_KEY[:5]}...)")