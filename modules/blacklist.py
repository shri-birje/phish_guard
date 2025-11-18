# modules/blacklist.py
import os
import threading
from urllib.parse import urlparse

LOCK = threading.Lock()
ROOT = os.path.dirname(os.path.dirname(__file__))  # project root if modules/ is at projectroot/modules
BLACKLIST_PATH = os.path.join(ROOT, "blacklist.txt")

def _ensure_file():
    if not os.path.exists(BLACKLIST_PATH):
        with open(BLACKLIST_PATH, "w", encoding="utf-8") as f:
            f.write("")  # create empty

def _norm_domain(url_or_domain: str) -> str:
    if not url_or_domain:
        return ""
    try:
        maybe = url_or_domain.strip()
        if maybe.startswith("http://") or maybe.startswith("https://"):
            p = urlparse(maybe)
            return (p.hostname or "").lower()
        # maybe bare domain
        return maybe.split("/")[0].split(":")[0].lower()
    except Exception:
        return url_or_domain.lower()

def load_blacklist() -> set:
    _ensure_file()
    with LOCK:
        with open(BLACKLIST_PATH, "r", encoding="utf-8") as f:
            lines = [l.strip().lower() for l in f if l.strip()]
    return set(lines)

def is_blacklisted(url_or_domain: str) -> bool:
    d = _norm_domain(url_or_domain)
    if not d:
        return False
    blacks = load_blacklist()
    return d in blacks

def add_to_blacklist(url_or_domain: str, reason: str = "") -> bool:
    """Add domain to blacklist. Returns True if added, False if already present."""
    d = _norm_domain(url_or_domain)
    if not d:
        return False
    _ensure_file()
    with LOCK:
        with open(BLACKLIST_PATH, "r", encoding="utf-8") as f:
            existing = {line.strip().lower() for line in f if line.strip()}
        if d in existing:
            return False
        with open(BLACKLIST_PATH, "a", encoding="utf-8") as f:
            f.write(d + "\n")
    return True

def remove_from_blacklist(url_or_domain: str) -> bool:
    """Remove domain from blacklist file."""
    d = _norm_domain(url_or_domain)
    if not d:
        return False
    _ensure_file()
    with LOCK:
        with open(BLACKLIST_PATH, "r", encoding="utf-8") as f:
            lines = [line.strip().lower() for line in f if line.strip()]
        if d not in lines:
            return False
        lines = [line for line in lines if line != d]
        with open(BLACKLIST_PATH, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")
    return True
