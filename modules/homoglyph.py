# modules/homoglyph.py
import re
from difflib import SequenceMatcher
import urllib.parse

# small mapping of confusables (extend when needed)
CONFUSABLES = {
    '\u0430':'a','\u03B1':'a','\u0435':'e','\u03B5':'e',
    '\u043E':'o','\u03BF':'o','\uFF4F':'o','\u0131':'i',
    '\u0456':'i','0':'o','1':'l'
}

def normalize_confusables(s: str) -> str:
    return ''.join([CONFUSABLES.get(ch, ch) for ch in s])

def extract_domain(url: str) -> str:
    if not url: return ''
    if not re.match(r'https?://', url):
        url = 'http://' + url
    try:
        p = urllib.parse.urlparse(url)
        return (p.hostname or '').lower()
    except Exception:
        return url.lower()

def best_similarity(a: str, b_list: list) -> float:
    best = 0.0
    for t in b_list:
        try:
            r = SequenceMatcher(None, a, t).ratio()
            if r > best: best = r
        except Exception:
            pass
    return best

def analyze_homoglyph(url: str, trusted_domains: list) -> float:
    domain = extract_domain(url)
    if not domain:
        return 0.0
    raw = domain
    normalized = normalize_confusables(raw)
    # quick allow if identical and trusted
    if normalized == raw and normalized in trusted_domains:
        return 0.0

    sim_norm = best_similarity(normalized, trusted_domains) if trusted_domains else 0.0
    sim_raw = best_similarity(raw, trusted_domains) if trusted_domains else 0.0

    score = 0.0
    # large similarity after normalization but not for raw -> suspicious
    if sim_norm >= 0.85 and sim_raw < sim_norm - 0.05:
        score += 80 * sim_norm
    # presence of unicode
    if any(ord(c) > 127 for c in raw):
        score += 30
    # digits ratio suspicious
    digit_ratio = sum(c.isdigit() for c in raw) / max(1, len(raw))
    if digit_ratio > 0.15:
        score += 20 * digit_ratio
    # levenshtein-ish penalties (short distance)
    # normalized distance handled in features; here keep a small boost
    if sim_norm > 0.7 and sim_raw < 0.7:
        score += 10

    return min(100.0, max(0.0, score))
