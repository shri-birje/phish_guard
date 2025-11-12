# modules/features.py
import re
import math
import idna
import unicodedata
from collections import Counter
import datetime

# optional whois import (may fail if system cannot resolve whois)
try:
    import whois as pywhois
except Exception:
    pywhois = None

# -------------------------
# basic helpers
# -------------------------
def levenshtein(a: str, b: str) -> int:
    if a == b: return 0
    la, lb = len(a), len(b)
    if la == 0: return lb
    if lb == 0: return la
    prev = list(range(lb+1))
    for i, ca in enumerate(a, start=1):
        cur = [i] + [0]*lb
        for j, cb in enumerate(b, start=1):
            add = prev[j] + 1
            delete = cur[j-1] + 1
            change = prev[j-1] + (0 if ca==cb else 1)
            cur[j] = min(add, delete, change)
        prev = cur
    return prev[lb]

def to_ascii(domain: str) -> str:
    try:
        return idna.encode(domain).decode()
    except Exception:
        return domain

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    counts = Counter(s)
    probs = [c/len(s) for c in counts.values()]
    return -sum(p*math.log2(p) for p in probs)

def count_non_ascii(s: str) -> int:
    return sum(1 for ch in s if ord(ch) > 127)

HOMOGLYPH_MAP = {
    '0':'o', '1':'l', '3':'e', '4':'a', '5':'s', '7':'t', '8':'b',
    'l':'1', 'o':'0', 'i':'1', 's':'5', 'a':'4'
}
def homoglyph_sub_count(domain: str) -> int:
    c = 0
    for ch in domain:
        if ch.lower() in HOMOGLYPH_MAP:
            c += 1
    return c

SUSPICIOUS_TLDS = {'.zip', '.top', '.xyz', '.country', '.info', '.icu', '.loan'}

def extract_sld(host: str) -> str:
    parts = host.split('.')
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]

# Domain age in days (best-effort using python-whois)
def domain_age_days(hostname: str, fallback_max=36500):
    if not hostname:
        return None
    # strip path
    host = re.sub(r'^https?://', '', hostname).split('/')[0].split(':')[0]
    if pywhois is None:
        return None
    try:
        w = pywhois.whois(host)
        if not w:
            return None
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if isinstance(created, datetime.datetime):
            delta = datetime.datetime.utcnow() - created
            return max(0, delta.days)
        return None
    except Exception:
        # whois can fail for many reasons (rate limit, TLD not supported)
        return None

# -------------------------
# Main extractor
# -------------------------
def extract_features_from_url(url: str, trusted_domains: list = None) -> dict:
    host = (url or "").lower().strip()
    host = re.sub(r'^https?://', '', host)
    host = host.split('/')[0]
    host = host.split(':')[0]

    parts = host.split('.')
    tld = '.' + parts[-1] if len(parts) > 1 else ''
    sld = extract_sld(host)
    ascii = to_ascii(host)

    feats = {}
    feats['url_length'] = len(url or "")
    feats['domain_length'] = len(host)
    feats['sld_length'] = len(sld)
    feats['num_dots'] = host.count('.')
    feats['tld_suspicious'] = 1 if tld in SUSPICIOUS_TLDS else 0
    feats['unicode_chars'] = count_non_ascii(host)
    feats['homoglyph_subs'] = homoglyph_sub_count(host)
    feats['punycode_diff'] = 1 if ascii != host else 0
    feats['shannon_entropy'] = round(shannon_entropy(host), 4)
    feats['digit_ratio'] = sum(ch.isdigit() for ch in host)/max(1,len(host))
    feats['alpha_ratio'] = sum(ch.isalpha() for ch in host)/max(1,len(host))
    feats['count_digits'] = sum(ch.isdigit() for ch in host)
    feats['count_letters'] = sum(ch.isalpha() for ch in host)
    feats['count_special'] = sum(not ch.isalnum() for ch in host)
    feats['has_https'] = 1 if url.startswith("https") else 0
    feats['has_at'] = 1 if '@' in url else 0
    feats['has_hyphen'] = 1 if '-' in host else 0
    feats['has_ip'] = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', sld) else 0
    feats['unique_char_ratio'] = len(set(host))/max(1,len(host))
    # ratio from full host length to sld length
    feats['ratio_to_sld'] = round(len(sld)/max(1,len(host)), 4)

    # domain age (days)
    try:
        age_days = domain_age_days(host)
        feats['domain_age_days'] = age_days if age_days is not None else -1
    except Exception:
        feats['domain_age_days'] = -1

    # compare to trusted list if present
    if trusted_domains:
        best_sim_norm = 0.0
        best_sim_raw = 0.0
        min_lev = 999
        raw = host
        # create a simple normalized form that maps some confusables to ascii
        def normalize_confusables(s):
            mapping = {'\u0430':'a','\u03B1':'a','\u0435':'e','\u03B5':'e','\u043E':'o','\u03BF':'o','\uFF4F':'o','\u0131':'i','\u0456':'i','0':'o','1':'l'}
            return ''.join([mapping.get(ch, ch) for ch in s])
        norm = normalize_confusables(raw)
        for t in trusted_domains:
            t_sld = t.split('.')[0].lower()
            # similarity via ratio
            try:
                from difflib import SequenceMatcher
                sim_norm = SequenceMatcher(None, norm, t_sld).ratio()
                sim_raw = SequenceMatcher(None, raw, t_sld).ratio()
                if sim_norm > best_sim_norm:
                    best_sim_norm = sim_norm
                if sim_raw > best_sim_raw:
                    best_sim_raw = sim_raw
            except Exception:
                pass
            try:
                d = levenshtein(sld, t_sld)
                if d < min_lev:
                    min_lev = d
            except Exception:
                pass
        feats['best_sim_trusted_norm'] = round(best_sim_norm, 4)
        feats['best_sim_trusted_raw'] = round(best_sim_raw, 4)
        feats['min_lev_trusted'] = min_lev if min_lev != 999 else -1
    else:
        feats['best_sim_trusted_norm'] = 0.0
        feats['best_sim_trusted_raw'] = 0.0
        feats['min_lev_trusted'] = -1

    return feats
