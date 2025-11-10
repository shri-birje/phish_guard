# modules/features.py
import re
import urllib.parse
from difflib import SequenceMatcher
import math

# small map of common homoglyphs -> latin approximations (extendable)
CONFUSABLES = {
    '\u0430':'a', '\u03B1':'a', '\u0435':'e', '\u03B5':'e', '\u043E':'o', '\u03BF':'o',
    '\uFF4F':'o', '\u0131':'i', '\u0456':'i', '0':'o', '1':'l', 'l':'1'
}

SUSPICIOUS_TLDS = {'.top', '.xyz', '.zip', '.tk', '.pw', '.info'}

def extract_domain(url: str) -> str:
    if not url:
        return ''
    if not re.match(r'https?://', url):
        url = 'http://' + url
    try:
        p = urllib.parse.urlparse(url)
        hostname = (p.hostname or '').lower()
        return hostname
    except Exception:
        return url.lower()

def normalize_confusables(s: str) -> str:
    return ''.join([CONFUSABLES.get(ch, ch) for ch in s])

def levenshtein(a: str, b: str) -> int:
    """Simple Levenshtein distance (no extra dependencies)."""
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)
    v0 = list(range(len(b) + 1))
    v1 = [0] * (len(b) + 1)
    for i in range(len(a)):
        v1[0] = i + 1
        for j in range(len(b)):
            cost = 0 if a[i] == b[j] else 1
            v1[j+1] = min(v1[j] + 1, v0[j+1] + 1, v0[j] + cost)
        v0, v1 = v1, v0
    return v0[len(b)]

def ratio(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [float(s.count(c)) / len(s) for c in set(s)]
    return - sum(p * math.log2(p) for p in probs)

def domain_sld_tld(domain: str):
    """Return (sld, tld). sld = second-level domain (example from example.co.uk -> example.co)"""
    if not domain:
        return '', ''
    parts = domain.split('.')
    if len(parts) <= 1:
        return domain, ''
    # simple approach: last part is tld; sld = join(last two if country-code?) - keep simple:
    tld = '.' + parts[-1]
    sld = parts[-2]
    return sld, tld

def best_similarity_to_trusted(domain: str, trusted_list: list) -> float:
    if not domain or not trusted_list:
        return 0.0
    best = 0.0
    for t in trusted_list:
        sim = ratio(domain, t)
        if sim > best:
            best = sim
    return best

def count_confusable_chars(s: str) -> int:
    return sum(1 for ch in s if ch in CONFUSABLES and CONFUSABLES[ch] != ch)

def extract_features_from_url(url: str, trusted_domains: list = None) -> dict:
    """
    Returns a dict of numeric features extracted from URL/domain.
    Keep keys stable (same names/order) so training/inference columns match.
    """
    trusted_domains = trusted_domains or []
    domain = extract_domain(url)
    sld, tld = domain_sld_tld(domain)
    normalized = normalize_confusables(domain)

    features = {}
    # Basic counts & ratios
    features['url_length'] = len(url or '')
    features['domain_length'] = len(domain or '')
    features['sld_length'] = len(sld or '')
    features['num_dots'] = domain.count('.')
    features['count_digits'] = sum(c.isdigit() for c in domain)
    features['digit_ratio'] = features['count_digits'] / max(1.0, features['domain_length'])
    features['count_letters'] = sum(c.isalpha() for c in domain)
    features['count_special'] = sum(not c.isalnum() and c != '.' for c in domain)

    # Flags
    features['has_https'] = 1 if url.lower().startswith('https') else 0
    features['has_at'] = 1 if '@' in url else 0
    features['has_hyphen'] = 1 if '-' in domain else 0
    features['has_ip'] = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain) else 0
    features['unicode_chars'] = 1 if any(ord(c) > 127 for c in domain) else 0

    # Homoglyph / confusable metrics
    features['confusable_count'] = count_confusable_chars(domain)
    features['normalized_equals_raw'] = 1 if normalized == domain else 0
    features['normalized_length_diff'] = abs(len(normalized) - len(domain))

    # similarity to trusted domains (best)
    try:
        features['best_sim_trusted_raw'] = best_similarity_to_trusted(domain, trusted_domains)
        features['best_sim_trusted_norm'] = best_similarity_to_trusted(normalized, trusted_domains)
    except Exception:
        features['best_sim_trusted_raw'] = 0.0
        features['best_sim_trusted_norm'] = 0.0

    # Levenshtein to top trusted (min distance) - normalized by domain length
    min_lev = min((levenshtein(domain, t) for t in (trusted_domains or [''])), default=len(domain))
    features['min_lev_trusted_norm'] = min_lev / max(1, features['domain_length'])

    # Suspicious TLD
    features['suspicious_tld'] = 1 if (tld.lower() in SUSPICIOUS_TLDS) else 0

    # entropy & char diversity
    features['shannon_entropy'] = round(shannon_entropy(domain), 4)
    features['unique_char_ratio'] = len(set(domain)) / max(1.0, features['domain_length'])

    # Levenshtein/ratio to "popular" short names (optionally)
    features['ratio_to_sld'] = ratio(domain, sld or domain)

    # Return numeric-only dict (float/int)
    return {k: float(v) if isinstance(v, (int, float)) else v for k, v in features.items()}
