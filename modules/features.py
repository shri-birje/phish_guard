import os
import re
import math
import socket
import ssl
from functools import lru_cache
from collections import Counter, OrderedDict
from difflib import SequenceMatcher
import datetime

import idna
import requests
import tldextract

from modules.unicode_utils import (
    count_zero_width_chars,
    analyze_script_mix,
)

try:
    from rapidfuzz import fuzz
except Exception:  # pragma: no cover
    fuzz = None

try:
    import whois as pywhois
except Exception:
    pywhois = None

try:
    from OpenSSL import crypto
except Exception:
    crypto = None

HOMOGLYPH_MAP = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "l": "1",
    "o": "0",
    "i": "1",
    "s": "5",
    "a": "4",
}

SUSPICIOUS_TLDS = {".zip", ".top", ".xyz", ".country", ".info", ".icu", ".loan"}

# new: suspicious keywords in subdomains (for phishing-y patterns like login/paypal/etc.)
SUSPICIOUS_SUBDOMAIN_KEYWORDS = [
    "login",
    "secure",
    "update",
    "verify",
    "account",
    "billing",
    "support",
    "security",
    "confirm",
]

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
SAFE_BROWSING_KEY = os.environ.get("GOOGLE_SAFEBROWSING_KEY")
SAFE_BROWSING_CLIENT_ID = os.environ.get("GSB_CLIENT_ID", "phishguard")
SAFE_BROWSING_CLIENT_VERSION = os.environ.get("GSB_CLIENT_VERSION", "1.0.0")
SSL_TIMEOUT = float(os.environ.get("SSL_LOOKUP_TIMEOUT", "5"))
ENABLE_SSL_LOOKUPS = os.environ.get("DISABLE_SSL_LOOKUPS", "0") != "1"

# bumped because we added new features (subdomain_* + brand_in_subdomain_not_domain + is_new_domain)
FEATURE_VERSION = 3

FEATURE_DEFAULTS = OrderedDict(
    [
        ("url_length", 0.0),
        ("domain_length", 0.0),
        ("sld_length", 0.0),
        ("num_dots", 0.0),
        ("tld_suspicious", 0.0),
        ("unicode_chars", 0.0),
        ("homoglyph_subs", 0.0),
        ("punycode_diff", 0.0),
        ("shannon_entropy", 0.0),
        ("digit_ratio", 0.0),
        ("alpha_ratio", 0.0),
        ("count_digits", 0.0),
        ("count_letters", 0.0),
        ("count_special", 0.0),
        ("has_https", 0.0),
        ("has_at", 0.0),
        ("has_hyphen", 0.0),
        ("has_ip", 0.0),
        ("unique_char_ratio", 0.0),
        ("ratio_to_sld", 0.0),
        # NEW: subdomain features
        ("num_subdomains", 0.0),
        ("has_suspicious_subdomain_keyword", 0.0),
        ("subdomain_length", 0.0),
        ("subdomain_entropy", 0.0),
        ("brand_in_subdomain_not_domain", 0.0),
        # WHOIS / domain age
        ("domain_age_days", -1.0),
        ("domain_age_months", -1.0),
        ("domain_age_years", -1.0),
        ("domain_days_until_expiry", -1.0),
        ("domain_last_updated_days", -1.0),
        ("domain_creation_ts", -1.0),
        ("domain_updated_ts", -1.0),
        ("domain_expiry_ts", -1.0),
        ("is_new_domain", 0.0),
        # brand similarity / fuzzy
        ("best_sim_trusted_norm", 0.0),
        ("best_sim_trusted_raw", 0.0),
        ("min_lev_trusted", -1.0),
        ("best_fuzzy_ratio", 0.0),
        # unicode / homoglyph stats
        ("zero_width_char_count", 0.0),
        ("has_zero_width_chars", 0.0),
        ("unicode_script_diversity", 0.0),
        ("has_mixed_scripts", 0.0),
        ("mixed_latin_cyrillic", 0.0),
        ("mixed_latin_greek", 0.0),
        # Google Safe Browsing
        ("gsb_flagged", 0.0),
        ("gsb_threat_malware", 0.0),
        ("gsb_threat_phishing", 0.0),
        ("gsb_threat_social_engineering", 0.0),
        ("gsb_threat_unwanted_software", 0.0),
        ("gsb_match_count", 0.0),
        # SSL
        ("ssl_cert_present", 0.0),
        ("ssl_cert_valid", 0.0),
        ("ssl_cert_is_self_signed", 0.0),
        ("ssl_cert_validity_period_days", -1.0),
        ("ssl_cert_days_to_expire", -1.0),
        ("ssl_cert_issue_age_days", -1.0),
    ]
)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    prev = list(range(lb + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i] + [0] * lb
        for j, cb in enumerate(b, start=1):
            add = prev[j] + 1
            delete = cur[j - 1] + 1
            change = prev[j - 1] + (0 if ca == cb else 1)
            cur[j] = min(add, delete, change)
        prev = cur
    return prev[lb]


def to_ascii(domain: str) -> str:
    try:
        return idna.encode(domain).decode()
    except Exception:
        return domain


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    probs = [c / len(s) for c in counts.values()]
    return -sum(p * math.log2(p) for p in probs)


def count_non_ascii(s: str) -> int:
    return sum(1 for ch in s if ord(ch) > 127)


def homoglyph_sub_count(domain: str) -> int:
    return sum(1 for ch in domain if ch.lower() in HOMOGLYPH_MAP)


def extract_sld(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]


def _normalize_host(url: str) -> str:
    host = (url or "").strip().lower()
    host = re.sub(r"^https?://", "", host)
    host = host.split("/")[0]
    host = host.split(":")[0]
    return host


def _now() -> datetime.datetime:
    return datetime.datetime.utcnow()


def _dt(value):
    if isinstance(value, list):
        value = value[0]
    if isinstance(value, datetime.datetime):
        return value.replace(tzinfo=None)
    if isinstance(value, datetime.date):
        return datetime.datetime.combine(value, datetime.time.min)
    return None


@lru_cache(maxsize=256)
def _fetch_whois(host: str) -> dict:
    if pywhois is None or not host:
        return {}
    try:
        record = pywhois.whois(host)
    except Exception:
        return {}
    if not record:
        return {}
    created = _dt(getattr(record, "creation_date", None))
    updated = _dt(getattr(record, "updated_date", None))
    expiry = _dt(getattr(record, "expiration_date", None))
    now = _now()

    def days_delta(start, end):
        if start is None or end is None:
            return None
        return (end - start).days

    age_days = days_delta(created, now)
    days_to_expiry = days_delta(now, expiry)
    last_updated_days = days_delta(updated, now)
    return {
        "creation": created,
        "updated": updated,
        "expiry": expiry,
        "age_days": age_days,
        "days_to_expiry": days_to_expiry,
        "last_updated_days": last_updated_days,
    }


def _asn1_to_dt(raw):
    if not raw:
        return None
    try:
        value = raw.decode("ascii") if isinstance(raw, bytes) else raw
        return datetime.datetime.strptime(value, "%Y%m%d%H%M%SZ")
    except Exception:
        return None


@lru_cache(maxsize=256)
def _fetch_ssl_metadata(host: str) -> dict:
    """
    Fetch SSL metadata for a host using pyOpenSSL.

    Returns {} on any failure, so it never crashes feature extraction.
    """
    if not ENABLE_SSL_LOOKUPS or not host or crypto is None:
        return {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=SSL_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(True)
    except Exception:
        return {}
    try:
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)
    except Exception:
        return {}

    try:
        issue = _asn1_to_dt(cert.get_notBefore())
        expiry = _asn1_to_dt(cert.get_notAfter())
    except Exception:
        # If this fails for any reason, treat as no SSL metadata
        return {}

    now = _now()
    validity_period = (expiry - issue).days if issue and expiry else None
    days_to_expire = (expiry - now).days if expiry else None
    issue_age = (now - issue).days if issue else None

    subject = cert.get_subject()
    issuer = cert.get_issuer()
    try:
        is_self_signed = subject.get_components() == issuer.get_components()
    except Exception:
        is_self_signed = False

    return {
        "issue": issue,
        "expiry": expiry,
        "validity_period": validity_period,
        "days_to_expire": days_to_expire,
        "issue_age": issue_age,
        "is_self_signed": 1 if is_self_signed else 0,
    }


@lru_cache(maxsize=512)
def _google_safe_browsing_lookup(url: str) -> dict:
    if not SAFE_BROWSING_KEY or not url:
        return {}
    body = {
        "client": {"clientId": SAFE_BROWSING_CLIENT_ID, "clientVersion": SAFE_BROWSING_CLIENT_VERSION},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "PHISHING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(f"{SAFE_BROWSING_URL}?key={SAFE_BROWSING_KEY}", json=body, timeout=4)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return {}
    matches = data.get("matches", [])
    categories = {m.get("threatType", "").upper() for m in matches}
    return {
        "flagged": 1 if matches else 0,
        "match_count": len(matches),
        "malware": 1 if "MALWARE" in categories else 0,
        "phishing": 1 if "PHISHING" in categories else 0,
        "social_engineering": 1 if "SOCIAL_ENGINEERING" in categories else 0,
        "unwanted_software": 1 if "UNWANTED_SOFTWARE" in categories or "POTENTIALLY_HARMFUL_APPLICATION" in categories else 0,
    }


def _zero_width_stats(host: str) -> dict:
    count = count_zero_width_chars(host)
    return {
        "zero_width_char_count": float(count),
        "has_zero_width_chars": 1.0 if count else 0.0,
    }


def _script_mix_stats(host: str) -> dict:
    mix = analyze_script_mix(host)
    return {
        "unicode_script_diversity": float(mix.get("script_diversity", 0)),
        "has_mixed_scripts": float(mix.get("has_mixed_scripts", 0)),
        "mixed_latin_cyrillic": float(mix.get("mixed_latin_cyrillic", 0)),
        "mixed_latin_greek": float(mix.get("mixed_latin_greek", 0)),
    }

def _parse_host_parts(host: str):
    """
    Use tldextract to split host into (subdomain, domain, suffix).

    On any error (including RecursionError in some environments),
    fall back to a simple split, so feature extraction NEVER crashes.
    """
    if not host:
        return "", "", ""

    try:
        ext = tldextract.extract(host)
        subdomain = ext.subdomain or ""
        domain = ext.domain or ""
        suffix = ext.suffix or ""
        return subdomain, domain, suffix
    except Exception:
        # Fallback: simple split like "a.b.c.com" -> subdomain="a.b.c", domain="com?", suffix=""
        parts = host.split(".")
        if len(parts) >= 2:
            domain = parts[-2]
            suffix = parts[-1]
            subdomain = ".".join(parts[:-2])
        else:
            domain = host
            suffix = ""
            subdomain = ""
        return subdomain.lower(), domain.lower(), suffix.lower()


def _subdomain_features(host: str) -> dict:
    """
    Compute subdomain-based features:

      - num_subdomains
      - has_suspicious_subdomain_keyword
      - subdomain_length
      - subdomain_entropy
    """
    subdomain, _, _ = _parse_host_parts(host)
    if not subdomain:
        return {
            "num_subdomains": 0.0,
            "has_suspicious_subdomain_keyword": 0.0,
            "subdomain_length": 0.0,
            "subdomain_entropy": 0.0,
        }

    labels = [lbl for lbl in subdomain.split(".") if lbl]
    num_subdomains = len(labels)
    lower_sd = subdomain.lower()
    has_suspicious = any(k in lower_sd for k in SUSPICIOUS_SUBDOMAIN_KEYWORDS)
    entropy = shannon_entropy(subdomain)

    return {
        "num_subdomains": float(num_subdomains),
        "has_suspicious_subdomain_keyword": float(int(has_suspicious)),
        "subdomain_length": float(len(subdomain)),
        "subdomain_entropy": float(round(entropy, 4)),
    }


def _brand_mismatch_feature(host: str, trusted_domains: list | None) -> dict:
    """
    Detect cases like:
        paypal.com.login.verify.ru
    where 'paypal' appears in the subdomain but the registrable domain is not paypal.com.

    Returns:
        {"brand_in_subdomain_not_domain": 0.0 or 1.0}
    """
    if not trusted_domains:
        return {"brand_in_subdomain_not_domain": 0.0}

    subdomain, domain, suffix = _parse_host_parts(host)
    if not domain:
        return {"brand_in_subdomain_not_domain": 0.0}

    registrable = f"{domain}.{suffix}" if suffix else domain
    sd_lower = subdomain.lower()
    reg_lower = registrable.lower()

    brands = set()
    for td in trusted_domains:
        try:
            ext = tldextract.extract(td)
            if ext.domain:
                brands.add(ext.domain.lower())
        except Exception:
            continue

    suspicious = 0
    for brand in brands:
        if brand in sd_lower and brand not in reg_lower:
            suspicious = 1
            break

    return {"brand_in_subdomain_not_domain": float(suspicious)}


def extract_features_from_url(url: str, trusted_domains: list = None, enable_network_enrichment: bool = True) -> dict:
    host = _normalize_host(url)
    parts = host.split(".") if host else [""]

    tld = "." + parts[-1] if len(parts) > 1 else ""
    sld = extract_sld(host) if host else ""
    ascii_host = to_ascii(host)

    feats = OrderedDict(FEATURE_DEFAULTS)
    feats["url_length"] = float(len(url or ""))
    feats["domain_length"] = float(len(host))
    feats["sld_length"] = float(len(sld))
    feats["num_dots"] = float(host.count("."))
    feats["tld_suspicious"] = 1.0 if tld in SUSPICIOUS_TLDS else 0.0
    feats["unicode_chars"] = float(count_non_ascii(host))
    feats["homoglyph_subs"] = float(homoglyph_sub_count(host))
    feats["punycode_diff"] = 1.0 if ascii_host != host else 0.0
    feats["shannon_entropy"] = round(shannon_entropy(host), 4)
    feats["digit_ratio"] = sum(ch.isdigit() for ch in host) / max(1, len(host))
    feats["alpha_ratio"] = sum(ch.isalpha() for ch in host) / max(1, len(host))
    feats["count_digits"] = float(sum(ch.isdigit() for ch in host))
    feats["count_letters"] = float(sum(ch.isalpha() for ch in host))
    feats["count_special"] = float(sum(not ch.isalnum() for ch in host))
    feats["has_https"] = 1.0 if (url or "").startswith("https") else 0.0
    feats["has_at"] = 1.0 if "@" in (url or "") else 0.0
    feats["has_hyphen"] = 1.0 if "-" in host else 0.0
    feats["has_ip"] = 1.0 if re.match(r"^\d+\.\d+\.\d+\.\d+$", host) else 0.0
    feats["unique_char_ratio"] = len(set(host)) / max(1, len(host))
    feats["ratio_to_sld"] = round(len(sld) / max(1, len(host)), 4)

    # subdomain-based lexical features
    feats.update(_subdomain_features(host))

    # brand mismatch (trusted brand in subdomain, but different registrable domain)
    feats.update(_brand_mismatch_feature(host, trusted_domains))

    # unicode / script mix
    feats.update(_zero_width_stats(host))
    feats.update(_script_mix_stats(host))

    # WHOIS, SSL, GSB
    if enable_network_enrichment and host:
        try:
            whois_data = _fetch_whois(host)
        except Exception:
            whois_data = {}
        if whois_data:
            age_days = whois_data.get("age_days")
            if age_days is not None:
                feats["domain_age_days"] = float(age_days)
                feats["domain_age_months"] = round(age_days / 30.0, 2)
                feats["domain_age_years"] = round(age_days / 365.0, 2)
                feats["is_new_domain"] = 1.0 if age_days < 30 else 0.0
            else:
                feats["is_new_domain"] = 0.0

            feats["domain_days_until_expiry"] = float(whois_data.get("days_to_expiry", -1) or -1)
            feats["domain_last_updated_days"] = float(whois_data.get("last_updated_days", -1) or -1)
            feats["domain_creation_ts"] = float(whois_data["creation"].timestamp()) if whois_data.get("creation") else -1.0
            feats["domain_updated_ts"] = float(whois_data["updated"].timestamp()) if whois_data.get("updated") else -1.0
            feats["domain_expiry_ts"] = float(whois_data["expiry"].timestamp()) if whois_data.get("expiry") else -1.0

        try:
            ssl_meta = _fetch_ssl_metadata(host)
        except Exception:
            ssl_meta = {}
        if ssl_meta:
            feats["ssl_cert_present"] = 1.0
            feats["ssl_cert_valid"] = 1.0 if ssl_meta.get("days_to_expire", -1) >= 0 else 0.0
            feats["ssl_cert_is_self_signed"] = float(ssl_meta.get("is_self_signed", 0))
            feats["ssl_cert_validity_period_days"] = float(ssl_meta.get("validity_period", -1) or -1)
            feats["ssl_cert_days_to_expire"] = float(ssl_meta.get("days_to_expire", -1) or -1)
            feats["ssl_cert_issue_age_days"] = float(ssl_meta.get("issue_age", -1) or -1)

        try:
            gsb = _google_safe_browsing_lookup(url)
        except Exception:
            gsb = {}
        if gsb:
            feats["gsb_flagged"] = float(gsb.get("flagged", 0))
            feats["gsb_match_count"] = float(gsb.get("match_count", 0))
            feats["gsb_threat_malware"] = float(gsb.get("malware", 0))
            feats["gsb_threat_phishing"] = float(gsb.get("phishing", 0))
            feats["gsb_threat_social_engineering"] = float(gsb.get("social_engineering", 0))
            feats["gsb_threat_unwanted_software"] = float(gsb.get("unwanted_software", 0))

    # compare to trusted list if present
    if trusted_domains:
        best_sim_norm = 0.0
        best_sim_raw = 0.0
        best_fuzzy = 0.0
        min_lev = 999
        raw = host

        def normalize_confusables(s):
            mapping = {
                "\u0430": "a",
                "\u03b1": "a",
                "\u0435": "e",
                "\u03b5": "e",
                "\u043e": "o",
                "\u03bf": "o",
                "\uff4f": "o",
                "\u0131": "i",
                "\u0456": "i",
                "0": "o",
                "1": "l",
            }
            return "".join([mapping.get(ch, ch) for ch in s])

        norm = normalize_confusables(raw)

        for t in trusted_domains:
            target = (t or "").split("/")[0].split(":")[0].lower()
            t_sld = target.split(".")[0] if target else ""
            try:
                sim_norm = SequenceMatcher(None, norm, t_sld).ratio()
                sim_raw = SequenceMatcher(None, raw, t_sld).ratio()
                best_sim_norm = max(best_sim_norm, sim_norm)
                best_sim_raw = max(best_sim_raw, sim_raw)
            except Exception:
                pass
            try:
                d = levenshtein(sld, t_sld)
                if d < min_lev:
                    min_lev = d
            except Exception:
                pass
            try:
                if fuzz:
                    ratio = max(fuzz.ratio(raw, target), fuzz.partial_ratio(raw, target))
                else:
                    ratio = SequenceMatcher(None, raw, target).ratio() * 100
                best_fuzzy = max(best_fuzzy, ratio)
            except Exception:
                pass

        feats["best_sim_trusted_norm"] = round(best_sim_norm, 4)
        feats["best_sim_trusted_raw"] = round(best_sim_raw, 4)
        feats["min_lev_trusted"] = float(min_lev if min_lev != 999 else -1)
        feats["best_fuzzy_ratio"] = round(best_fuzzy, 2)

    # ensure ordering
    return OrderedDict((k, feats.get(k, FEATURE_DEFAULTS[k])) for k in FEATURE_DEFAULTS.keys())
