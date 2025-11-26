import json
import os
from datetime import datetime, timezone

import tldextract

try:
    import whois  # from python-whois
except ImportError:
    whois = None  # we will handle this gracefully


CACHE_PATH = os.path.join("data", "domain_age_cache.json")


def _load_cache() -> dict:
    if not os.path.exists(CACHE_PATH):
        return {}
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(cache: dict) -> None:
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    try:
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f)
    except Exception:
        # cache failure should never crash the app
        pass


def _extract_registrable_domain(url_or_domain: str) -> str:
    """
    Accepts either a full URL or just a host/domain, returns registrable domain
    like 'example.com' or 'example.co.uk'.
    """
    ext = tldextract.extract(url_or_domain)
    if not ext.domain:
        return (url_or_domain or "").lower()
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return ext.domain.lower()


def _compute_domain_age_days(domain: str) -> int | None:
    """
    Returns age in days, or None if WHOIS lookup fails.
    """
    if whois is None:
        return None

    try:
        w = whois.whois(domain)
    except Exception:
        return None

    created = w.creation_date

    # python-whois sometimes returns a list, sometimes a single datetime, sometimes None
    if created is None:
        return None
    if isinstance(created, list):
        created = created[0]

    if not isinstance(created, datetime):
        return None

    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    delta = now - created
    return max(delta.days, 0)


def get_domain_age_features(url_or_domain: str) -> dict:
    """
    Public helper used by feature extraction or other modules.

    Returns:
        {
            "domain_age_days":   int   (0 if unknown),
            "domain_age_months": float (0.0 if unknown),
            "domain_age_years":  float (0.0 if unknown),
            "is_new_domain":     0/1   (1 if <30 days)
        }
    """
    cache = _load_cache()
    key = _extract_registrable_domain(url_or_domain)

    if key in cache:
        info = cache[key]
        age_days = info.get("domain_age_days")
    else:
        age_days = _compute_domain_age_days(key)
        cache[key] = {"domain_age_days": age_days}
        _save_cache(cache)

    if age_days is None:
        # unknown age – use 0 but mark not new
        return {
            "domain_age_days": 0,
            "domain_age_months": 0.0,
            "domain_age_years": 0.0,
            "is_new_domain": 0,
        }

    is_new = 1 if age_days < 30 else 0
    months = age_days / 30.0
    years = age_days / 365.0

    return {
        "domain_age_days": int(age_days),
        "domain_age_months": float(round(months, 2)),
        "domain_age_years": float(round(years, 2)),
        "is_new_domain": is_new,
    }
