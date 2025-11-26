import json
import time
from dataclasses import dataclass, asdict

import requests


# Change this to your Render URL when testing in production:
# BASE_URL = "https://your-render-service.onrender.com"
BASE_URL = "http://127.0.0.1:5001"


@dataclass
class TestCase:
    name: str
    url: str
    user_id: str
    behavior: dict


# Some realistic behavior profiles
LOW_RISK_BEHAVIOR = {
    "typing_cps": 2.5,
    "avg_mouse_speed": 35,
    "click_std": 15,
    "scroll_speed": 10,
}

HIGH_RISK_BEHAVIOR = {
    "typing_cps": 0.4,
    "avg_mouse_speed": 4,
    "click_std": 3,
    "scroll_speed": 0,
}

# Unicode homoglyph examples – copy/paste as-is.
HOMOGLYPH_PAYPAL = "https://раураl.com/login"              # Cyrillic "р", "а"
HOMOGLYPH_GOOGLE = "https://ɡoogle.com"                    # Latin small letter script g
HOMOGLYPH_MICROSOFT = "https://microsоft.com-support.help" # Cyrillic "о"


TEST_CASES = [
    # Benign
    TestCase(
        name="Benign - Google",
        url="https://www.google.com",
        user_id="user-benign-1",
        behavior=LOW_RISK_BEHAVIOR,
    ),
    TestCase(
        name="Benign - Wikipedia",
        url="https://www.wikipedia.org",
        user_id="user-benign-2",
        behavior=LOW_RISK_BEHAVIOR,
    ),

    # Subdomain & brand impersonation
    TestCase(
        name="Phish - Paypal subdomain impersonation",
        url="https://paypal.com.account-security.ru/login",
        user_id="user-phish-1",
        behavior=HIGH_RISK_BEHAVIOR,
    ),
    TestCase(
        name="Phish - Google brand in subdomain",
        url="https://google.com.mail-signin.net/",
        user_id="user-phish-2",
        behavior=HIGH_RISK_BEHAVIOR,
    ),

    # WHOIS + age: very new / suspicious TLDs
    TestCase(
        name="Suspicious - Fresh login .site",
        url="https://login-update.site/",
        user_id="user-phish-3",
        behavior=HIGH_RISK_BEHAVIOR,
    ),

    # SSL edge cases (BadSSL)
    TestCase(
        name="SSL - Expired cert (badssl)",
        url="https://expired.badssl.com/",
        user_id="user-ssl-1",
        behavior=LOW_RISK_BEHAVIOR,
    ),
    TestCase(
        name="SSL - Self-signed cert (badssl)",
        url="https://self-signed.badssl.com/",
        user_id="user-ssl-2",
        behavior=LOW_RISK_BEHAVIOR,
    ),

    # Homoglyph / Unicode trickery
    TestCase(
        name="Homoglyph - Paypal (Cyrillic)",
        url=HOMOGLYPH_PAYPAL,
        user_id="user-homo-1",
        behavior=HIGH_RISK_BEHAVIOR,
    ),
    TestCase(
        name="Homoglyph - Google (script g)",
        url=HOMOGLYPH_GOOGLE,
        user_id="user-homo-2",
        behavior=HIGH_RISK_BEHAVIOR,
    ),
    TestCase(
        name="Homoglyph + subdomain - Microsoft",
        url=HOMOGLYPH_MICROSOFT,
        user_id="user-homo-3",
        behavior=HIGH_RISK_BEHAVIOR,
    ),

    # Realistic combined phish
    TestCase(
        name="Realistic - Signin Paypal multi-subdomain",
        url="https://signin-paypal.com.verify-account-security.com/login",
        user_id="user-phish-4",
        behavior=HIGH_RISK_BEHAVIOR,
    ),
]


def call_check_api(test: TestCase):
    url = f"{BASE_URL}/api/check"
    payload = {
        "url": test.url,
        "user_id": test.user_id,
        "behavior": test.behavior,
    }
    try:
        resp = requests.post(url, json=payload, timeout=10)
    except Exception as e:
        print(f"[ERROR] {test.name}: request failed: {e}")
        return None
    if resp.status_code != 200:
        print(f"[ERROR] {test.name}: HTTP {resp.status_code} -> {resp.text}")
        return None
    try:
        return resp.json()
    except json.JSONDecodeError:
        print(f"[ERROR] {test.name}: invalid JSON response: {resp.text[:200]}")
        return None


def summarize_result(test: TestCase, result: dict):
    if not result:
        print(f"[SKIP] {test.name} – no result")
        return

    features = result.get("features", {}) or {}
    phishing_score = result.get("phishing_score")
    risk = result.get("risk_level")
    action = result.get("action")
    model_prob = features.get("model_raw_probability")
    brand_mismatch = features.get("brand_in_subdomain_not_domain")
    is_new_domain = features.get("is_new_domain")
    ssl_valid = features.get("ssl_cert_valid")
    ssl_present = features.get("ssl_cert_present")
    domain_age_years = features.get("domain_age_years")
    num_subdomains = features.get("num_subdomains")
    homoglyph_subs = features.get("homoglyph_subs")
    gsb_flagged = features.get("gsb_flagged")

    print("=" * 80)
    print(f"Test: {test.name}")
    print(f"URL : {test.url}")
    print(f"User: {test.user_id}")
    print(f"Phishing score : {phishing_score} | Risk: {risk} | Action: {action}")
    print(f"Model P(phish): {model_prob}")
    print("Key features:")
    print(f"  - brand_in_subdomain_not_domain : {brand_mismatch}")
    print(f"  - num_subdomains                : {num_subdomains}")
    print(f"  - homoglyph_subs                : {homoglyph_subs}")
    print(f"  - is_new_domain                 : {is_new_domain}")
    print(f"  - domain_age_years              : {domain_age_years}")
    print(f"  - ssl_cert_present              : {ssl_present}")
    print(f"  - ssl_cert_valid                : {ssl_valid}")
    print(f"  - gsb_flagged                   : {gsb_flagged}")
    print()


def main():
    print(f"🔍 Running {len(TEST_CASES)} tests against {BASE_URL} ...\n")
    for test in TEST_CASES:
        result = call_check_api(test)
        summarize_result(test, result)
        # tiny delay so you can see rate limiting behavior if any
        time.sleep(0.3)


if __name__ == "__main__":
    main()
