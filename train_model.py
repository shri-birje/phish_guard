import argparse
import csv
import os
from io import StringIO
from typing import List

import joblib
import pandas as pd
import requests
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score
from sklearn.model_selection import train_test_split

from modules.features import extract_features_from_url, FEATURE_DEFAULTS, FEATURE_VERSION

try:
    from xgboost import XGBClassifier
except Exception:  # pragma: no cover
    XGBClassifier = None

try:
    from lightgbm import LGBMClassifier
except Exception:  # pragma: no cover
    LGBMClassifier = None

DATA_PATH = os.path.join("data", "labeled_urls.csv")
MODEL_PATH = "rf_model.joblib"
TRUSTED_PATH = "trusted_domains.txt"

PHISHING_FEEDS = [
    {"name": "openphish", "url": "https://openphish.com/feed.txt", "parser": "lines"},
    {
        "name": "phishing_db",
        "url": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
        "parser": "lines",
    },
    {
        "name": "trickest_domains",
        "url": "https://raw.githubusercontent.com/trickest/phishing-domains/main/domains.txt",
        "parser": "domains",
    },
]

BENIGN_FEEDS = [
    {
        "name": "top_sites",
        "url": "https://raw.githubusercontent.com/zacanger/top-sites/master/top-sites.json",
        "parser": "json",
    },
    {
        "name": "tranco",
        "url": "https://tranco-list.eu/top-1m.csv",
        "parser": "csv_domain",
        "domain_index": 1,
    },
]

BENIGN_FALLBACK = [
    "https://google.com",
    "https://microsoft.com",
    "https://github.com",
    "https://openai.com",
    "https://wikipedia.org",
    "https://cloudflare.com",
    "https://paypal.com",
    "https://stripe.com",
    "https://bbc.com",
    "https://nytimes.com",
]

PHISHING_FALLBACK = [
    "http://secure-update-login.com",
    "http://paypal-verification-alert.net",
    "http://support-microsoft-security-check.com",
    "http://login-dropboxsecure.net",
    "http://apple-id-account-validation.net",
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Train phishing detection model with enriched homoglyph + URL + WHOIS + SSL + subdomain features."
    )
    parser.add_argument("--model-type", choices=["rf", "xgboost", "lightgbm"], default="rf")
    parser.add_argument(
        "--refresh-feeds",
        action="store_true",
        help="Rebuild dataset from open-source feeds into data/labeled_urls.csv (overwrites).",
    )
    parser.add_argument(
        "--max-feed-samples",
        type=int,
        default=2000,
        help="Maximum samples to keep per class when pulling from feeds.",
    )
    parser.add_argument(
        "--disable-remote-lookups",
        action="store_true",
        help="Skip WHOIS/SSL/SafeBrowsing lookups for faster but less rich features.",
    )
    return parser.parse_args()


def ensure_scheme(url: str) -> str:
    if not url:
        return ""
    url = url.strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def fetch_line_feed(url: str, limit: int = None) -> List[str]:
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
    except Exception as exc:
        print(f"[WARN] Unable to download {url}: {exc}")
        return []
    entries = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(ensure_scheme(line))
        if limit and len(entries) >= limit:
            break
    return entries


def fetch_domain_csv(url: str, domain_index: int = 1, limit: int = None) -> List[str]:
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
    except Exception as exc:
        print(f"[WARN] Unable to download {url}: {exc}")
        return []
    reader = csv.reader(StringIO(resp.text))
    entries = []
    for row in reader:
        if len(row) <= domain_index:
            continue
        domain = row[domain_index].strip()
        if not domain or domain.lower() == "domain":
            continue
        entries.append(ensure_scheme(domain))
        if limit and len(entries) >= limit:
            break
    return entries


def fetch_json_list(url: str, limit: int = None) -> List[str]:
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
    except Exception as exc:
        print(f"[WARN] Unable to download {url}: {exc}")
        return []
    try:
        data = resp.json()
    except ValueError:
        return []
    entries = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                entries.append(ensure_scheme(item))
            elif isinstance(item, dict):
                value = item.get("url") or item.get("domain")
                if value:
                    entries.append(ensure_scheme(value))
            if limit and len(entries) >= limit:
                break
    return entries


def fetch_feed_entries(feed, limit: int) -> List[str]:
    parser = feed.get("parser")
    if parser == "lines":
        return fetch_line_feed(feed["url"], limit)
    if parser == "domains":
        domains = fetch_line_feed(feed["url"], limit)
        return [ensure_scheme(domain) for domain in domains]
    if parser == "csv_domain":
        return fetch_domain_csv(feed["url"], feed.get("domain_index", 1), limit)
    if parser == "json":
        return fetch_json_list(feed["url"], limit)
    return []


def build_dataset_from_feeds(max_samples: int) -> pd.DataFrame:
    phishing_urls = set()
    benign_urls = set()

    per_feed_limit = max(50, max_samples // max(1, len(PHISHING_FEEDS)))
    for feed in PHISHING_FEEDS:
        entries = fetch_feed_entries(feed, per_feed_limit)
        phishing_urls.update(entries)

    per_feed_limit = max(50, max_samples // max(1, len(BENIGN_FEEDS)))
    for feed in BENIGN_FEEDS:
        entries = fetch_feed_entries(feed, per_feed_limit)
        benign_urls.update(entries)

    if not phishing_urls:
        phishing_urls.update(PHISHING_FALLBACK)
    if not benign_urls:
        benign_urls.update(BENIGN_FALLBACK)

    phishing_list = list(phishing_urls)[:max_samples]
    benign_list = list(benign_urls)[:max_samples]
    print(f"📥 Collected {len(phishing_list)} phishing and {len(benign_list)} benign samples from feeds.")
    df = pd.DataFrame(
        {"url": phishing_list + benign_list, "label": [1] * len(phishing_list) + [0] * len(benign_list)}
    )
    return df


def load_dataset(refresh: bool, max_samples: int) -> pd.DataFrame:
    os.makedirs("data", exist_ok=True)
    if refresh or not os.path.exists(DATA_PATH):
        df = build_dataset_from_feeds(max_samples)
        df.to_csv(DATA_PATH, index=False)
        print(f"💾 Saved refreshed dataset to {DATA_PATH}")
        return df
    print(f"📊 Loading dataset from {DATA_PATH}")
    df = pd.read_csv(DATA_PATH)
    if {"url", "label"} - set(df.columns):
        raise ValueError("Dataset must contain 'url' and 'label' columns.")
    return df


def balance_dataset(df: pd.DataFrame) -> pd.DataFrame:
    counts = df["label"].value_counts()
    if len(counts) < 2:
        print("⚠️ Dataset has a single class only; skipping balancing.")
        return df
    min_count = counts.min()
    balanced = (
        df.groupby("label", group_keys=False)
        .apply(lambda x: x.sample(min_count, random_state=42) if len(x) > min_count else x)
        .reset_index(drop=True)
    )
    balanced = balanced.sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"⚖️ Balanced dataset to {len(balanced)} samples (per class={min_count}).")
    return balanced


def load_trusted_domains() -> List[str]:
    if not os.path.exists(TRUSTED_PATH):
        return []
    with open(TRUSTED_PATH, "r", encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip()]


def extract_all_features(df: pd.DataFrame, enable_network: bool = True) -> pd.DataFrame:
    trusted = load_trusted_domains()
    rows = []
    print(
        f"🔍 Extracting features for {len(df)} URLs "
        f"(network_enrichment={'ON' if enable_network else 'OFF'}, FEATURE_VERSION={FEATURE_VERSION})..."
    )
    for url, label in zip(df["url"], df["label"]):
        try:
            feats = extract_features_from_url(
                url,
                trusted_domains=trusted,
                enable_network_enrichment=enable_network,
            )
            feats["label"] = int(label)
            feats["url"] = url
            rows.append(feats)
        except Exception as exc:
            print(f"[WARN] feature extraction failed for {url}: {exc}")
    feature_df = pd.DataFrame(rows).fillna(0)

    # Ensure we only keep the features defined in FEATURE_DEFAULTS, in the correct order
    ordered_cols = list(FEATURE_DEFAULTS.keys())
    feature_cols = [col for col in ordered_cols if col in feature_df.columns]
    missing = [c for c in ordered_cols if c not in feature_df.columns]
    if missing:
        print(f"⚠️ Warning: missing {len(missing)} expected features: {missing[:8]}...")

    feature_df = feature_df[feature_cols + ["label", "url"]]
    print(f"✅ Final feature matrix shape: {feature_df.shape} (features={len(feature_cols)})")
    return feature_df


def build_model(model_type: str):
    if model_type == "xgboost":
        if XGBClassifier is None:
            print("⚠️ xgboost not installed. Falling back to RandomForest.")
        else:
            return XGBClassifier(
                n_estimators=500,
                max_depth=8,
                learning_rate=0.05,
                subsample=0.9,
                colsample_bytree=0.9,
                random_state=42,
                tree_method="hist",
                eval_metric="logloss",
                use_label_encoder=False,
            )
    if model_type == "lightgbm":
        if LGBMClassifier is None:
            print("⚠️ lightgbm not installed. Falling back to RandomForest.")
        else:
            return LGBMClassifier(
                n_estimators=800,
                max_depth=-1,
                learning_rate=0.03,
                subsample=0.9,
                colsample_bytree=0.9,
                class_weight="balanced",
                random_state=42,
            )
    # Default: RandomForest (rf)
    return RandomForestClassifier(
        n_estimators=400,
        max_depth=None,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample",
    )


def train_and_save(feature_df: pd.DataFrame, model_type: str):
    # Separate features vs label/url
    X = feature_df.drop(columns=["label", "url"], errors="ignore")
    y = feature_df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y if len(set(y)) > 1 else None,
    )

    model = build_model(model_type)
    print(f"📈 Training {model.__class__.__name__} on {X_train.shape[1]} features...")
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    try:
        if hasattr(model, "predict_proba"):
            y_prob = model.predict_proba(X_test)[:, 1]
            auc = roc_auc_score(y_test, y_prob)
        else:
            y_prob = None
            auc = None
    except Exception:
        y_prob = None
        auc = None

    print("✅ Accuracy:", round(accuracy_score(y_test, y_pred), 4))
    if auc is not None:
        print("✅ ROC-AUC:", round(auc, 4))
    print(classification_report(y_test, y_pred, digits=3))

    artifact = {
        "model": model,
        "columns": list(X.columns),
        "feature_version": FEATURE_VERSION,
    }
    joblib.dump(artifact, MODEL_PATH)
    print(f"💾 Saved model ({model.__class__.__name__}) to {MODEL_PATH}")
    print("ℹ️ Columns used:", len(artifact["columns"]), "FEATURE_VERSION:", FEATURE_VERSION)


def main():
    args = parse_args()
    df = load_dataset(refresh=args.refresh_feeds, max_samples=args.max_feed_samples)
    df = balance_dataset(df)
    feature_df = extract_all_features(df, enable_network=not args.disable_remote_lookups)
    train_and_save(feature_df, args.model_type)
    print("🎯 Training complete. You can now run: python app.py")


if __name__ == "__main__":
    main()
