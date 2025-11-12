# auto_retrain.py
import sqlite3
import json
import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
from datetime import datetime, timedelta

DB = os.path.join(os.path.dirname(__file__), "phishing_logs.db")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "rf_model.joblib")

# threshold config
MIN_NEW_EXAMPLES = 20  # retrain only when at least this many labeled examples available
TEST_SIZE = 0.2
RANDOM_STATE = 42

def fetch_labeled_examples(conn):
    # this expects that logs.features_json contains a dict including a numeric 'label' field
    cur = conn.cursor()
    cur.execute("SELECT url, features_json FROM logs WHERE features_json IS NOT NULL")
    rows = cur.fetchall()
    data = []
    for url, features_json in rows:
        try:
            feats = json.loads(features_json)
            # label: either included in features (if you manually added), else attempt to heuristically label:
            # Use phishing_score > 50 as positive for auto-retrain (you might want manual review)
            # For now, we skip if no label
            if 'label' in feats:
                label = int(feats['label'])
            elif 'model_raw_probability' in feats:
                label = 1 if feats['model_raw_probability'] >= 0.5 else 0
            else:
                # fallback: skip ambiguous examples
                continue
            data.append((url, feats, label))
        except Exception:
            continue
    return data

def prepare_dataset(data):
    # build X, y from data list
    feature_rows = []
    labels = []
    for url, feats, label in data:
        # remove non-numeric or nested fields
        clean = {k: (v if isinstance(v, (int,float)) else (float(v) if isinstance(v, bool) else None)) for k,v in feats.items() if isinstance(v,(int,float,bool))}
        if not clean:
            continue
        feature_rows.append(clean)
        labels.append(label)
    if not feature_rows:
        return None, None
    X = pd.DataFrame(feature_rows).fillna(0)
    y = np.array(labels)
    return X, y

def train_and_save(X, y):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y if len(set(y))>1 else None)
    model = RandomForestClassifier(n_estimators=200, random_state=RANDOM_STATE)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))
    joblib.dump({"model": model, "columns": list(X.columns)}, MODEL_PATH)
    print("💾 Saved model to", MODEL_PATH)

def main():
    conn = sqlite3.connect(DB)
    data = fetch_labeled_examples(conn)
    conn.close()
    print("Found examples:", len(data))
    if len(data) < MIN_NEW_EXAMPLES:
        print("Not enough labeled examples to retrain (need at least {})".format(MIN_NEW_EXAMPLES))
        return
    X, y = prepare_dataset(data)
    if X is None or len(X) < MIN_NEW_EXAMPLES:
        print("Not enough usable features.")
        return
    train_and_save(X, y)

if __name__ == "__main__":
    main()
