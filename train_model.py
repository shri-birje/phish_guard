# train_model.py
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
from modules.features import extract_features_from_url

print("📊 Loading dataset...")
df = pd.read_csv("data/labeled_urls.csv")

print("🔍 Extracting features...")
trusted = []
try:
    with open("trusted_domains.txt", "r", encoding="utf-8") as f:
        trusted = [x.strip().lower() for x in f if x.strip()]
except:
    trusted = []

feature_list = []
labels = []

for _, row in df.iterrows():
    feats = extract_features_from_url(row["url"], trusted_domains=trusted)
    feature_list.append(feats)
    labels.append(int(row["label"]))

X = pd.DataFrame(feature_list).fillna(0)
y = np.array(labels)

print("📈 Training model...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

model = RandomForestClassifier(n_estimators=200, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"✅ Accuracy: {acc:.2f}")
print(classification_report(y_test, y_pred))

# Save model with columns for inference alignment
joblib.dump({"model": model, "columns": X.columns.tolist()}, "rf_model.joblib")
print("💾 Model saved as rf_model.joblib with feature columns.")
