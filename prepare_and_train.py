import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
from modules.homoglyph import extract_features_from_url

# -----------------------
# Step 1: Build dataset
# -----------------------

print("📦 Building dataset...")

# ✅ Benign (safe) URLs
benign = [
    "google.com", "amazon.com", "facebook.com", "twitter.com",
    "github.com", "linkedin.com", "apple.com", "wikipedia.org", "youtube.com",
    "microsoft.com", "netflix.com", "reddit.com", "instagram.com"
]
df_ben = pd.DataFrame({"url": benign, "label": [0]*len(benign)})

# ✅ Phishing URLs (from your file)
with open("data/phish_raw.txt", encoding="utf-8") as f:
    phish_urls = [x.strip() for x in f.readlines() if x.strip()]

df_phish = pd.DataFrame({"url": phish_urls, "label": [1]*len(phish_urls)})

# ✅ Combine & save
df = pd.concat([df_ben, df_phish], ignore_index=True)
df.to_csv("data/labeled_urls.csv", index=False)
print(f"✅ Dataset ready: {len(df)} total URLs ({len(df_ben)} safe, {len(df_phish)} phishing)")

print(df['label'].value_counts())

# -----------------------
# Step 2: Extract features
# -----------------------

print("🧠 Extracting features...")
features = []
labels = []

for _, row in df.iterrows():
    try:
        feats = extract_features_from_url(row['url'])
        features.append(feats)
        labels.append(row['label'])
    except Exception as e:
        print("⚠️ Skipped:", row['url'], "Error:", e)

X = pd.DataFrame(features)
y = np.array(labels)

print("✅ Features extracted:", X.shape)

# -----------------------
# Step 3: Train model
# -----------------------

print("🚀 Training model...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=200, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print("\n✅ Training complete!")
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# -----------------------
# Step 4: Save model
# -----------------------

joblib.dump(model, "rf_model.joblib")
print("\n💾 Model saved as rf_model.joblib")
print("✅ Classes:", model.classes_)
