import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
from modules.homoglyph import extract_features_from_url  # reuse your module if it has this

# 1. Load dataset (must contain 'url' and 'label' columns)
df = pd.read_csv("phishing_dataset.csv")  # <-- put your dataset path

# 2. Extract features
feature_list = []
labels = []

for _, row in df.iterrows():
    features = extract_features_from_url(row['url'])
    feature_list.append(features)
    labels.append(row['label'])

X = pd.DataFrame(feature_list)
y = np.array(labels)

# 3. Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. Train Random Forest
model = RandomForestClassifier(n_estimators=200, random_state=42)
model.fit(X_train, y_train)

# 5. Evaluate
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# 6. Save model
joblib.dump(model, "rf_model.joblib")
print("✅ Model saved as rf_model.joblib")
