import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os

# ============================
# Load Dataset
# ============================

df = pd.read_csv("dataset/Malware dataset.csv")

print("Dataset Loaded Successfully")
print(df.shape)

# ============================
# Remove hash column
# ============================

df = df.drop("hash", axis=1)

# ============================
# Convert malware/benign to numbers
# ============================

encoder = LabelEncoder()
df["classification"] = encoder.fit_transform(df["classification"])

# ============================
# Split Features and Labels
# ============================

X = df.drop("classification", axis=1)
y = df["classification"]

# ============================
# Train/Test Split
# ============================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42
)

# ============================
# Train Random Forest
# ============================

print("\nTraining Model...\n")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)

# ============================
# Prediction
# ============================

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\nModel Accuracy:")
print(f"{accuracy*100:.2f}%")

print("\nClassification Report:\n")
print(classification_report(y_test, predictions))

# ============================
# Save Model
# ============================

os.makedirs("models", exist_ok=True)

joblib.dump(model, "models/malware_model.pkl")

print("\nModel Saved Successfully!")
print("Location: models/malware_model.pkl")