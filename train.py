
import os
import re
import warnings
import joblib
import pandas as pd
import numpy as np

from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.feature_selection import mutual_info_classif
from sklearn.preprocessing import LabelEncoder

warnings.filterwarnings("ignore")

# ---------------- PATHS ----------------

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "raw" / "phishing" / "phishing_emails.csv"
OUTPUT_DIR = BASE_DIR / "outputs"
MODEL_DIR = BASE_DIR / "models"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
MODEL_DIR.mkdir(parents=True, exist_ok=True)

# ---------------- LOAD DATASET ----------------

if not DATA_PATH.exists():
    raise FileNotFoundError(f"Dataset not found: {DATA_PATH}")

df = pd.read_csv(DATA_PATH)

if "Email Text" not in df.columns or "Email Type" not in df.columns:
    raise ValueError("Dataset must contain 'Email Text' and 'Email Type' columns.")

df = df[["Email Text", "Email Type"]].dropna()
df["Email Text"] = df["Email Text"].astype(str)

def encode_label(value):
    value = str(value).strip().lower()

    if "phish" in value:
        return 1
    if "safe" in value or "legitimate" in value or "ham" in value:
        return 0

    return value

df["label"] = df["Email Type"].apply(encode_label)

if df["label"].nunique() != 2:
    raise ValueError("Dataset must contain exactly two classes: Safe and Phishing.")

encoder = LabelEncoder()
df["label"] = encoder.fit_transform(df["label"])

X = df["Email Text"]
y = df["label"]

if y.value_counts().min() < 2:
    raise ValueError("At least 2 examples of each class are required. Add more dataset rows.")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

# ---------------- ML MODELS ----------------

models = {
    "Logistic Regression": LogisticRegression(max_iter=1000),
    "SVM": LinearSVC(),
    "Random Forest": RandomForestClassifier(
        n_estimators=100,
        random_state=42
    ),
    "Neural Network": MLPClassifier(
        hidden_layer_sizes=(64, 32),
        max_iter=300,
        random_state=42,
        early_stopping=True
    )
}

# Add XGBoost if installed
try:
    from xgboost import XGBClassifier

    models["XGBoost"] = XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        random_state=42,
        eval_metric="logloss"
    )
except ImportError:
    print("XGBoost not installed. Skipping XGBoost model.")

# ---------------- TRAIN AND COMPARE ----------------

results = []
trained_models = {}

for name, model in models.items():

    print(f"\nTraining {name}...")

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=5000,
            stop_words="english",
            ngram_range=(1, 2)
        )),
        ("classifier", model)
    ])

    try:
        pipeline.fit(X_train, y_train)
        predictions = pipeline.predict(X_test)

        results.append({
            "Model": name,
            "Accuracy": accuracy_score(y_test, predictions),
            "Precision": precision_score(y_test, predictions, zero_division=0),
            "Recall": recall_score(y_test, predictions, zero_division=0),
            "F1 Score": f1_score(y_test, predictions, zero_division=0)
        })

        trained_models[name] = pipeline

        print(f"{name} completed successfully.")

    except Exception as error:
        print(f"{name} failed: {error}")

if not results:
    raise RuntimeError("No ML model could be trained successfully.")

results_df = pd.DataFrame(results)
results_df.to_csv(OUTPUT_DIR / "model_comparison.csv", index=False)

joblib.dump(trained_models, MODEL_DIR / "research_models.pkl")

# ---------------- FEATURE EXTRACTION ----------------

def extract_features(text):

    text = str(text)
    lower = text.lower()

    urls = re.findall(r"https?://\S+|www\.\S+", lower)
    words = re.findall(r"\b\w+\b", lower)

    linguistic = {
        "urgency_words": sum(
            lower.count(word)
            for word in ["urgent", "immediately", "expire", "suspended", "warning"]
        ),
        "exclamation_count": text.count("!"),
        "question_count": text.count("?"),
        "uppercase_count": sum(1 for c in text if c.isupper()),
        "word_count": len(words)
    }

    semantic = {
        "credential_terms": sum(
            lower.count(word)
            for word in ["password", "login", "verify", "account", "credential"]
        ),
        "financial_terms": sum(
            lower.count(word)
            for word in ["bank", "payment", "credit", "card", "money"]
        ),
        "reward_terms": sum(
            lower.count(word)
            for word in ["winner", "prize", "reward", "gift", "claim"]
        ),
        "action_terms": sum(
            lower.count(word)
            for word in ["click", "confirm", "update", "submit", "download"]
        )
    }

    contextual = {
        "url_count": len(urls),
        "ip_url_count": sum(
            1 for url in urls
            if re.search(r"https?://\d{1,3}(?:\.\d{1,3}){3}", url)
        ),
        "short_url_count": sum(
            1 for url in urls
            if any(short in url for short in ["bit.ly", "tinyurl", "t.co"])
        ),
        "email_count": len(re.findall(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            text
        ))
    }

    return {**linguistic, **semantic, **contextual}


feature_rows = [extract_features(text) for text in X_train]
feature_df = pd.DataFrame(feature_rows).fillna(0)

# ---------------- FEATURE IMPORTANCE ----------------

feature_groups = {
    "Linguistic": [
        "urgency_words",
        "exclamation_count",
        "question_count",
        "uppercase_count",
        "word_count"
    ],
    "Semantic": [
        "credential_terms",
        "financial_terms",
        "reward_terms",
        "action_terms"
    ],
    "Contextual": [
        "url_count",
        "ip_url_count",
        "short_url_count",
        "email_count"
    ]
}

if feature_df.shape[1] > 0:
    importance_values = mutual_info_classif(
        feature_df,
        y_train,
        random_state=42
    )

    individual_df = pd.DataFrame({
        "Feature": feature_df.columns,
        "Importance": importance_values
    })

    individual_df["Group"] = individual_df["Feature"].apply(
        lambda feature: next(
            group for group, features in feature_groups.items()
            if feature in features
        )
    )

    group_df = (
        individual_df.groupby("Group", as_index=False)["Importance"]
        .mean()
        .rename(columns={"Group": "Feature Group"})
    )

    individual_df = individual_df.sort_values(
        "Importance", ascending=False
    )

    group_df.to_csv(
        OUTPUT_DIR / "feature_group_importance.csv",
        index=False
    )

    individual_df.to_csv(
        OUTPUT_DIR / "individual_feature_importance.csv",
        index=False
    )

# ---------------- SAVE SUMMARY ----------------

print("\n====================================")
print("PHISHSHIELD X TRAINING COMPLETED")
print("====================================")

print("\nMODEL COMPARISON:")
print(results_df.to_string(index=False))

print("\nGenerated files:")
print(OUTPUT_DIR / "model_comparison.csv")
print(OUTPUT_DIR / "feature_group_importance.csv")
print(OUTPUT_DIR / "individual_feature_importance.csv")
print(MODEL_DIR / "research_models.pkl")




