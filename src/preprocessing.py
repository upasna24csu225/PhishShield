
import os
import pandas as pd
import re

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

RAW_PATH = os.path.join(
    BASE_DIR, "data", "raw", "phishing", "phishing_emails.csv"
)

PROCESSED_PATH = os.path.join(
    BASE_DIR, "data", "processed", "cleaned_emails.csv"
)


def clean_text(text):
    text = str(text).lower()
    text = re.sub(r"http\S+|www\S+", " URL ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def preprocess_dataset():

    if not os.path.exists(RAW_PATH):
        raise FileNotFoundError(f"Dataset not found: {RAW_PATH}")

    df = pd.read_csv(RAW_PATH)

    required_columns = ["Email Text", "Email Type"]

    for column in required_columns:
        if column not in df.columns:
            raise ValueError(f"Missing required column: {column}")

    df = df[required_columns].copy()

    df.dropna(subset=required_columns, inplace=True)

    df["Email Text"] = df["Email Text"].apply(clean_text)

    df = df[df["Email Text"] != ""]

    df["label"] = df["Email Type"].map({
        "Safe Email": 0,
        "Phishing Email": 1
    })

    df.dropna(subset=["label"], inplace=True)
    df["label"] = df["label"].astype(int)

    os.makedirs(os.path.dirname(PROCESSED_PATH), exist_ok=True)

    df.to_csv(PROCESSED_PATH, index=False)

    print("Dataset preprocessing completed!")
    print("Total records:", len(df))
    print("Processed file:", PROCESSED_PATH)

    return df


if __name__ == "__main__":
    preprocess_dataset()