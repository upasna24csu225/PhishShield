

import os
import pandas as pd

DATASET_PATH = os.path.join(
    "data", "raw", "phishing", "phishing_emails.csv"
)


def check_dataset():

    print("\n========== DATASET VALIDATION ==========\n")

    if not os.path.exists(DATASET_PATH):
        print("ERROR: Dataset file not found!")
        return

    df = pd.read_csv(DATASET_PATH)

    print("Dataset loaded successfully!")
    print("Shape:", df.shape)

    required_columns = ["Email Text", "Email Type"]

    missing_columns = [
        col for col in required_columns if col not in df.columns
    ]

    if missing_columns:
        print("Missing columns:", missing_columns)
        return

    print("\nRequired columns: PASS")

    print("\nMissing values:")
    print(df[required_columns].isnull().sum())

    print("\nDuplicate rows:", df.duplicated().sum())

    print("\nLabel distribution:")
    print(df["Email Type"].value_counts())

    valid_labels = ["Safe Email", "Phishing Email"]

    invalid_labels = df[
        ~df["Email Type"].isin(valid_labels)
    ]

    print("\nInvalid labels:", len(invalid_labels))

    empty_emails = (
        df["Email Text"].astype(str).str.strip() == ""
    ).sum()

    print("Empty email records:", empty_emails)

    print("\n========== VALIDATION COMPLETE ==========")


if __name__ == "__main__":
    check_dataset()