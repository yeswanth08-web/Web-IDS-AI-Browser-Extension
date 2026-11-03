"""Train an optional Random Forest baseline from a labelled packet-feature CSV.

Required columns: Length, TTL, Protocol, IsTCP, IsUDP, IsICMP, Label.
This is a packet-level starter schema, not a direct import of CIC-IDS flow columns.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline

FEATURES = ["Length", "TTL", "Protocol", "IsTCP", "IsUDP", "IsICMP"]
BENIGN_LABELS = {"benign", "normal", "0", "false", "legitimate"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", help="CSV containing the required features and Label")
    parser.add_argument("--label-column", default="Label")
    parser.add_argument("--output", default=str(Path(__file__).with_name("webguard_rf.joblib")))
    args = parser.parse_args()

    frame = pd.read_csv(args.csv)
    required = FEATURES + [args.label_column]
    missing = sorted(set(required) - set(frame.columns))
    if missing:
        raise SystemExit("CSV is missing columns: " + ", ".join(missing))

    features = frame[FEATURES].apply(pd.to_numeric, errors="coerce")
    features = features.replace([np.inf, -np.inf], np.nan)
    labels = frame[args.label_column].astype("string").str.strip().str.lower()
    valid_labels = labels.notna() & labels.ne("")
    features, labels = features.loc[valid_labels], labels.loc[valid_labels]
    labels = labels.map(lambda value: "benign" if value in BENIGN_LABELS else "attack")

    # Remove rows with no usable feature values; remaining missing cells are imputed.
    usable = features.notna().any(axis=1)
    features, labels = features.loc[usable], labels.loc[usable]
    if features.empty or features.isna().all().any():
        raise SystemExit("Each feature column must contain at least one numeric value.")
    counts = labels.value_counts()
    if labels.nunique() != 2 or counts.min() < 2:
        raise SystemExit("Need at least two rows in each binary class (benign and attack).")

    x_train, x_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.25, random_state=42, stratify=labels
    )
    model = make_pipeline(
        SimpleImputer(strategy="median"),
        RandomForestClassifier(
            n_estimators=250,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
            min_samples_leaf=2,
        ),
    )
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)

    print("Held-out classification report (not a guarantee of real-world performance):")
    print(classification_report(y_test, predictions, labels=["benign", "attack"], zero_division=0))
    print("Confusion matrix [benign, attack]:")
    print(confusion_matrix(y_test, predictions, labels=["benign", "attack"]))

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output)
    print(f"Saved model: {output}")
    print("Reminder: validate on an independent, representative capture/dataset before interpreting these metrics.")


if __name__ == "__main__":
    main()
