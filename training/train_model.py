import os
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

DATASET = "dataset/network_data.csv"
MODEL_PATH = "models/ids_model.pkl"

FEATURES = [
    "failed_attempts",
    "connection_count",
    "unique_ports",
    "packet_count",
    "bytes_transferred"
]

TARGET = "label"


def train():

    df = pd.read_csv(DATASET)

    X = df[FEATURES]
    y = df[TARGET]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced"
    )

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("Accuracy:",
          accuracy_score(y_test, predictions))

    print("\nClassification Report:")
    print(classification_report(y_test, predictions))

    os.makedirs("models", exist_ok=True)

    joblib.dump(model, MODEL_PATH)

    print("\nModel saved:", MODEL_PATH)


if __name__ == "__main__":
    train()