import os
import joblib
import numpy as np

MODEL_PATH = "models/ids_model.pkl"

FEATURES = [
    "failed_attempts",
    "connection_count",
    "unique_ports",
    "packet_count",
    "bytes_transferred"
]


def load_model():
    if not os.path.exists(MODEL_PATH):
        return None

    return joblib.load(MODEL_PATH)


def predict_ml(data):
    model = load_model()

    if model is None:
        return {
            "detected": False,
            "confidence": 0,
            "prediction": "MODEL_NOT_TRAINED"
        }

    values = [data.get(feature, 0) for feature in FEATURES]

    X = np.array(values).reshape(1, -1)

    prediction = model.predict(X)[0]

    if hasattr(model, "predict_proba"):
        probability = max(model.predict_proba(X)[0])
    else:
        probability = 1.0

    detected = bool(prediction == 1)

    return {
        "detected": detected,
        "confidence": probability * 100,
        "prediction": "ATTACK" if detected else "NORMAL"
    }