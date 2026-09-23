import os
import joblib
import pandas as pd


# =========================================================
# MODEL PATH
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "threat_model.pkl")


# =========================================================
# MODEL VARIABLES
# =========================================================

_model = None
_features = None


# =========================================================
# LOAD MODEL
# =========================================================

def load_model():
    global _model, _features

    if _model is not None:
        return _model, _features

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"threat_model.pkl was not found at:\n{MODEL_PATH}"
        )

    data = joblib.load(MODEL_PATH)

    if not isinstance(data, dict):
        raise ValueError(
            "threat_model.pkl must contain a dictionary "
            "with 'model' and 'features'."
        )

    if "model" not in data:
        raise KeyError(
            "The key 'model' was not found in threat_model.pkl."
        )

    if "features" not in data:
        raise KeyError(
            "The key 'features' was not found in threat_model.pkl."
        )

    _model = data["model"]
    _features = data["features"]

    if not _features:
        raise ValueError(
            "The feature list inside threat_model.pkl is empty."
        )

    return _model, _features


# =========================================================
# ML PREDICTION
# =========================================================

def predict_ml(feature_data):

    model, features = load_model()

    if not isinstance(feature_data, dict):
        raise TypeError(
            "feature_data must be a dictionary."
        )

    # Create one-row DataFrame using the exact
    # feature order used during model training.
    X = pd.DataFrame([feature_data])

    # Add missing features with 0.
    for feature in features:
        if feature not in X.columns:
            X[feature] = 0

    # Keep ONLY the features expected by the model
    # and preserve their original training order.
    X = X[features]

    # Make prediction
    prediction = model.predict(X)[0]

    # Calculate confidence
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X)[0]
        probability = float(max(probabilities))
    else:
        probability = 0.0

    return prediction, probability
