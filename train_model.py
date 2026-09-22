import joblib
import pandas as pd

data = joblib.load("threat_model.pkl")
model = data["model"]
features = data["features"]

def predict_ml(feature_data):
    X = pd.DataFrame([feature_data])[features]
    prediction = model.predict(X)[0]
    probability = max(model.predict_proba(X)[0])
    return prediction, probability