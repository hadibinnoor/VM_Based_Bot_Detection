"""
Flask-based inference microservice.

Endpoints:

    POST /predict   { "features": [<N_FEATURES floats>] }
                    →  { "is_bot": bool, "confidence": float, "bot_prob": float }

    GET  /health    →  { "status": "ok", "n_features": int }
    GET  /features  →  { "features": [<name>, ...] }

Run:
    python3 inference_server.py
"""

from __future__ import annotations

import logging
import os
import sys

import joblib
import numpy as np
from flask import Flask, jsonify, request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import FEATURE_NAMES, N_FEATURES  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("inference")

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(HERE, "rf_model.pkl")

app = Flask(__name__)

try:
    model = joblib.load(MODEL_PATH)
    logger.info("Model loaded from %s (features=%d)", MODEL_PATH, N_FEATURES)
except FileNotFoundError:
    logger.error("rf_model.pkl not found. Run train_model.py first.")
    sys.exit(1)


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True)
    if not data or "features" not in data:
        return jsonify({"error": "missing features"}), 400

    feats = data["features"]
    if not isinstance(feats, list) or len(feats) != N_FEATURES:
        return (
            jsonify(
                {"error": f"expected {N_FEATURES} features, got {len(feats) if isinstance(feats, list) else type(feats).__name__}"}
            ),
            400,
        )

    try:
        x = np.asarray(feats, dtype=np.float64).reshape(1, -1)
    except (TypeError, ValueError) as exc:
        return jsonify({"error": f"bad feature values: {exc}"}), 400

    # Defensive: NaN / inf can appear if the Go side divides by zero
    # (e.g. timing_jitter_ratio with mean=0 after an incomplete VM run).
    x = np.nan_to_num(x, nan=0.0, posinf=0.0, neginf=0.0)

    is_bot_int = int(model.predict(x)[0])
    proba = model.predict_proba(x)[0]
    confidence = float(proba[is_bot_int])
    bot_prob = float(proba[1])

    return jsonify(
        {
            "is_bot": bool(is_bot_int),
            "confidence": round(confidence, 4),
            "bot_prob": round(bot_prob, 4),
        }
    )


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "n_features": N_FEATURES})


@app.route("/features", methods=["GET"])
def features_endpoint():
    return jsonify({"features": FEATURE_NAMES})


if __name__ == "__main__":
    host = os.getenv("ML_HOST", "127.0.0.1")
    port = int(os.getenv("ML_PORT", "5001"))
    app.run(host=host, port=port, debug=False, threaded=True)
