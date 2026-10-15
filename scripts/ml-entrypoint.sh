#!/bin/sh
set -eu

MODEL_PATH="/app/ml/rf_model.pkl"
AUTO_TRAIN="${ML_AUTO_TRAIN_IF_MISSING:-false}"

if [ ! -f "$MODEL_PATH" ]; then
  if [ "$AUTO_TRAIN" = "true" ]; then
    echo "[ml-entrypoint] rf_model.pkl not found, training model (auto-train enabled)..."
    python /app/ml/train_model.py
  else
    echo "[ml-entrypoint] ERROR: rf_model.pkl not found and auto-train is disabled."
    echo "[ml-entrypoint] Provide /app/ml/rf_model.pkl or set ML_AUTO_TRAIN_IF_MISSING=true."
    exit 1
  fi
fi

echo "[ml-entrypoint] starting inference server..."
exec python /app/ml/inference_server.py
