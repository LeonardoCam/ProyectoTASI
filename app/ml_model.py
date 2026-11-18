"""Módulo de inferencia del modelo de Machine Learning (Capa 2 honesta).

Carga el clasificador HistGradientBoosting entrenado sobre características léxicas honestas
(sin fuga de datos por esquema HTTP/HTTPS ni prefijo www).

Se utiliza como capa complementaria determinista-estadística para calibrar enlaces en la
"zona gris" (puntuaciones intermedias o ambiguas).
"""
import logging
from pathlib import Path
from typing import Any, Dict, Optional

import joblib

from eval.ml_features import HONEST_FEATURES, extract

logger = logging.getLogger("ml_model")

MODEL_PATH = Path(__file__).resolve().parent / "models" / "url_model.joblib"

_MODEL_CACHE: Optional[Dict[str, Any]] = None


def get_model_bundle() -> Optional[Dict[str, Any]]:
    """Carga de forma perezosa y segura el artefacto del modelo."""
    global _MODEL_CACHE
    if _MODEL_CACHE is not None:
        return _MODEL_CACHE

    if not MODEL_PATH.exists():
        logger.warning("No se encontró el modelo ML en %s. Capa ML inactiva.", MODEL_PATH)
        return None

    try:
        data = joblib.load(MODEL_PATH)
        _MODEL_CACHE = data
        logger.info(
            "Modelo ML cargado exitosamente (%d características, exactitud prueba: %s).",
            len(data.get("features", [])),
            data.get("metrics", {}).get("accuracy", "n/a"),
        )
        return _MODEL_CACHE
    except Exception as exc:
        logger.error("Error al cargar el modelo ML desde %s: %s", MODEL_PATH, exc)
        return None


def evaluate_ml(url: str) -> Dict[str, Any]:
    """Evalúa las características léxicas de la URL con el modelo honesto."""
    bundle = get_model_bundle()
    if bundle is None:
        return {
            "available": False,
            "probability": None,
            "risk_score": None,
            "risk_level": "NO_DISPONIBLE",
            "high_risk": False,
            "low_risk": False,
            "features": {},
            "metrics": {},
        }

    clf = bundle["model"]
    thresholds = bundle.get("thresholds", {"high_risk": 0.65, "low_risk": 0.25})
    high_th = thresholds.get("high_risk", 0.65)
    low_th = thresholds.get("low_risk", 0.25)

    try:
        feats = extract(url, honest=True)
        prob = float(clf.predict_proba([feats])[0, 1])
        risk_score = round(prob * 100, 1)

        if prob >= high_th:
            level = "ALTO"
        elif prob >= 0.40:
            level = "MEDIO"
        else:
            level = "BAJO"

        feature_dict = dict(zip(HONEST_FEATURES, feats))

        return {
            "available": True,
            "probability": round(prob, 4),
            "risk_score": risk_score,
            "risk_level": level,
            "high_risk": prob >= high_th,
            "low_risk": prob <= low_th,
            "features": feature_dict,
            "metrics": bundle.get("metrics", {}),
        }
    except Exception as exc:
        logger.error("Error durante la inferencia ML para la URL %s: %s", url, exc)
        return {
            "available": False,
            "probability": None,
            "risk_score": None,
            "risk_level": "ERROR",
            "high_risk": False,
            "low_risk": False,
            "features": {},
            "metrics": {},
        }
