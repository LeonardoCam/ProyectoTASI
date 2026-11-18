"""Script de entrenamiento para el modelo honesto de Machine Learning (Capa 2).

Combina:
1. Muestras léxicas de URLs de Kaggle filtradas (sin fuga de datos de esquema ni www).
2. Feeds de amenazas activos (URLhaus, OpenPhish, phishing-filter, blackbook).
3. Dominios legítimos Tranco y peruanos con patrones de rutas comunes.
4. Exporta el modelo optimizado HistGradientBoostingClassifier a app/models/url_model.joblib.
"""
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import accuracy_score, roc_auc_score
from sklearn.model_selection import train_test_split

from app.tranco import _DEFAULT_TRANCO_TOP
from eval.kaggle_eval import PHISHING_KIT, load
from eval.ml_features import HONEST_FEATURES, extract

ROOT = Path(__file__).resolve().parent.parent
FEEDS_DIR = ROOT / "data" / "threat_feeds"
MODEL_PATH = ROOT / "app" / "models" / "url_model.joblib"


def train_and_save():
    t0 = time.time()
    rng = random.Random(42)

    # 1. URLs de Kaggle
    rows = load(150000, 42)
    benign_kaggle = [u for u, t in rows if t == "benign" and not PHISHING_KIT.search(u)]
    malicious_kaggle = [u for u, t in rows if t in ("phishing", "malware")]

    # 2. Dominios y rutas legítimas
    popular_domains = [
        "upch.edu.pe", "pucp.edu.pe", "unmsm.edu.pe", "uni.edu.pe", "gob.pe", "reniec.gob.pe", "sunat.gob.pe",
        "viabcp.com", "interbank.pe", "bbva.pe", "scotiabank.com.pe", "bancodelanacion.com.pe",
        "elcomercio.pe", "larepublica.pe", "rpp.pe", "andina.pe",
        "mit.edu", "stanford.edu", "harvard.edu", "ox.ac.uk", "cam.ac.uk",
        "bbc.com", "cnn.com", "nytimes.com", "theguardian.com", "reuters.com",
    ]
    all_benign_bases = list(set(list(_DEFAULT_TRANCO_TOP) + popular_domains))

    benign_synthetic = []
    for d in all_benign_bases:
        benign_synthetic.append(d)
        benign_synthetic.append(f"{d}/")
        for p in ["index.html", "home", "login", "portal", "about-us", "contact", "services", "search?q=info", "help/faq", "en/home", "terms"]:
            benign_synthetic.append(f"{d}/{p}")

    # 3. Feeds de amenazas en vivo
    live_threat_urls = []
    for name in ("URLhaus", "blackbook", "phishing-filter", "OpenPhish"):
        p = FEEDS_DIR / f"{name}.txt"
        if p.exists():
            lines = [l.strip() for l in p.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip() and not l.startswith(("#", "!"))]
            live_threat_urls.extend(lines)

    n_b = min(len(benign_kaggle), 35000)
    n_m = min(len(malicious_kaggle), 25000)
    n_t = min(len(live_threat_urls), 25000)

    all_benign = rng.sample(benign_kaggle, n_b) + benign_synthetic * 8
    all_malicious = rng.sample(malicious_kaggle, n_m) + rng.sample(live_threat_urls, n_t)

    urls = all_benign + all_malicious
    y = np.array([0] * len(all_benign) + [1] * len(all_malicious), dtype=np.int32)
    print(f"Dataset consolidado: {len(urls)} muestras ({y.mean():.1%} maliciosas) en {time.time()-t0:.1f}s")

    t1 = time.time()
    X = np.array([extract(u, honest=True) for u in urls], dtype=np.float32)
    print(f"Extracción de características completada en {time.time()-t1:.1f}s")

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.15, stratify=y, random_state=42)
    clf = HistGradientBoostingClassifier(max_iter=220, learning_rate=0.08, min_samples_leaf=30, random_state=42)
    clf.fit(Xtr, ytr)

    probs = clf.predict_proba(Xte)[:, 1]
    acc = float(accuracy_score(yte, probs > 0.5))
    auc = float(roc_auc_score(yte, probs))
    print(f"Exactitud en prueba: {acc:.4f}, AUC: {auc:.4f}")

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "model": clf,
        "features": HONEST_FEATURES,
        "sklearn_version": sklearn.__version__,
        "metrics": {
            "accuracy": round(acc, 4),
            "auc": round(auc, 4),
            "training_samples": int(len(Xtr)),
            "test_samples": int(len(Xte)),
        },
        "thresholds": {
            "high_risk": 0.65,
            "low_risk": 0.25,
        },
    }
    joblib.dump(payload, MODEL_PATH, compress=3)
    print(f"Modelo guardado exitosamente en {MODEL_PATH} ({MODEL_PATH.stat().st_size / 1024:.1f} KB)")


if __name__ == "__main__":
    train_and_save()
