"""Reproduce y verifica el enfoque de machine learning de los notebooks de Kaggle.

    python -m eval.train_ml                 # reproducción + verificación (escribe eval/ml_results.json)
    python -m eval.train_ml --save          # además guarda el modelo honesto en app/models/ (no se usa: ver README)

Pasos:
 1. Reproducción: características "raw" + Random Forest, split 80/20 estratificado -> exactitud
    comparable a la que reportan los notebooks (~97-99 %).
 2. Fuga: importancia de las columnas que dependen del esquema (count_https, count_http, www...).
 3. Modelo honesto: mismas características calculadas sin esquema ni "www." y sin esas columnas.
 4. Validación EXTERNA con datos de hoy, que el modelo nunca vio: dominios/URLs activos en las
    listas de amenazas (URLhaus, blackbook, phishing-filter, OpenPhish) frente a sitios legítimos
    del ranking Tranco (puestos 1 000-200 000). Se compara con el motor heurístico del proyecto.
"""
import argparse
import json
import random
import time
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import accuracy_score, roc_auc_score, roc_curve
from sklearn.model_selection import train_test_split

from app import heuristics
from eval.ml_features import HONEST_FEATURES, RAW_FEATURES, extract
from app.normalize import normalize_url
from eval.kaggle_eval import DATA, PHISHING_KIT, load

ROOT = Path(__file__).resolve().parent.parent
FEEDS_DIR = ROOT / "data" / "threat_feeds"
MODEL_PATH = ROOT / "app" / "models" / "url_model.joblib"
OUT = ROOT / "eval" / "ml_results.json"


def _X(urls, honest):
    return np.array([extract(u, honest) for u in urls], dtype=np.float32)


def _recall_at_fpr(y, p, fpr_target):
    fpr, tpr, _ = roc_curve(y, p)
    return float(tpr[np.searchsorted(fpr, fpr_target, side="right") - 1])


def external_set(tranco_csv: Path, n: int, seed: int):
    rng = random.Random(seed)
    bad = []
    for name in ("URLhaus", "blackbook", "phishing-filter"):
        lines = (FEEDS_DIR / f"{name}.txt").read_text(encoding="utf-8").splitlines()
        bad += [l.strip() for l in lines if l.strip() and l[0] not in "#!"]
    bad += [l.strip() for l in (FEEDS_DIR / "OpenPhish.txt").read_text(encoding="utf-8").splitlines() if l.strip()]
    good = [l.strip().split(",", 1)[1] for l in tranco_csv.read_text().splitlines()[1000:200000]]
    bad, good = rng.sample(bad, min(n, len(bad))), rng.sample(good, n)
    return bad + good, np.array([1] * len(bad) + [0] * len(good))


def heuristic_scores(urls):
    out = []
    for u in urls:
        try:
            url, _ = normalize_url(u)
            out.append(min(sum(f["points"] for f in heuristics.evaluate(url, 0, 10_000)[1] if f["id"] != "no_https"), 100))
        except Exception:
            out.append(0)
    return np.array(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tranco", type=Path, required=True, help="top-1m.csv de https://tranco-list.eu")
    ap.add_argument("--save", action="store_true")
    ap.add_argument("--external-n", type=int, default=5000)
    args = ap.parse_args()
    t0 = time.time()
    res = {"dataset": str(DATA.name)}

    rows = load(None, 42)
    urls = [u for u, _ in rows]
    y = np.array([0 if t == "benign" else 1 for _, t in rows])
    print(f"{len(urls)} URLs ({y.mean():.1%} maliciosas)")

    # 1) Reproducción (como los notebooks)
    Xr = _X(urls, honest=False)
    Xtr, Xte, ytr, yte = train_test_split(Xr, y, test_size=0.2, stratify=y, random_state=42)
    rf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42, min_samples_leaf=2).fit(Xtr, ytr)
    acc_raw = accuracy_score(yte, rf.predict(Xte))
    imp = sorted(zip(RAW_FEATURES, rf.feature_importances_), key=lambda x: -x[1])
    res["reproduccion"] = {"modelo": "RandomForest(100)", "accuracy_test": round(acc_raw, 4),
                           "auc_test": round(roc_auc_score(yte, rf.predict_proba(Xte)[:, 1]), 4),
                           "importancias_top": [(k, round(float(v), 4)) for k, v in imp[:8]]}
    print(f"[1] Reproducción RF raw: accuracy={acc_raw:.4f}  top={[k for k, _ in imp[:5]]}")

    # Solo el esquema: ¿cuánto acierta un clasificador que mira únicamente http/https/www?
    leak_idx = [RAW_FEATURES.index(k) for k in ("count_https", "count_http", "count_www", "abnormal_url")]
    rf_leak = RandomForestClassifier(n_estimators=50, n_jobs=-1, random_state=42).fit(Xtr[:, leak_idx], ytr)
    res["solo_esquema_accuracy"] = round(accuracy_score(yte, rf_leak.predict(Xte[:, leak_idx])), 4)
    print(f"[2] Solo columnas de esquema/www: accuracy={res['solo_esquema_accuracy']:.4f}")

    # 3) Modelo honesto (sin esquema ni www, sin kits mal etiquetados como benignos)
    keep = [i for i, (u, t) in enumerate(rows) if not (t == "benign" and PHISHING_KIT.search(u))]
    Xh = _X([urls[i] for i in keep], honest=True)
    yh = y[keep]
    Xtr, Xte, ytr, yte = train_test_split(Xh, yh, test_size=0.2, stratify=yh, random_state=42)
    hgb = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1, random_state=42).fit(Xtr, ytr)
    p = hgb.predict_proba(Xte)[:, 1]
    res["honesto_kaggle"] = {"modelo": "HistGradientBoosting", "accuracy_test": round(accuracy_score(yte, p > 0.5), 4),
                             "auc_test": round(roc_auc_score(yte, p), 4)}
    print(f"[3] Honesto en Kaggle: {res['honesto_kaggle']}")

    # 4) Validación externa con datos de hoy
    ext_urls, ext_y = external_set(args.tranco, args.external_n, 7)
    ext = {}
    for name, scores in (
        ("rf_notebook", rf.predict_proba(_X(ext_urls, honest=False))[:, 1]),
        ("ml_honesto", hgb.predict_proba(_X(ext_urls, honest=True))[:, 1]),
        ("heuristica_proyecto", heuristic_scores(ext_urls)),
    ):
        ext[name] = {"auc": round(roc_auc_score(ext_y, scores), 4),
                     "recall_fpr_1pct": round(_recall_at_fpr(ext_y, scores, 0.01), 4),
                     "recall_fpr_5pct": round(_recall_at_fpr(ext_y, scores, 0.05), 4)}
        print(f"[4] Externo {name:20} {ext[name]}")
    combo = 0.5 * hgb.predict_proba(_X(ext_urls, True))[:, 1] + 0.5 * heuristic_scores(ext_urls) / 100
    ext["ml_honesto+heuristica"] = {"auc": round(roc_auc_score(ext_y, combo), 4),
                                    "recall_fpr_1pct": round(_recall_at_fpr(ext_y, combo, 0.01), 4),
                                    "recall_fpr_5pct": round(_recall_at_fpr(ext_y, combo, 0.05), 4)}
    print(f"[4] Externo {'ml_honesto+heuristica':20} {ext['ml_honesto+heuristica']}")
    res["externo_2026"] = {"n_maliciosas": int(ext_y.sum()), "n_legitimas": int((1 - ext_y).sum()), **ext}

    # Umbrales del modelo honesto para un FPR de 1 % y 5 % en sitios legítimos de hoy
    good_p = np.sort(hgb.predict_proba(_X([u for u, t in zip(ext_urls, ext_y) if t == 0], True))[:, 1])
    res["umbrales_honesto"] = {"fpr_1pct": round(float(good_p[int(len(good_p) * 0.99)]), 4),
                               "fpr_5pct": round(float(good_p[int(len(good_p) * 0.95)]), 4)}
    res["segundos"] = round(time.time() - t0, 1)
    OUT.write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Resultados en {OUT}")

    if args.save:
        import joblib
        import sklearn
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": hgb, "features": HONEST_FEATURES, "sklearn": sklearn.__version__,
                     "thresholds": res["umbrales_honesto"], "metrics": {"kaggle": res["honesto_kaggle"],
                                                                        "externo": ext["ml_honesto"]}},
                    MODEL_PATH, compress=3)
        print(f"Modelo guardado en {MODEL_PATH} ({MODEL_PATH.stat().st_size / 1024:.0f} KB)")


if __name__ == "__main__":
    main()
