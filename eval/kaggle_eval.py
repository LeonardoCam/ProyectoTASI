"""Evaluación del motor heurístico con el dataset público de Kaggle "Malicious URLs dataset".

Fuente: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset (malicious_phish.csv,
651 191 URLs etiquetadas: benign, phishing, defacement, malware).

Uso:
    python -m eval.kaggle_eval --download          # descarga el CSV a eval/data/ (una vez)
    python -m eval.kaggle_eval                      # evalúa todo el dataset
    python -m eval.kaggle_eval --limit 50000        # muestra estratificada reproducible

Es una evaluación OFFLINE: no se visita ninguna URL (muchas son maliciosas o ya no existen),
así que solo mide la parte léxica del motor (dominio, TLD, IP, subdominios, palabras clave,
suplantación de marca...). Los factores que dependen de la red se fijan por escenario:
  - "whois_ok":   antigüedad conocida y antigua (aísla los factores léxicos).
  - "whois_none": WHOIS no disponible (como ocurre con .pe, .co.uk, .de...).
En ambos, hops=0 y HTTPS se toma del esquema escrito en la URL (sin esquema -> https).

Advertencia del dataset: casi todas las URLs benignas vienen sin esquema y todas las de
defacement con http://, así que el esquema "filtra" la etiqueta. Por eso se reporta también
la tasa de falsos positivos SIN el factor no_https, que es la cifra honesta.

Escribe eval/kaggle_results.json.
"""
import argparse
import collections
import csv
import io
import json
import random
import re
import time
import urllib.request
import zipfile
from pathlib import Path

from app import heuristics
from app.normalize import normalize_url

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data" / "malicious_phish.csv"
OUT = ROOT / "kaggle_results.json"
DOWNLOAD_URL = "https://www.kaggle.com/api/v1/datasets/download/sid321axn/malicious-urls-dataset"
LABELS = ("benign", "phishing", "defacement", "malware")
SCENARIOS = {"whois_ok": 10_000, "whois_none": None}
# El dataset tiene ruido de etiqueta: miles de URLs "benign" son kits de phishing evidentes
# (paypal.com.cgi.bin.webscr...otro-dominio.com). Se cuentan aparte para no confundirlas con FP reales.
PHISHING_KIT = re.compile(
    r"(webscr|cgi[.-]bin|\b(paypal|apple|ebay|amazon|icloud|netflix|facebook|microsoft)[.-](com|co|info|fr|us)[.-])",
    re.IGNORECASE,
)


def download() -> None:
    DATA.parent.mkdir(parents=True, exist_ok=True)
    print(f"Descargando {DOWNLOAD_URL} ...")
    with urllib.request.urlopen(DOWNLOAD_URL, timeout=300) as r:
        blob = r.read()
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        DATA.write_bytes(z.read("malicious_phish.csv"))
    print(f"Guardado en {DATA} ({DATA.stat().st_size / 1e6:.1f} MB)")


def load(limit: int | None, seed: int) -> list[tuple[str, str]]:
    with open(DATA, encoding="utf-8", errors="replace", newline="") as f:
        rows = [(r["url"], r["type"]) for r in csv.DictReader(f) if r["type"] in LABELS]
    if limit and limit < len(rows):
        rng = random.Random(seed)
        by = collections.defaultdict(list)
        for u, t in rows:
            by[t].append((u, t))
        rows = []
        for t, items in by.items():  # estratificado: mantiene la proporción de cada clase
            rows += rng.sample(items, max(1, round(limit * len(items) / sum(map(len, by.values())))))
    return rows


def _auc(y: list[int], s: list[int]):
    """AUC ROC (Mann-Whitney) sin dependencias: prob. de que un phishing puntúe más que una benigna."""
    pos = collections.Counter(v for v, t in zip(s, y) if t == 1)
    neg = collections.Counter(v for v, t in zip(s, y) if t == 0)
    n_pos, n_neg = sum(pos.values()), sum(neg.values())
    if not n_pos or not n_neg:
        return None
    wins, neg_below = 0.0, 0
    for v in sorted(set(pos) | set(neg)):
        wins += pos[v] * (neg_below + neg[v] / 2)
        neg_below += neg[v]
    return round(wins / (n_pos * n_neg), 4)


def evaluate(rows, age):
    flagged = collections.Counter()         # score >= MEDIO por etiqueta
    flagged_no_http = collections.Counter() # idem, ignorando el factor no_https
    total = collections.Counter()
    factor_fire = collections.defaultdict(collections.Counter)
    fp_factor = collections.Counter()
    fp_examples = []
    rng = random.Random(0)
    auc_y, auc_s = [], []  # para el AUC en los subconjuntos de alta confianza
    fp_label_noise = 0
    benign_noise_total = 0
    phish_scheme_total = phish_scheme_hit = 0
    fn_examples = []
    for raw, label in rows:
        try:
            url, _ = normalize_url(raw)
            score, factors = heuristics.evaluate(url, 0, age, None)
        except Exception:
            continue
        total[label] += 1
        ids = {f["id"] for f in factors}
        for i in ids:
            factor_fire[i][label] += 1
        score_wo = min(sum(f["points"] for f in factors if f["id"] != "no_https"), 100)
        if label == "benign" and PHISHING_KIT.search(raw):
            benign_noise_total += 1
        elif label == "benign":
            auc_y.append(0); auc_s.append(score_wo)
        if label == "phishing" and raw.lower().startswith(("http://", "https://")):
            auc_y.append(1); auc_s.append(score_wo)
            phish_scheme_total += 1
            if score_wo >= heuristics.MEDIUM_THRESHOLD:
                phish_scheme_hit += 1
            elif len(fn_examples) < 15 and rng.random() < 0.01:
                fn_examples.append({"url": raw[:160], "score": score_wo, "factors": sorted(ids - {"no_https"})})
        if score >= heuristics.MEDIUM_THRESHOLD:
            flagged[label] += 1
        if score_wo >= heuristics.MEDIUM_THRESHOLD:
            flagged_no_http[label] += 1
            if label == "benign" and PHISHING_KIT.search(raw):
                fp_label_noise += 1
            elif label == "benign":
                fp_factor.update(ids - {"no_https"})
                if len(fp_examples) < 15:
                    fp_examples.append({"url": raw, "score": score_wo, "factors": sorted(ids - {"no_https"})})

    def rate(c, t):
        return round(c[t] / total[t], 4) if total[t] else None

    # Subconjuntos de alta confianza (ver docstring): phishing con esquema explícito y benignas
    # sin kits mal etiquetados. Sin el factor no_https para no aprovechar la fuga del esquema.
    clean_fp = flagged_no_http["benign"] - fp_label_noise
    clean_benign = total["benign"] - benign_noise_total

    malicious = [t for t in LABELS if t != "benign"]
    mal_total = sum(total[t] for t in malicious)
    return {
        "n": dict(total),
        "fpr_benign": rate(flagged, "benign"),
        "fpr_benign_sin_no_https": rate(flagged_no_http, "benign"),
        "alta_confianza": {
            "fpr_benignas_limpias": round(clean_fp / clean_benign, 4) if clean_benign else None,
            "recall_phishing_con_esquema": round(phish_scheme_hit / phish_scheme_total, 4) if phish_scheme_total else None,
            "auc": _auc(auc_y, auc_s),
            "n_benignas_limpias": clean_benign,
            "n_phishing_con_esquema": phish_scheme_total,
        },
        "fn_phishing_con_esquema_ejemplos": fn_examples,
        "fp_que_son_kits_phishing_mal_etiquetados": fp_label_noise,
        "fpr_benign_sin_no_https_ni_ruido": round((flagged_no_http["benign"] - fp_label_noise) / total["benign"], 4) if total["benign"] else None,
        "deteccion": {t: rate(flagged, t) for t in malicious},
        "deteccion_sin_no_https": {t: rate(flagged_no_http, t) for t in malicious},
        "deteccion_maliciosas_total_sin_no_https": round(sum(flagged_no_http[t] for t in malicious) / mal_total, 4) if mal_total else None,
        "tasa_factor_por_clase": {
            i: {t: rate(c, t) for t in LABELS} for i, c in sorted(factor_fire.items())
        },
        "factores_en_falsos_positivos": dict(fp_factor.most_common()),
        "ejemplos_falsos_positivos": fp_examples,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--download", action="store_true")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    if args.download or not DATA.exists():
        download()

    t0 = time.time()
    rows = load(args.limit, args.seed)
    results = {"dataset": DOWNLOAD_URL, "umbral_medio": heuristics.MEDIUM_THRESHOLD, "filas": len(rows)}
    for name, age in SCENARIOS.items():
        results[name] = evaluate(rows, age)
    results["segundos"] = round(time.time() - t0, 1)
    OUT.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")

    for name in SCENARIOS:
        r = results[name]
        print(f"[{name}] FPR benignas: {r['fpr_benign']:.2%} (sin no_https: {r['fpr_benign_sin_no_https']:.2%}; "
              f"descontando {r['fp_que_son_kits_phishing_mal_etiquetados']} kits mal etiquetados: {r['fpr_benign_sin_no_https_ni_ruido']:.2%}) | "
              f"detección sin no_https: " + ", ".join(f"{k}={v:.2%}" for k, v in r["deteccion_sin_no_https"].items()))
        a = r["alta_confianza"]
        print(f"    alta confianza -> FPR benignas limpias: {a['fpr_benignas_limpias']:.2%} | "
              f"recall phishing con esquema: {a['recall_phishing_con_esquema']:.2%} | AUC: {a['auc']}")
    print(f"Resultados en {OUT}")


if __name__ == "__main__":
    main()
