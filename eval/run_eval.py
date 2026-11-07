"""Evalúa el pipeline real contra las metas del Cap. III. Uso: python -m eval.run_eval"""
import asyncio
import json
import statistics
import time
from pathlib import Path

import httpx
from sklearn.metrics import roc_auc_score

from app import api, heuristics, config
from eval.dataset import build
from eval.sim import World

OUT = Path(__file__).parent / "results.json"
THRESHOLD = heuristics.MEDIUM_THRESHOLD   # puntaje >= 30 => alerta (MEDIO o ALTO)


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(int(len(xs) * p), len(xs) - 1)]


async def main():
    world = World()
    restore = world.install()
    api.limiter.per_minute = 0   # sin límite durante la evaluación
    transport = httpx.ASGITransport(app=api.app)
    res = {}
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            # ---------- Detección + expansión
            cases = build()
            for k in cases:
                world.add_chain(k["urls"])
                world.ages[heuristics.registrable_domain(k["urls"][-1].split("/")[2])] = k["age"]
            world.delay = False
            scores, labels, ok, exact, lat_nocache = [], [], 0, 0, []
            rows = []
            for k in cases:
                api.cache.clear()
                t = time.perf_counter()
                r = await c.post("/api/v1/expand", json={"url": k["urls"][0]})
                lat_nocache.append((time.perf_counter() - t) * 1000)
                if r.status_code == 200:
                    j = r.json(); ok += 1
                    exact += j["final_url"] == k["urls"][-1]
                    scores.append(j["risk_score"]); labels.append(k["label"])
                    rows.append((k, j))
            tp = sum(1 for s, l in zip(scores, labels) if s >= THRESHOLD and l == 1)
            fn = sum(1 for s, l in zip(scores, labels) if s < THRESHOLD and l == 1)
            fp = sum(1 for s, l in zip(scores, labels) if s >= THRESHOLD and l == 0)
            tn = sum(1 for s, l in zip(scores, labels) if s < THRESHOLD and l == 0)
            rec, prec = tp / (tp + fn), tp / (tp + fp)
            res["deteccion"] = dict(umbral=THRESHOLD, n=len(labels), tp=tp, fn=fn, fp=fp, tn=tn,
                                    recall=rec, precision=prec, f1=2 * prec * rec / (prec + rec),
                                    fpr=fp / (fp + tn), auc=roc_auc_score(labels, scores))
            hard = [(k, j) for k, j in rows if k["hard"]]
            res["deteccion"]["casos_dificiles"] = dict(
                n=len(hard),
                errores=sum(1 for k, j in hard if (j["risk_score"] >= THRESHOLD) != bool(k["label"])))
            res["distribucion"] = {
                "legitimos": sorted(s for s, l in zip(scores, labels) if l == 0),
                "ataques": sorted(s for s, l in zip(scores, labels) if l == 1)}
            res["expansion"] = dict(tasa_exito=ok / len(cases), exactitud_destino=exact / ok)
            # enlaces muertos (inactivos): no cuentan para la tasa, deben fallar de forma controlada
            dead = await c.post("/api/v1/expand", json={"url": "https://bit.ly/muerto123"})
            res["expansion"]["enlace_muerto_status"] = dead.status_code

            # ---------- Bucles y cadenas excesivas
            loops = 0; total = 0
            for i in range(10):
                a, b = f"https://bit.ly/loop{i}a", f"https://bit.ly/loop{i}b"
                world.routes[a] = (302, b); world.routes[b] = (302, a)
                r = await c.post("/api/v1/expand", json={"url": a}); total += 1
                loops += r.status_code == 400 and r.json()["detail"]["code"] == "redirect_loop"
            for i in range(10):
                urls = [f"https://bit.ly/long{i}-{j}" for j in range(config.MAX_REDIRECTS + 6)]
                world.add_chain(urls)
                r = await c.post("/api/v1/expand", json={"url": urls[0]}); total += 1
                loops += r.status_code == 400 and r.json()["detail"]["code"] == "too_many_redirects"
            res["bucles"] = dict(casos=total, cortados=loops)

            # ---------- SSRF
            payloads = ["http://127.0.0.1/", "http://localhost/", "http://[::1]/", "http://10.0.0.1/",
                        "http://192.168.0.1/admin", "http://172.16.5.4/", "http://169.254.169.254/latest/meta-data/",
                        "http://2130706433/", "http://0177.0.0.1/", "http://0x7f.0.0.1/", "http://0.0.0.0/",
                        "http://100.64.0.1/", "http://[::ffff:127.0.0.1]/", "http://127.1/", "http://localhost:22/",
                        "http://127.0.0.1:6379/", "file:///etc/passwd", "ftp://internal.corp/", "gopher://127.0.0.1/",
                        "http://user:pw@127.0.0.1/", "http://internal.corp/"]
            for i in range(4):   # redirecciones desde un enlace público hacia la red interna
                src = f"https://bit.ly/ssrf{i}"
                world.routes[src] = (302, ["http://169.254.169.254/latest/", "http://127.0.0.1:8000/", "http://10.1.1.1/", "http://localhost/"][i])
                payloads.append(src)
            blocked = 0
            for p in payloads:
                r = await c.post("/api/v1/expand", json={"url": p})
                blocked += r.status_code == 400
            res["ssrf"] = dict(intentos=len(payloads), bloqueados=blocked)

            # ---------- Latencia con red simulada
            world.delay = True
            fresh = [k for k in cases if k["urls"][0]][:60]
            lat_n = []
            for k in fresh:
                api.cache.clear()
                t = time.perf_counter()
                await c.post("/api/v1/expand", json={"url": k["urls"][0]})
                lat_n.append((time.perf_counter() - t) * 1000)
            res["latencia_sin_cache_ms"] = dict(p50=pct(lat_n, .5), p95=pct(lat_n, .95))
            url = fresh[0]["urls"][0]
            api.cache.clear()
            await c.post("/api/v1/expand", json={"url": url})
            hits, lat_c = 0, []
            for _ in range(100):
                t = time.perf_counter()
                r = await c.post("/api/v1/expand", json={"url": url})
                lat_c.append((time.perf_counter() - t) * 1000)
                hits += r.json()["cached"]
            res["cache"] = dict(consultas=100, aciertos=hits, p95_ms=pct(lat_c, .95))

            # ---------- Carga: 20 usuarios concurrentes
            api.cache.clear()
            errs = 0; n = 0
            async def user(ix):
                nonlocal errs, n
                for k in cases[ix * 10:(ix + 1) * 10]:
                    r = await c.post("/api/v1/expand", json={"url": k["urls"][0]}); n += 1
                    errs += r.status_code >= 500
            await asyncio.gather(*(user(i) for i in range(20)))
            res["carga"] = dict(usuarios=20, peticiones=n, errores_5xx=errs)

            # ---------- Explicabilidad
            mh = [j for k, j in rows if j["risk_level"] in ("MEDIO", "ALTO")]
            res["explicabilidad"] = dict(medio_alto=len(mh), con_factor=sum(1 for j in mh if j["factors"]))
            # ejemplos para la presentación
            res["ejemplos"] = {
                "alto": max((j for k, j in rows if k["label"] == 1), key=lambda j: j["risk_score"]),
                "bajo": min((j for k, j in rows if k["label"] == 0), key=lambda j: j["risk_score"]),
            }
    finally:
        restore()
    OUT.write_text(json.dumps(res, indent=2, ensure_ascii=False))
    d = res["deteccion"]
    print(json.dumps({k: v for k, v in res.items() if k not in ("distribucion", "ejemplos")}, indent=2, ensure_ascii=False))


asyncio.run(main())
