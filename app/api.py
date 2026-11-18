import asyncio
import logging
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from contextlib import asynccontextmanager
from typing import Optional

from . import config, domain_info, heuristics, ml_model, reputation, resolver, threat_intel
from .cache import TTLCache
from .normalize import normalize_url
from .ratelimit import RateLimiter
from .security import UnsafeURLError, assert_safe_url


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Las listas de amenazas se descargan en segundo plano: la API arranca al instante y usa la
    # copia en disco hasta que termine la primera actualización.
    task = None
    if not logging.getLogger().handlers:  # uvicorn solo configura sus propios loggers
        logging.basicConfig(level=logging.INFO, format="%(levelname)s:     [%(name)s] %(message)s")
        logging.getLogger("httpx").setLevel(logging.WARNING)   # no registrar cada petición interna
    if _on_feeds_updated not in threat_intel.intel.on_update:
        threat_intel.intel.on_update.append(_on_feeds_updated)
    if config.THREAT_FEEDS_ENABLED:
        threat_intel.intel.load_from_disk()
        task = asyncio.create_task(threat_intel.intel.run_forever())
    yield
    if task:
        task.cancel()


app = FastAPI(
    title="Motor de Expansión de URLs y Heurística",
    description="Expande URLs acortadas de forma asíncrona y segura y evalúa el riesgo del destino (0-100).",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

cache = TTLCache()
limiter = RateLimiter(config.RATE_LIMIT_PER_MIN)
log = logging.getLogger("api")


def _on_feeds_updated(changed: list[str]) -> None:
    """Las listas de amenazas trajeron datos nuevos: los resultados guardados pueden haber quedado
    desactualizados (un enlace "BAJO" que ahora figura como malware), así que se descartan."""
    n = len(cache)
    cache.clear()
    log.info("Caché vaciada (%d resultados) porque se actualizaron: %s", n, ", ".join(changed))


class URLRequest(BaseModel):
    url: str = Field(..., max_length=config.MAX_URL_LENGTH)


class FeedbackRequest(BaseModel):
    url: str
    feedback_type: str = Field(..., description="'ok' para veredicto acertado, 'fp' para falso positivo")
    comment: Optional[str] = None


_feedback_log: list[dict] = []


@app.post("/api/v1/feedback")
async def submit_feedback(fb: FeedbackRequest):
    entry = {
        "url": fb.url,
        "type": fb.feedback_type,
        "comment": fb.comment,
        "received_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    _feedback_log.append(entry)
    if len(_feedback_log) > 200:
        _feedback_log.pop(0)
    return {"status": "ok", "message": "Gracias por tu reporte. Se ha registrado para auditoría y mejora continua."}


def _toggle_www(url: str) -> str:
    parts = urlsplit(url)
    host = parts.hostname or ""
    new_host = host[4:] if host.startswith("www.") else "www." + host
    netloc = new_host + (f":{parts.port}" if parts.port else "")
    return parts._replace(netloc=netloc).geturl()


def _cache_key(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{(parts.hostname or '').lower()}{parts.path}?{parts.query}"


@app.get("/api/v1/health")
async def health():
    return {
        "status": "ok", "cache_entries": len(cache), "cache_hits": cache.hits, "cache_misses": cache.misses,
        "cache_ttl_s": cache.ttl,
        "threat_feeds": threat_intel.intel.status(), "virustotal_enabled": bool(config.VIRUSTOTAL_API_KEY),
    }


@app.post("/api/v1/expand")
async def expand_url(req: URLRequest, request: Request):
    # Red de seguridad: cada fase tiene su propio límite, pero ninguna petición debe quedar colgada.
    try:
        return await asyncio.wait_for(_expand(req, request), timeout=config.REQUEST_DEADLINE)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail={
            "code": "timeout", "message": "El análisis tardó demasiado. Inténtalo de nuevo en unos segundos."})


async def _expand(req: URLRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not limiter.allow(client_ip):
        raise HTTPException(status_code=429, detail="Demasiadas solicitudes. Intenta de nuevo en un minuto.")

    started = time.perf_counter()
    url, scheme_added = normalize_url(req.url)

    key = _cache_key(url)
    cached = cache.get(key)
    if cached is not None and not cached["threat_intel"]["matches"] and any(
            threat_intel.intel.lookup(u) for u in cached["redirect_chain"]):
        cache.delete(key)   # guardado como limpio pero ahora figura en una lista: se vuelve a analizar
        cached = None
    if cached is not None:
        return {**cached, "input_url": req.url.strip(), "cached": True,
                "cache_expires_in_s": round(cache.remaining(key) or 0),
                "elapsed_ms": round((time.perf_counter() - started) * 1000)}

    dns_note = None

    async def _resolve_with_fallback():
        nonlocal url, dns_note
        try:
            await assert_safe_url(url)
        except UnsafeURLError as e:
            if e.code != "domain_not_found":
                raise
            # Muchos sitios existen solo con o solo sin "www" (sunat.gob.pe vs www.sunat.gob.pe).
            alt = _toggle_www(url)
            try:
                await assert_safe_url(alt)
            except UnsafeURLError:
                raise e
            dns_note = (f"{urlsplit(url).hostname} no tiene registros DNS; "
                        f"se analizó {urlsplit(alt).hostname}.")
            url = alt
        try:
            return await resolver.expand(url)
        except resolver.UpstreamError as e:
            # Reintentar por http solo si https fue RECHAZADO (sitios sin TLS); si no contestó,
            # por http tampoco lo hará y se duplicaría la espera.
            if not scheme_added or isinstance(e, resolver.UpstreamTimeout):
                raise
            # Sin esquema y el sitio no responde por HTTPS: reintentar por HTTP.
            url = "http://" + url[len("https://"):]
            await assert_safe_url(url)
            return await resolver.expand(url)

    async def _assess(final_url: str, chain: list[str], hops: int, visited: bool, matches, vt=None,
                      not_found: bool = False, reachable: bool = True,
                      redirect_problem: Optional[str] = None,
                      page_title: Optional[str] = None,
                      security_headers: Optional[dict] = None,
                      content_disposition: Optional[str] = None) -> dict:
        host = (urlsplit(final_url).hostname or "").lower()
        domain = heuristics.registrable_domain(host)
        tasks = [domain_info.domain_age_days(domain), reputation.is_flagged(final_url)]
        if vt is None:
            tasks.append(threat_intel.virustotal(final_url))
        if final_url.startswith("https://"):
            tasks.append(domain_info.cert_age_days(host))
        results = await asyncio.gather(*tasks)
        age, flagged = results[0], results[1]
        idx = 2
        if vt is None:
            vt = results[idx]
            idx += 1
        cert_age = results[idx] if len(results) > idx else None

        ml_eval = ml_model.evaluate_ml(final_url)
        score, factors = heuristics.evaluate(
            final_url, hops, age, flagged, matches, vt, domain_not_found=not_found,
            redirect_problem=redirect_problem, cert_age_days=cert_age,
            page_title=page_title, security_headers=security_headers,
            content_disposition=content_disposition,
            ml_result=ml_eval,
        )
        result = {
            "input_url": req.url.strip(),
            "original_url": url,
            "final_url": final_url,
            "redirect_chain": chain,
            "hops": hops,
            "https": final_url.startswith("https://"),
            "domain": host,
            "registered_domain": domain,
            "domain_age_days": age,
            "cert_age_days": cert_age,
            "page_title": page_title,
            "security_headers": security_headers or {},
            "domain_exists": not not_found,
            "reachable": reachable and not not_found,
            "dns_note": dns_note,
            "reputation_checked": flagged is not None,
            "threat_intel": {
                "destination_visited": visited,
                "lists_loaded": sum(1 for s in threat_intel.intel.status().values() if s["entradas"]),
                "matches": [{"source": m.source, "category": m.category, "matched": m.matched} for m in matches],
                "virustotal": None if vt is None else {
                    "malicious": vt.malicious, "suspicious": vt.suspicious, "engines": vt.engines, "link": vt.permalink,
                },
            },
            "ml_analysis": {
                "available": ml_eval.get("available", False),
                "probability": ml_eval.get("probability"),
                "risk_score": ml_eval.get("risk_score"),
                "risk_level": ml_eval.get("risk_level"),
                "calibrated_grey_zone": any(f.get("id") in ("ml_lexical_risk", "ml_lexical_benign") for f in factors),
            },
            "risk_score": score,
            "risk_level": heuristics.risk_level(score),
            "factors": factors,
            "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        cache.set(key, result)
        return {**result, "cached": False, "cache_expires_in_s": cache.ttl,
                "elapsed_ms": round((time.perf_counter() - started) * 1000)}

    # 1) Antes de conectar (y antes del DNS, porque muchos dominios de malware ya no resuelven):
    #    si la URL está reportada como malware/phishing, NO se visita. La consulta es local.
    pre_matches = threat_intel.intel.lookup(url)  # [] si no hay host (javascript:, URL malformada...)
    if pre_matches:
        return await _assess(url, [url], 0, False, pre_matches)

    # 2) Expandir la cadena de redirecciones (cada salto validado contra SSRF).
    try:
        exp = await asyncio.wait_for(_resolve_with_fallback(), timeout=config.TOTAL_TIMEOUT)
    except UnsafeURLError as e:
        if e.code == "domain_not_found":
            # El dominio no existe (típico de phishing dado de baja): no hay nada que visitar, pero
            # la URL, las listas de amenazas, VirusTotal y WHOIS sí se pueden evaluar.
            dns_note = dns_note or e.message
            return await _assess(url, [url], 0, False, threat_intel.intel.lookup(url), not_found=True)
        raise HTTPException(status_code=400, detail={"code": e.code, "message": e.message})
    except (resolver.RedirectLoopError, resolver.TooManyRedirectsError) as e:
        # Un bucle o una cadena interminable ya es una señal de riesgo: se evalúa en vez de fallar.
        dns_note = f"{e} Se evaluó sin llegar a un destino final."
        loop = isinstance(e, resolver.RedirectLoopError)
        return await _assess(url, [url], 0, False, threat_intel.intel.lookup(url), reachable=False,
                             redirect_problem="loop" if loop else "too_many")
    except (resolver.UpstreamError, asyncio.TimeoutError) as e:
        # El sitio existe pero no respondió (caído, bloqueado por la red, certificado inválido...).
        # Los sitios de malware suelen caerse o bloquear: se evalúa igual con lo que no requiere
        # visitarlo (forma de la URL, listas de amenazas, VirusTotal, WHOIS).
        reason = str(e) or "Tiempo de espera agotado al resolver el enlace."
        dns_note = f"El sitio no respondió ({reason.rstrip('.').lower()}); se evaluó sin visitarlo."
        return await _assess(url, [url], 0, False, threat_intel.intel.lookup(url), reachable=False)

    # 3) Cualquier salto de la cadena reportado cuenta (un acortador limpio que lleva a malware).
    matches, seen = [], set()
    for hop in exp.chain:
        for m in threat_intel.intel.lookup(hop):
            if (m.source, m.matched) not in seen:
                seen.add((m.source, m.matched))
                matches.append(m)
    return await _assess(
        exp.final_url, exp.chain, exp.hops, True, matches,
        page_title=exp.title, security_headers=exp.security_headers,
        content_disposition=exp.content_disposition,
    )
