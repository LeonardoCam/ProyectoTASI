import asyncio
import time
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from . import config, domain_info, heuristics, reputation, resolver
from .cache import TTLCache
from .ratelimit import RateLimiter
from .security import UnsafeURLError, assert_safe_url

app = FastAPI(
    title="Motor de Expansión de URLs y Heurística",
    description="Expande URLs acortadas de forma asíncrona y segura y evalúa el riesgo del destino (0-100).",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

cache = TTLCache()
limiter = RateLimiter(config.RATE_LIMIT_PER_MIN)


class URLRequest(BaseModel):
    url: str = Field(..., max_length=config.MAX_URL_LENGTH)


def _cache_key(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{(parts.hostname or '').lower()}{parts.path}?{parts.query}"


@app.get("/api/v1/health")
async def health():
    return {"status": "ok", "cache_entries": len(cache), "cache_hits": cache.hits, "cache_misses": cache.misses}


@app.post("/api/v1/expand")
async def expand_url(req: URLRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not limiter.allow(client_ip):
        raise HTTPException(status_code=429, detail="Demasiadas solicitudes. Intenta de nuevo en un minuto.")

    started = time.perf_counter()
    url = req.url.strip()

    key = _cache_key(url)
    cached = cache.get(key)
    if cached is not None:
        return {**cached, "cached": True, "elapsed_ms": round((time.perf_counter() - started) * 1000)}

    try:
        await assert_safe_url(url)
        exp = await asyncio.wait_for(resolver.expand(url), timeout=config.TOTAL_TIMEOUT)
    except UnsafeURLError as e:
        raise HTTPException(status_code=400, detail={"code": e.code, "message": e.message})
    except resolver.RedirectLoopError as e:
        raise HTTPException(status_code=400, detail={"code": "redirect_loop", "message": str(e)})
    except resolver.TooManyRedirectsError as e:
        raise HTTPException(status_code=400, detail={"code": "too_many_redirects", "message": str(e)})
    except (resolver.UpstreamError, asyncio.TimeoutError) as e:
        msg = str(e) or "Tiempo de espera agotado al resolver el enlace."
        raise HTTPException(status_code=504, detail={"code": "upstream_error", "message": msg})

    host = (urlsplit(exp.final_url).hostname or "").lower()
    domain = heuristics.registrable_domain(host)

    age, flagged = await asyncio.gather(
        domain_info.domain_age_days(domain),
        reputation.is_flagged(exp.final_url),
    )
    score, factors = heuristics.evaluate(exp.final_url, exp.hops, age, flagged)

    result = {
        "original_url": url,
        "final_url": exp.final_url,
        "redirect_chain": exp.chain,
        "hops": exp.hops,
        "https": exp.final_url.startswith("https://"),
        "domain": host,
        "registered_domain": domain,
        "domain_age_days": age,
        "reputation_checked": flagged is not None,
        "risk_score": score,
        "risk_level": heuristics.risk_level(score),
        "factors": factors,
    }
    cache.set(key, result)
    return {**result, "cached": False, "elapsed_ms": round((time.perf_counter() - started) * 1000)}
