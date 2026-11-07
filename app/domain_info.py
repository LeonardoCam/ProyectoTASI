"""Consulta WHOIS (OSINT básico) con caché propia para no saturar a los servidores WHOIS."""
import asyncio
import datetime
from typing import Optional

import whois

from . import config
from .cache import TTLCache

_whois_cache = TTLCache(ttl=config.CACHE_TTL * 6)


def _fetch(domain: str):
    return whois.whois(domain)


async def domain_age_days(domain: str) -> Optional[int]:
    """Días desde la creación del dominio, o None si WHOIS no entrega el dato."""
    cached = _whois_cache.get(domain)
    if cached is not None:
        return cached[0]

    age: Optional[int] = None
    try:
        info = await asyncio.wait_for(asyncio.to_thread(_fetch, domain), timeout=8)
        created = info.creation_date
        if isinstance(created, list):
            created = min((c for c in created if c), default=None)
        if isinstance(created, datetime.datetime):
            now = datetime.datetime.now(created.tzinfo) if created.tzinfo else datetime.datetime.now()
            age = max((now - created).days, 0)
    except Exception:
        age = None

    _whois_cache.set(domain, (age,))  # se guarda también el "None" para no reintentar
    return age
