"""Reputación externa opcional: Google Safe Browsing v4 (gratuita con clave de API)."""
from typing import Optional

import httpx

from . import config
from .net import SSL_CONTEXT

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


async def is_flagged(url: str, transport: Optional[httpx.AsyncBaseTransport] = None) -> Optional[bool]:
    """True/False si hay veredicto; None si el servicio no está configurado o falla."""
    if not config.SAFE_BROWSING_API_KEY:
        return None
    body = {
        "client": {"clientId": "proyecto-tasi", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=5, transport=transport, verify=SSL_CONTEXT) as client:
            r = await client.post(ENDPOINT, params={"key": config.SAFE_BROWSING_API_KEY}, json=body)
            r.raise_for_status()
            return bool(r.json().get("matches"))
    except Exception:
        return None
