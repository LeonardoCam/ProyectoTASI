"""Motor heurístico determinista: puntaje de riesgo 0-100 con factores explicables."""
import ipaddress
import re
from dataclasses import dataclass, asdict
from typing import Optional
from urllib.parse import urlsplit

import tldextract

# Sin descargas de red: usa la lista de sufijos incluida en el paquete.
_extract = tldextract.TLDExtract(suffix_list_urls=())

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "bl.ink", "t.ly", "lnkd.in", "s.id",
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "country",
    "work", "support", "rest", "icu", "cam", "monster",
}
PHISHING_KEYWORDS = re.compile(
    r"(login|signin|verif|secure|account|update|banking|bcp|interbank|bbva|yape|plin|"
    r"sunat|reniec|password|clave|suspend|paypal|wallet)",
    re.IGNORECASE,
)

MEDIUM_THRESHOLD = 30
HIGH_THRESHOLD = 60


@dataclass
class Factor:
    id: str
    description: str
    points: int


def registrable_domain(host: str) -> str:
    """Dominio registrable (ej. 'a.b.example.co.uk' -> 'example.co.uk'); WHOIS se consulta con este."""
    ext = _extract(host)
    return ext.top_domain_under_public_suffix or host


def risk_level(score: int) -> str:
    if score >= HIGH_THRESHOLD:
        return "ALTO"
    if score >= MEDIUM_THRESHOLD:
        return "MEDIO"
    return "BAJO"


def evaluate(
    final_url: str,
    hops: int,
    domain_age_days: Optional[int],
    reputation_flagged: Optional[bool] = None,
) -> tuple[int, list[dict]]:
    """Devuelve (puntaje 0-100, factores). Todo factor que suma puntos queda justificado."""
    parts = urlsplit(final_url)
    host = (parts.hostname or "").lower()
    factors: list[Factor] = []

    def add(fid: str, desc: str, pts: int) -> None:
        factors.append(Factor(fid, desc, pts))

    # --- Reputación externa: coincidencia confirmada domina el resultado
    if reputation_flagged:
        add("reputation", "El destino figura en una base de datos de amenazas (Google Safe Browsing).", 70)

    # --- Antigüedad del dominio (OSINT/WHOIS)
    if domain_age_days is None:
        add("age_unknown", "No se pudo determinar la antigüedad del dominio (WHOIS protegido o no disponible).", 15)
    elif domain_age_days < 30:
        add("age_lt_30", f"Dominio muy reciente ({domain_age_days} días): patrón típico de campañas de fraude.", 40)
    elif domain_age_days < 180:
        add("age_lt_180", f"Dominio reciente ({domain_age_days} días).", 20)
    elif domain_age_days < 365:
        add("age_lt_365", f"Dominio con menos de un año ({domain_age_days} días).", 8)

    # --- Protocolo y red
    if parts.scheme != "https":
        add("no_https", "El destino final no usa HTTPS (comunicación sin cifrar).", 15)
    if hops >= 5:
        add("hops_many", f"Cadena de redirección larga ({hops} saltos).", 20)
    elif hops >= 3:
        add("hops_some", f"Varias redirecciones encadenadas ({hops} saltos).", 10)

    # --- Características léxicas de la URL
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    if is_ip:
        add("ip_host", "El destino usa una dirección IP en lugar de un nombre de dominio.", 25)
    else:
        if "xn--" in host:
            add("punycode", "El dominio usa punycode (posible suplantación con caracteres similares).", 15)
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS:
            add("bad_tld", f"Extensión de dominio con alta incidencia de abuso (.{tld}).", 10)
        ext = _extract(host)
        if ext.subdomain and ext.subdomain.count(".") >= 2:
            add("subdomains", "Muchos subdominios anidados, técnica común para imitar marcas.", 10)
        if registrable_domain(host) in SHORTENERS:
            add("nested_shortener", "El destino final es otro acortador de URL (encadenamiento para ocultar el destino).", 10)

    if "@" in final_url.split("?", 1)[0].split("//", 1)[-1]:
        add("at_sign", "La URL contiene '@', usado para disfrazar el dominio real.", 15)
    path_query = (parts.path or "") + "?" + (parts.query or "")
    if PHISHING_KEYWORDS.search(host + path_query):
        add("keywords", "La URL contiene palabras típicas de phishing (login, verificación, banca, etc.).", 10)

    score = min(sum(f.points for f in factors), 100)
    return score, [asdict(f) for f in factors]
