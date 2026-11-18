"""Consulta WHOIS (OSINT básico) con caché propia para no saturar a los servidores WHOIS.

La respuesta se DESCARGA con `python-whois` (sabe qué servidor consultar para cada extensión y
sigue las referencias), pero la fecha de creación se EXTRAE con un lector propio: el intérprete
de la librería tiene expresiones regulares con retroceso catastrófico (la respuesta de 1,3 KB de
`trilltrill.jp` tardaba 91 s de CPU) y, como `re` no libera el GIL, congelaba todo el servidor.
El lector propio recorre línea a línea con patrones anclados y sin retroceso.

Nota: algunos registros no publican la fecha (p. ej. NIC.PE para .pe, DENIC para .de); en ese
caso se devuelve None y el motor lo trata como "antigüedad desconocida".
"""
import asyncio
import datetime
import logging
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from whois.whois import NICClient

from . import config
from .cache import TTLCache
from .net import SSL_CONTEXT

_whois_cache = TTLCache(ttl=config.CACHE_TTL * 6)

# WHOIS usa sockets bloqueantes y puede saltar entre varios servidores (referrals): un hilo puede
# quedar ocupado bastante después de que el análisis dejó de esperarlo. Con su propio grupo de
# hilos no agota el grupo compartido, que también usa la resolución DNS del sistema.
_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="whois")
logging.getLogger("whois.whois").setLevel(logging.CRITICAL)   # errores de socket esperables

# Claves (normalizadas) que indican la fecha de creación en los distintos registros.
CREATION_KEYS = {
    "creation date", "created", "created on", "created date", "created at", "creation_date",
    "registered on", "registered", "registered date", "registration date", "registration time",
    "domain registration date", "domain create date", "domain created", "record created",
    "commencement date", "domain name commencement date", "domain record activated",
    "first registration date", "fecha de registro", "fecha de creacion", "fecha de creación",
    "登録年月日",
}
_MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}
_ISO = re.compile(r"(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})")          # 2004-10-24, 2014/05/27
_COMPACT = re.compile(r"(\d{4})(\d{2})(\d{2})(?!\d)")               # 19970711
_DMY_NAME = re.compile(r"(\d{1,2})[-/. ]([a-z]{3})[a-z]*[-/. ](\d{4})", re.IGNORECASE)  # 22-Oct-1997
_DMY = re.compile(r"(\d{1,2})[./-](\d{1,2})[./-](\d{4})")           # 24.10.2004
_BEFORE = re.compile(r"before ([a-z]{3})[a-z]*[-/. ](\d{4})", re.IGNORECASE)  # before Aug-1996 (.uk)
_MAX_LINES, _MAX_LINE = 600, 300


def _parse_date(value: str) -> Optional[datetime.date]:
    value = value.strip()[:60]
    candidates = []
    if m := _ISO.match(value):
        candidates.append((int(m[1]), int(m[2]), int(m[3])))
    elif m := _COMPACT.match(value):
        candidates.append((int(m[1]), int(m[2]), int(m[3])))
    elif m := _DMY_NAME.match(value):
        if m[2].lower() in _MONTHS:
            candidates.append((int(m[3]), _MONTHS[m[2].lower()], int(m[1])))
    elif m := _DMY.match(value):
        candidates.append((int(m[3]), int(m[2]), int(m[1])))
    elif m := _BEFORE.match(value):
        if m[1].lower() in _MONTHS:
            candidates.append((int(m[2]), _MONTHS[m[1].lower()], 1))
    for y, mo, d in candidates:
        try:
            date = datetime.date(y, mo, d)
        except ValueError:
            continue
        if 1985 <= date.year and date <= datetime.date.today():
            return date
    return None


def creation_date(text: str) -> Optional[datetime.date]:
    """Fecha de creación más antigua que aparezca en una respuesta WHOIS cruda."""
    found = []
    for raw in text.splitlines()[:_MAX_LINES]:
        line = raw.strip()[:_MAX_LINE]
        if not line or line[0] in "%#>":
            continue
        if line.startswith("[") and "]" in line:          # formato JPRS: "[Created on]  2014/05/27"
            key, _, value = line[1:].partition("]")
        elif ":" in line:
            key, _, value = line.partition(":")
        else:
            continue
        key = " ".join(key.lower().split())
        if key in CREATION_KEYS:
            date = _parse_date(value)
            if date:
                found.append(date)
    return min(found) if found else None


def _fetch(domain: str) -> str:
    return NICClient().whois_lookup(None, domain, 0, quiet=True, timeout=config.WHOIS_TIMEOUT)


async def domain_age_days(domain: str) -> Optional[int]:
    """Días desde la creación del dominio, o None si WHOIS no entrega el dato."""
    cached = _whois_cache.get(domain)
    if cached is not None:
        return cached[0]

    age: Optional[int] = None
    try:
        loop = asyncio.get_running_loop()
        text = await asyncio.wait_for(loop.run_in_executor(_executor, _fetch, domain),
                                      timeout=config.WHOIS_TIMEOUT + 1)
        created = creation_date(text or "")
        if created:
            age = max((datetime.date.today() - created).days, 0)
    except Exception:
        age = None

    _whois_cache.set(domain, (age,))  # se guarda también el "None" para no reintentar
    return age


_cert_cache = TTLCache(ttl=config.CACHE_TTL * 6)


def _fetch_cert_age(hostname: str, port: int = 443) -> Optional[int]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(min(config.DNS_TIMEOUT, 3.0))
        conn = SSL_CONTEXT.wrap_socket(sock, server_hostname=hostname)
        conn.connect((hostname, port))
        cert = conn.getpeercert()
        conn.close()
        if not cert:
            return None
        not_before = cert.get("notBefore")
        if not_before:
            issued = datetime.datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z").date()
            return max((datetime.date.today() - issued).days, 0)
    except Exception:
        pass
    return None


async def cert_age_days(hostname: str, port: int = 443) -> Optional[int]:
    """Días desde la emisión del certificado TLS/SSL, o None si no se pudo determinar."""
    cached = _cert_cache.get(f"{hostname}:{port}")
    if cached is not None:
        return cached[0]

    age: Optional[int] = None
    try:
        loop = asyncio.get_running_loop()
        age = await asyncio.wait_for(
            loop.run_in_executor(_executor, _fetch_cert_age, hostname, port),
            timeout=min(config.DNS_TIMEOUT, 3.0) + 1,
        )
    except Exception:
        age = None

    _cert_cache.set(f"{hostname}:{port}", (age,))
    return age
