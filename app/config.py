"""Configuración centralizada (variables de entorno con valores seguros por defecto)."""
import os


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


MAX_REDIRECTS = _int("MAX_REDIRECTS", 10)          # saltos máximos antes de cortar la cadena
REQUEST_TIMEOUT = _int("REQUEST_TIMEOUT", 8)        # segundos por petición
TOTAL_TIMEOUT = _int("TOTAL_TIMEOUT", 20)           # segundos para toda la expansión
MAX_URL_LENGTH = _int("MAX_URL_LENGTH", 2048)
ALLOWED_PORTS = {80, 443}                           # SSRF: solo puertos web estándar

CACHE_TTL = _int("CACHE_TTL", 3600)                 # "memoria inteligente"
CACHE_MAX_ENTRIES = _int("CACHE_MAX_ENTRIES", 1000)

RATE_LIMIT_PER_MIN = _int("RATE_LIMIT_PER_MIN", 30)

ALLOWED_ORIGINS = [
    o.strip()
    for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:4200").split(",")
    if o.strip()
]

# Reputación externa (opcional). Sin clave, el factor se omite y se informa.
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "")

# User-Agent de navegador comercial estándar (mitigación de anti-bots, Cap. IV 4.3)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]
