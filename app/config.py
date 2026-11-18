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
WHOIS_TIMEOUT = _int("WHOIS_TIMEOUT", 5)            # segundos por consulta WHOIS
REQUEST_DEADLINE = _int("REQUEST_DEADLINE", 40)     # tope absoluto de una petición /expand
MAX_URL_LENGTH = _int("MAX_URL_LENGTH", 2048)
ALLOWED_PORTS = {80, 443}                           # SSRF: solo puertos web estándar

# DNS: DNS-over-HTTPS público (Cloudflare/Google) con respaldo en el DNS del sistema.
DNS_USE_DOH = os.getenv("DNS_USE_DOH", "1") != "0"
DNS_TIMEOUT = _int("DNS_TIMEOUT", 4)

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

# Inteligencia de amenazas (app/threat_intel.py): listas públicas de malware/phishing + VirusTotal.
THREAT_FEEDS_ENABLED = os.getenv("THREAT_FEEDS_ENABLED", "1") != "0"
THREAT_FEEDS_REFRESH_HOURS = _int("THREAT_FEEDS_REFRESH_HOURS", 6)
THREAT_FEEDS_DIR = os.getenv("THREAT_FEEDS_DIR", os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "threat_feeds"))
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# User-Agent de navegador comercial estándar (mitigación de anti-bots, Cap. IV 4.3)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]
