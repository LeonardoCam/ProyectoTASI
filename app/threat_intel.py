"""Inteligencia de amenazas: listas públicas de malware/phishing + VirusTotal (opcional).

La forma de una URL casi nunca delata a un sitio que distribuye malware: hay que preguntar a
fuentes que lo hayan visto. Se usan listas públicas, gratuitas y sin registro, elegidas porque
NO contienen sitios populares (verificado contra el ranking Tranco top 10k):

  - URLhaus (abuse.ch) vía malware-filter: dominios que distribuyen malware.
  - blackbook (stamparm/maltrail): dominios de malware y servidores de control (C2).
  - phishing-filter (malware-filter: OpenPhish + PhishTank + PhishStats): dominios de phishing.
  - OpenPhish (feed público): URLs de phishing activas.

Se descartó Phishing.Database porque lista dominios legítimos (gravatar.com, mercadolibre.com.ar).

Las listas se descargan al iniciar la API y se refrescan cada THREAT_FEEDS_REFRESH_HOURS; se
guardan en disco para que un reinicio sin red siga funcionando. Se comparan por host EXACTO o
dominio padre listado: "a.duckdns.org" listado no marca "b.duckdns.org".

VirusTotal (https://www.virustotal.com) se consulta solo si existe VIRUSTOTAL_API_KEY (la clave
gratuita permite 4 consultas/min y 500/día; los resultados se guardan en caché).
"""
import asyncio
import base64
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlsplit

import httpx

from . import config
from .net import SSL_CONTEXT
from .cache import TTLCache

log = logging.getLogger("threat_intel")


@dataclass(frozen=True)
class Feed:
    name: str
    url: str
    kind: str        # "domain" (un host por línea) o "url" (URL completa por línea)
    category: str    # "malware" o "phishing"
    homepage: str


FEEDS = (
    Feed("URLhaus", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt",
         "domain", "malware", "https://urlhaus.abuse.ch"),
    Feed("blackbook", "https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt",
         "domain", "malware", "https://github.com/stamparm/blackbook"),
    Feed("phishing-filter", "https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt",
         "domain", "phishing", "https://gitlab.com/malware-filter/phishing-filter"),
    Feed("OpenPhish", "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
         "url", "phishing", "https://openphish.com"),
)


@dataclass(frozen=True)
class Match:
    source: str
    category: str
    matched: str


def _norm_url(url: str) -> str:
    try:
        p = urlsplit(url.strip())
    except ValueError:
        return url.strip().lower()
    host = (p.hostname or "").lower()
    path = p.path.rstrip("/")
    return f"{host}{path}" + (f"?{p.query}" if p.query else "")


def _parse(feed: Feed, text: str) -> set[str]:
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#!":
            continue
        if feed.kind == "domain":
            if " " in line:                     # formato hosts: "0.0.0.0 dominio"
                line = line.split()[-1]
            line = line.lower().lstrip("|").rstrip("^").strip(".")
            if line and "." in line:
                out.add(line)
        else:
            out.add(_norm_url(line))
    return out


class ThreatIntel:
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.domains: dict[str, set[str]] = {}   # nombre de lista -> hosts
        self.urls: dict[str, set[str]] = {}      # nombre de lista -> URLs normalizadas
        self.loaded_at: dict[str, float] = {}
        self._lock = asyncio.Lock()
        self._signature: dict[str, int] = {}   # huella del contenido de cada lista
        # Funciones a llamar cuando alguna lista cambia (p. ej. vaciar la caché de resultados).
        self.on_update: list[Callable[[list[str]], None]] = []

    # --- carga -------------------------------------------------------------------------
    def _store(self, feed: Feed, text: str) -> bool:
        """Carga la lista; devuelve True si su contenido cambió respecto a lo que había."""
        entries = _parse(feed, text)
        (self.domains if feed.kind == "domain" else self.urls)[feed.name] = entries
        self.loaded_at[feed.name] = time.time()
        signature = hash(frozenset(entries))
        changed = self._signature.get(feed.name) not in (None, signature)
        self._signature[feed.name] = signature
        return changed

    def load_from_disk(self) -> None:
        for feed in FEEDS:
            path = self.cache_dir / f"{feed.name}.txt"
            if path.exists() and feed.name not in self.loaded_at:
                self._store(feed, path.read_text(encoding="utf-8", errors="replace"))
                self.loaded_at[feed.name] = path.stat().st_mtime

    async def refresh(self, transport: Optional[httpx.AsyncBaseTransport] = None) -> None:
        """Descarga todas las listas; si una falla se conserva la copia en disco."""
        async with self._lock:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            changed: list[str] = []
            async with httpx.AsyncClient(timeout=60, follow_redirects=True, transport=transport, verify=SSL_CONTEXT) as client:
                async def one(feed: Feed):
                    try:
                        r = await client.get(feed.url)
                        r.raise_for_status()
                        (self.cache_dir / f"{feed.name}.txt").write_text(r.text, encoding="utf-8")
                        if self._store(feed, r.text):
                            changed.append(feed.name)
                    except Exception as e:  # red caída, 404...: seguir con lo que haya en disco
                        log.warning("No se pudo actualizar la lista %s: %s", feed.name, e)
                await asyncio.gather(*(one(f) for f in FEEDS))
            self.load_from_disk()
            if changed:
                log.info("Listas de amenazas actualizadas: %s", ", ".join(changed))
                for callback in self.on_update:
                    callback(changed)

    async def run_forever(self) -> None:
        self.load_from_disk()
        while True:
            await self.refresh()
            await asyncio.sleep(config.THREAT_FEEDS_REFRESH_HOURS * 3600)

    # --- consulta ----------------------------------------------------------------------
    def lookup(self, url: str) -> list[Match]:
        """Listas en las que figura la URL (por URL exacta, host o dominio padre listado)."""
        try:
            host = (urlsplit(url).hostname or "").lower().strip(".")
        except ValueError:
            return []
        if not host:
            return []
        labels = host.split(".")
        candidates = [".".join(labels[i:]) for i in range(len(labels) - 1)]  # a.b.c.com, b.c.com, c.com
        found: list[Match] = []
        for feed in FEEDS:
            if feed.kind == "domain":
                entries = self.domains.get(feed.name, ())
                hit = next((c for c in candidates if c in entries), None)
                if hit:
                    found.append(Match(feed.name, feed.category, hit))
            else:
                norm = _norm_url(url)
                if norm in self.urls.get(feed.name, ()):
                    found.append(Match(feed.name, feed.category, norm))
        return found

    def status(self) -> dict:
        return {
            f.name: {
                "categoria": f.category,
                "entradas": len((self.domains if f.kind == "domain" else self.urls).get(f.name, ())),
                "actualizada": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.loaded_at[f.name]))
                if f.name in self.loaded_at else None,
            }
            for f in FEEDS
        }


intel = ThreatIntel(Path(config.THREAT_FEEDS_DIR))

# --- VirusTotal ----------------------------------------------------------------------------
VT_ENDPOINT = "https://www.virustotal.com/api/v3/urls/"
_vt_cache = TTLCache(ttl=6 * 3600)


@dataclass(frozen=True)
class VTResult:
    malicious: int
    suspicious: int
    engines: int
    permalink: str


async def virustotal(url: str, transport: Optional[httpx.AsyncBaseTransport] = None) -> Optional[VTResult]:
    """Último análisis de VirusTotal para la URL; None si no hay clave, no existe o falla."""
    if not config.VIRUSTOTAL_API_KEY:
        return None
    cached = _vt_cache.get(url)
    if cached is not None:
        return cached[0]
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    result: Optional[VTResult] = None
    try:
        async with httpx.AsyncClient(timeout=8, transport=transport, verify=SSL_CONTEXT) as client:
            r = await client.get(VT_ENDPOINT + url_id, headers={"x-apikey": config.VIRUSTOTAL_API_KEY})
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            result = VTResult(
                malicious=int(stats.get("malicious", 0)),
                suspicious=int(stats.get("suspicious", 0)),
                engines=sum(int(v) for v in stats.values()),
                permalink=f"https://www.virustotal.com/gui/url/{url_id}",
            )
    except Exception as e:
        log.warning("VirusTotal no respondió: %s", e)
        return None  # no se cachea el error: se reintentará
    _vt_cache.set(url, (result,))
    return result
