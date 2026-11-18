"""Módulo de reputación y lista de confianza Tranco (Top Dominios).

Permite mitigar falsos positivos reduciendo puntos de riesgo para dominios de
alta reputación, amplia trayectoria y gran volumen de tráfico legítimo.
"""
from pathlib import Path
from typing import Set

# Conjunto optimizado de dominios consolidados (Top global de Tranco + top Perú/LatAm)
_DEFAULT_TRANCO_TOP: Set[str] = {
    # Motores de búsqueda, portales y nubes principales
    "google.com", "google.com.pe", "google.es", "google.com.mx", "google.com.br",
    "googleapis.com", "gstatic.com", "googleusercontent.com", "googlevideo.com",
    "youtube.com", "youtu.be", "microsoft.com", "live.com", "office.com", "office365.com",
    "microsoftonline.com", "msn.com", "bing.com", "azure.com", "windows.net",
    "apple.com", "icloud.com", "apple-dns.net", "mzstatic.com",
    "amazon.com", "amazon.es", "amazon.com.mx", "amazon.com.br", "amazonaws.com",
    "cloudflare.com", "cloudflare-dns.com", "akamai.net", "akamaized.net", "fastly.net",
    "github.com", "github.io", "githubassets.com", "gitlab.com", "bitbucket.org",
    "stackoverflow.com", "stackexchange.com", "npmjs.com", "python.org", "pypi.org",
    "docker.com", "wikipedia.org", "wikimedia.org", "w3.org", "mozilla.org", "ietf.org",
    "apache.org", "kernel.org", "archive.org", "openai.com", "anthropic.com",
    "zoom.us", "slack.com", "discord.com", "telegram.org",

    # Redes sociales, streaming y comunicación
    "facebook.com", "fb.com", "facebook.net", "fbcdn.net", "instagram.com", "cdninstagram.com",
    "whatsapp.com", "whatsapp.net", "wa.me", "linkedin.com", "licdn.com", "lnkd.in",
    "twitter.com", "x.com", "t.co", "twimg.com", "reddit.com", "redd.it", "pinterest.com",
    "tiktok.com", "byteoversea.com", "spotify.com", "spotifycdn.com", "netflix.com",
    "nflxext.com", "nflxvideo.net", "twitch.tv", "medium.com", "quora.com", "tumblr.com",
    "vimeo.com", "flickr.com",

    # Productividad, SaaS, diseño y comercio electrónico
    "canva.com", "notion.so", "notion.site", "trello.com", "atlassian.net", "atlassian.com",
    "figma.com", "dropbox.com", "dropboxusercontent.com", "box.com", "adobe.com",
    "salesforce.com", "shopify.com", "hubspot.com", "mailchimp.com", "sendgrid.com",
    "zendesk.com", "stripe.com", "paypal.com", "paypalobjects.com", "paypal.me",
    "ebay.com", "aliexpress.com", "mercadolibre.com", "mercadolibre.com.pe",
    "steampowered.com", "steamcommunity.com", "epicgames.com", "playstation.com",

    # Infraestructura, bases de datos y sistemas
    "oracle.com", "ibm.com", "intel.com", "cisco.com", "vmware.com", "redhat.com",
    "ubuntu.com", "debian.org", "kali.org", "mongodb.com", "postgresql.org", "mysql.com",
    "redis.io", "elastic.co",

    # Medios internacionales
    "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com", "theguardian.com", "reuters.com",
    "bloomberg.com", "forbes.com", "wsj.com",

    # PaaS, CDNs y hosting de desarrollo (sitios institucionales de la plataforma)
    "vercel.com", "netlify.com", "herokuapp.com", "digitalocean.com", "linode.com",

    # Perú: Universidades y sector educativo
    "upch.edu.pe", "pucp.edu.pe", "unmsm.edu.pe", "uni.edu.pe", "ulima.edu.pe", "utec.edu.pe",
    "usmp.edu.pe", "ucv.edu.pe", "urp.edu.pe", "continental.edu.pe", "upn.edu.pe", "esan.edu.pe",
    "up.edu.pe", "ucsp.edu.pe", "udep.edu.pe", "cientifica.edu.pe", "sise.edu.pe",

    # Perú: Entidades gubernamentales y del estado
    "gob.pe", "sunat.gob.pe", "reniec.gob.pe", "bn.com.pe", "indecopi.gob.pe", "onpe.gob.pe",
    "jne.gob.pe", "osiptel.gob.pe", "sbs.gob.pe", "essalud.gob.pe", "minsa.gob.pe", "minedu.gob.pe",
    "midagri.gob.pe", "mtc.gob.pe", "sunedu.gob.pe", "concytec.gob.pe", "pcm.gob.pe", "mef.gob.pe",

    # Perú: Medios de prensa y noticias
    "elcomercio.pe", "rpp.pe", "larepublica.pe", "andina.pe", "gestion.pe", "peru21.pe", "trome.pe",

    # Perú: Telecomunicaciones
    "claro.com.pe", "movistar.com.pe", "entel.pe", "bitel.com.pe",

    # Perú: Banca, billeteras y servicios financieros
    "viabcp.com", "bcp.com.pe", "interbank.pe", "interbank.com.pe", "bbva.pe", "scotiabank.com.pe",
    "yape.com.pe", "plin.pe", "banbif.com.pe", "pichincha.pe", "cajaarequipa.pe", "cajahuancayo.pe",
}

_loaded_domains: Set[str] = set(_DEFAULT_TRANCO_TOP)

# Cargar archivo externo opcional si existe (data/tranco_top.txt)
_custom_file = Path("data/tranco_top.txt")
if _custom_file.exists():
    try:
        with open(_custom_file, "r", encoding="utf-8") as f:
            for line in f:
                d = line.strip().lower()
                if d and not d.startswith("#"):
                    _loaded_domains.add(d)
    except Exception:
        pass


def is_tranco_top(domain: str) -> bool:
    """Indica si un dominio o alguno de sus padres está en la lista de alta reputación."""
    if not domain:
        return False
    d = domain.lower().strip()
    if d in _loaded_domains:
        return True
    parts = d.split(".")
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in _loaded_domains:
            return True
    return False


def tranco_count() -> int:
    """Cantidad de dominios en la lista de confianza."""
    return len(_loaded_domains)
