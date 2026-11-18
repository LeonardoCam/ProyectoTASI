"""Normalización de la URL ingresada por el usuario antes de validarla.

Los usuarios suelen pegar enlaces sin esquema (`bit.ly/abc`, `www.sitio.com`) o "defanged"
como en reportes de seguridad (`hxxps://sitio[.]com`). Aquí se llevan a una URL absoluta.
Los esquemas no web (javascript:, file:, data:...) se dejan intactos para que la validación
SSRF los rechace con `scheme_not_allowed`.
"""
import re

_HAS_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_FORBIDDEN_SCHEMES = {
    "javascript", "vbscript", "data", "file", "mailto", "tel", "about", "blob", "ftp", "ws", "wss",
}
_DEFANG = [
    (re.compile(r"^hxxp(s?)", re.IGNORECASE), r"http\1"),   # hxxp:// / hxxps://
    (re.compile(r"^(https?)\[:\]", re.IGNORECASE), r"\1:"),  # https[:]//
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]", re.IGNORECASE), "."),
]


_PAIRS = {"<": ">", "(": ")", "[": "]", "{": "}", '"': '"', "'": "'", "«": "»", "“": "”", "‘": "’", "`": "`"}
_TRAILING = ".,;:!?¿¡…"


_URL_IN_TEXT = re.compile(
    r"(?:[a-zA-Z][a-zA-Z0-9+.-]*://|hxxps?://|//)\S+"          # con esquema
    r"|(?<![@\w.-])(?:[\w-]+(?:\.|\[\.\]|\(\.\)))+[a-zA-Z]{2,}(?:[/:?#]\S*)?",  # dominio.tld[/ruta]
    re.IGNORECASE,
)


def _strip_wrapping(raw: str) -> str:
    """Quita lo que se pega al copiar un enlace de un chat o correo: '<https://x.com>', 'x.com/a).'

    Si se pegó una frase entera ("Mira esto: bit.ly/abc"), se extrae el primer enlace.
    """
    url = raw.strip()
    if any(c.isspace() for c in url):
        m = _URL_IN_TEXT.search(url)
        if m:
            url = m.group(0)
    changed = True
    while changed and len(url) > 1:
        changed = False
        if url[0] in _PAIRS and url[-1] == _PAIRS[url[0]]:
            url, changed = url[1:-1].strip(), True
        elif url[-1] in _TRAILING:
            url, changed = url[:-1], True
        elif url[-1] in ")]}>\"'”»’" and url.count(url[-1]) > url.count(_opening(url[-1])):
            url, changed = url[:-1], True      # cierre sin apertura: "(ver bit.ly/abc)"
        elif url[0] in "(<[{\"'“«‘" and url.count(url[0]) > url.count(_PAIRS[url[0]]):
            url, changed = url[1:], True
    return url


def _opening(close: str) -> str:
    return next((o for o, c in _PAIRS.items() if c == close), close)


def normalize_url(raw: str) -> tuple[str, bool]:
    """Devuelve (url_normalizada, se_agregó_esquema).

    Si se agregó el esquema se usa https://; el llamador puede reintentar con http://.
    """
    url = _strip_wrapping(raw)
    for pattern, repl in _DEFANG:
        url = pattern.sub(repl, url)

    if _HAS_SCHEME.match(url):
        return url, False
    if url.startswith("//"):                       # URL relativa al protocolo
        return "https:" + url, True

    scheme = url.split(":", 1)[0].lower() if ":" in url else ""
    if scheme in _FORBIDDEN_SCHEMES:
        return url, False                          # se rechazará en assert_safe_url
    return "https://" + url, True


def defang_url(url: str) -> str:
    """Sanitiza una URL para compartirla de forma segura sin riesgo de clic accidental.

    Ejemplo: https://phishing.bcp-portal.xyz/login -> hxxps://phishing[.]bcp-portal[.]xyz/login
    """
    from urllib.parse import urlsplit
    u = re.sub(r"^https://", "hxxps://", url.strip(), flags=re.IGNORECASE)
    u = re.sub(r"^http://", "hxxp://", u, flags=re.IGNORECASE)
    parts = urlsplit(u)
    if parts.netloc:
        defanged_netloc = parts.netloc.replace(".", "[.]")
        u = parts._replace(netloc=defanged_netloc).geturl()
    return u

