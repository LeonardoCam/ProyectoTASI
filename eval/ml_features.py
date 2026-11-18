"""Características léxicas de una URL para el modelo de machine learning.

Reproducen las del enfoque más usado en los notebooks de Kaggle sobre el "Malicious URLs dataset"
(conteos de caracteres, longitudes, IP, acortadores, palabras sospechosas...).

`honest=True` calcula todo sobre la URL SIN esquema ni "www." inicial y omite las columnas que
dependen de ellos (count_https, count_http, count_www, abnormal_url): en ese dataset casi todas las
URLs benignas vienen sin esquema y todas las de defacement con "http://", así que esas columnas le
"dicen" la etiqueta al modelo y su exactitud no se traslada al mundo real.
"""
import ipaddress
import re
from urllib.parse import urlsplit

SHORTENER = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
    r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
    r"short\.to|budurl\.com|ping\.fm|post\.ly|just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
    r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|"
    r"qr\.ae|adf\.ly|bitly\.com|cur\.lv|ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|"
    r"buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|scrnch\.me|filoops\.info|"
    r"vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|link\.zip\.net|rb\.gy|cutt\.ly|shorturl\.at",
    re.IGNORECASE,
)
SUSPICIOUS_WORDS = re.compile(
    r"paypal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr", re.IGNORECASE)

RAW_FEATURES = [
    "use_of_ip", "abnormal_url", "count_dot", "count_www", "count_at", "count_dir", "count_embed_domain",
    "short_url", "count_https", "count_http", "count_percent", "count_ques", "count_hyphen", "count_equal",
    "url_length", "hostname_length", "sus_url", "fd_length", "tld_length", "count_digits", "count_letters",
]
LEAKY = {"count_https", "count_http", "count_www", "abnormal_url"}
HONEST_FEATURES = [f for f in RAW_FEATURES if f not in LEAKY]


def _strip(url: str) -> str:
    u = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", url.strip())
    return u[4:] if u.lower().startswith("www.") else u


def extract(url: str, honest: bool = True) -> list[float]:
    u = _strip(url) if honest else url
    try:
        parts = urlsplit(u if "://" in u else "//" + u)
        host = (parts.hostname or "")
        path = parts.path or ""
    except ValueError:
        host, path = "", ""
    try:
        ipaddress.ip_address(host)
        use_of_ip = 1
    except ValueError:
        use_of_ip = 0
    first_dir = path.split("/")[1] if path.count("/") > 1 else ""
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    f = {
        "use_of_ip": use_of_ip,
        "abnormal_url": int(bool(host) and host in u),
        "count_dot": u.count("."),
        "count_www": u.lower().count("www"),
        "count_at": u.count("@"),
        "count_dir": path.count("/"),
        "count_embed_domain": path.count("//"),
        "short_url": int(bool(SHORTENER.search(u))),
        "count_https": u.lower().count("https"),
        "count_http": u.lower().count("http"),
        "count_percent": u.count("%"),
        "count_ques": u.count("?"),
        "count_hyphen": u.count("-"),
        "count_equal": u.count("="),
        "url_length": len(u),
        "hostname_length": len(host),
        "sus_url": int(bool(SUSPICIOUS_WORDS.search(u))),
        "fd_length": len(first_dir),
        "tld_length": len(tld),
        "count_digits": sum(c.isdigit() for c in u),
        "count_letters": sum(c.isalpha() for c in u),
    }
    return [f[k] for k in (HONEST_FEATURES if honest else RAW_FEATURES)]
