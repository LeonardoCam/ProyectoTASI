"""Motor heurístico determinista: puntaje de riesgo 0-100 con factores explicables."""
import ipaddress
import re
from dataclasses import dataclass, asdict
from typing import Optional, Sequence
from urllib.parse import urlsplit

import tldextract

from . import tranco

# Sin descargas de red: usa la lista de sufijos incluida en el paquete.
_extract = tldextract.TLDExtract(suffix_list_urls=())

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "bl.ink", "t.ly", "lnkd.in", "s.id",
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "country",
    "work", "support", "rest", "icu", "cam", "monster", "tech",
}

# Palabras de "acción" típicas de phishing. Se comparan por TOKEN completo (no subcadena):
# con subcadenas, "plin" coincidía con "discipline" y "login" con cualquier foro; en el dataset
# de Kaggle el factor se disparaba en el 6 % de las URLs benignas.
ACTION_WORDS = re.compile(
    r"^(login|logon|signin|signon|verify|verification|verificar|validate|validar|account|"
    r"update|actualizar|secure|security|seguridad|password|passwd|contrasena|clave|confirm|"
    r"confirmar|webscr|unlock|suspended|suspendida|recover|recovery|authenticate|wallet|billing)$"
)

# Marcas suplantadas con frecuencia -> dominios registrables oficiales. La marca es señal de
# riesgo solo si aparece en un dominio que NO es suyo (ej. "bcp-seguro.xyz", "paypal.com.evil.co").
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
    "netflix": {"netflix.com", "netflix.net"},
    "icloud": {"icloud.com", "apple.com"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com", "msn.com"},
    "office365": {"microsoft.com", "office.com", "office365.com"},
    "outlook": {"outlook.com", "live.com", "office.com", "microsoft.com"},
    "facebook": {"facebook.com", "fb.com", "facebook.net"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net", "wa.me"},
    "ebay": {"ebay.com", "ebay.es", "ebay.de", "ebay.co.uk", "ebay.com.au", "ebay.ca", "ebay.fr", "ebay.it"},
    "amazon": {"amazon.com", "amazon.es", "amazon.de", "amazon.co.uk", "amazon.com.br", "amazon.com.mx", "amazonaws.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"},
    "bcp": {"viabcp.com", "bcp.com.pe", "bcpbolivia.com"},
    "interbank": {"interbank.pe", "interbank.com.pe"},
    "bbva": {"bbva.pe", "bbva.com", "bbva.es", "bbva.mx", "bbvacontinental.pe"},
    "scotiabank": {"scotiabank.com", "scotiabank.com.pe"},
    "yape": {"yape.com.pe"},
    "plin": {"plin.pe"},
    "sunat": {"sunat.gob.pe"},
    "reniec": {"reniec.gob.pe"},
    "bancodelanacion": {"bn.com.pe"},
    "linkedin": {"linkedin.com", "lnkd.in"},
    "google": {"google.com", "googleusercontent.com", "googleapis.com", "gstatic.com", "youtube.com", "blogspot.com", "appspot.com", "goo.gl"},
    "gmail": {"gmail.com", "google.com"},
    "yahoo": {"yahoo.com", "yahoo.co.jp", "yimg.com"},
    "hotmail": {"hotmail.com", "live.com", "outlook.com", "microsoft.com"},
    "dropbox": {"dropbox.com", "dropboxusercontent.com", "db.tt"},
    "docusign": {"docusign.com", "docusign.net"},
    "adobe": {"adobe.com", "adobelogin.com"},
    "santander": {"santander.com", "santander.com.br", "santander.co.uk", "santander.es", "santander.com.mx"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "wellsfargo": {"wellsfargo.com"},
}
# Marcas que también se detectan como subcadena del dominio ("paypalverify.com"). Las cortas
# o comunes (apple, amazon, bcp...) solo por token completo para no marcar "pineapple.com".
# Marcas que también son palabras comunes: solo cuentan si el dominio trae además una palabra de
# acción (login, verify...). En Kaggle generaban FP como festival-outlook.* u officea-z.com.
COMMON_WORD_BRANDS = {"outlook", "office", "steam"}
BRANDS_SUBSTRING = {"paypal", "netflix", "icloud", "interbank", "scotiabank", "bancodelanacion", "metamask", "coinbase",
                    "binance", "linkedin", "dropbox", "docusign", "bankofamerica", "wellsfargo"}

# Sufijos de registro restringido (gobierno, educación): WHOIS no aporta, el registro ya está verificado.
RESTRICTED_SUFFIXES = ("gob.pe", "edu.pe", "mil.pe", "gov", "edu", "mil", "gov.uk", "ac.uk", "gob.mx", "gob.ar", "gov.br",
                       "edu.co", "gov.co", "gc.ca", "gov.au", "edu.au", "gob.es", "gouv.fr")

_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def _tokens(text: str) -> list[str]:
    return [t for t in _TOKEN_SPLIT.split(text.lower()) if t]


# --- Señales adicionales, medidas en el dataset de Kaggle (eval/kaggle_eval.py). Entre paréntesis:
#     % de URLs benignas vs % de phishing (con esquema) donde aparece la señal.

# Hosting gratuito, DNS dinámico y formularios: cualquiera publica ahí (0,7 % vs 8,6 %).
FREE_HOSTING = (
    "000webhostapp.com", "16mb.com", "brinkster.net", "ddnsfree.com", "duckdns.org", "no-ip.org", "no-ip.biz",
    "ddns.net", "myftpupload.com", "x10.mx", "hol.es", "esy.es", "weebly.com", "weeblysite.com", "wixsite.com",
    "webcindario.com", "altervista.org", "pastehtml.com", "byethost", "ucoz.", "narod.ru", "tripod.com",
    "angelfire.com", "godaddysites.com", "yolasite.com", "firebaseapp.com", "web.app", "glitch.me", "repl.co",
    "ngrok.io", "ngrok-free.app", "herokuapp.com", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
    "r2.dev", "ipfs.", "webnode.", "activehosted.com", "app.link", "square.site", "googledrive.com",
    "sites.google.com", "forms.gle", "jotform.", "typeform.com", "secureserver.net", "webhostbox.net",
    "inmotionhosting.com", "sharepoint.com",
)
# Directorios de CMS donde los atacantes suben kits en sitios comprometidos (1,4 % vs 16 %).
CMS_KIT_PATH = re.compile(
    r"/(wp-admin|wp-content|wp-includes|administrator|cgi-bin|components|plugins|modules|includes)/", re.IGNORECASE
)
# Carpeta con hash de 32 hex: los kits generan una por víctima (0,8 % vs 8,6 %).
HASH_DIR = re.compile(r"/[0-9a-f]{32}(/|$)", re.IGNORECASE)
# Un dominio completo dentro de la ruta: /www.bankofamerica.com.login/ (0,6 % vs 4,8 %). Se exige
# "www." para no marcar rutas normales como sites.google.com/a/empresa.com/ (el caso con marca se
# trata aparte en evaluate()).
DOMAIN_IN_PATH = re.compile(r"(^|[/=.-])www\.[a-z0-9-]{3,}\.(com|net|org)([./?-]|$)", re.IGNORECASE)
BRAND_DOMAIN_IN_PATH = re.compile(r"(^|[/=.-])(" + "|".join(BRANDS) + r")\.(com|net|org)([./?-]|$)", re.IGNORECASE)
# "com"/"net"/"org" como etiqueta del subdominio: apple.com-soporte.evil.net (0,5 % vs 6,8 %).
TLD_TOKENS_IN_SUBDOMAIN = {"com", "net", "org"}

# Typosquatting: sustitución de caracteres parecidos, distancia de Levenshtein o error de 1 letra.
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})
TYPO_TARGETS = (
    "paypal", "netflix", "icloud", "apple", "microsoft", "facebook", "instagram",
    "whatsapp", "amazon", "linkedin", "google", "yahoo", "dropbox", "hotmail", "binance", "coinbase",
    "interbank", "scotiabank", "santander", "bankofamerica", "wellsfargo", "docusign",
    "viabcp", "bbva", "yape", "plin",
)
TYPO_EXCLUSIONS = {"finance", "pine", "pineapple", "stream", "steamer", "sample", "app", "open"}


def _levenshtein(s1: str, s2: str) -> int:
    """Calcula la distancia de edición de Levenshtein entre dos cadenas."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1] + [0] * len(s2)
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr[j + 1] = min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost)
        prev = curr
    return prev[len(s2)]


def _typosquat(token: str) -> Optional[str]:
    """Marca que `token` imita (sin ser ella), o None."""
    if len(token) < 4:
        return None
    if token in TYPO_EXCLUSIONS:
        return None
    norm = token.translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
    for brand in TYPO_TARGETS:
        if token == brand:
            return None
        if norm == brand:
            return brand                      # g00gle, paypa1, rnicrosoft
        if len(brand) < 5 or norm[0] != brand[0]:
            # 1 letra de diferencia solo en marcas reconocidas y conservando la inicial:
            # evita confundir palabras reales como "finance" con "binance".
            continue
        if len(norm) == len(brand) and sum(a != b for a, b in zip(norm, brand)) == 1:
            return brand                      # linkedln, paypel
        if len(norm) == len(brand) + 1 and any(norm[:i] + norm[i + 1:] == brand for i in range(1, len(norm))):
            return brand                      # paypall, faceboook
        if _levenshtein(norm, brand) == 1:
            return brand                      # netfflix, viabc, amazzon
    return None

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


_OFFICIAL: set[str] = set()


def _all_official() -> set[str]:
    if not _OFFICIAL:
        _OFFICIAL.update(d for doms in BRANDS.values() for d in doms)
    return _OFFICIAL


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
    threat_matches: Sequence = (),
    virustotal: Optional[object] = None,
    domain_not_found: bool = False,
    redirect_problem: Optional[str] = None,
    cert_age_days: Optional[int] = None,
    page_title: Optional[str] = None,
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

    # --- Listas de amenazas (URLhaus, blackbook, OpenPhish...): un sitio reportado domina el resultado
    if threat_matches:
        cats = sorted({m.category for m in threat_matches})
        srcs = ", ".join(sorted({m.source for m in threat_matches}))
        what = " y ".join("malware" if c == "malware" else "phishing" for c in cats)
        add("threat_intel", f"Reportado como {what} en listas de amenazas ({srcs}): {threat_matches[0].matched}.", 80)

    if redirect_problem == "loop":
        add("redirect_loop", "El enlace redirige en bucle: técnica para evadir analizadores (o sitio mal configurado).", 15)
    elif redirect_problem == "too_many":
        add("hops_many", "La cadena de redirecciones supera el máximo permitido.", 20)

    if domain_not_found:
        add("domain_not_found", "El dominio no existe actualmente (sin registros DNS): es habitual en enlaces "
            "de phishing ya dados de baja. No lo abras si vuelve a aparecer.", 10)

    # --- VirusTotal: veredicto de decenas de antivirus
    if virustotal is not None:
        mal, sus, total = virustotal.malicious, virustotal.suspicious, virustotal.engines
        if mal >= 3:
            add("virustotal", f"VirusTotal: {mal} de {total} motores antivirus lo marcan como malicioso.", 80)
        elif mal >= 1:
            add("virustotal", f"VirusTotal: {mal} de {total} motores lo marcan como malicioso (pocos, posible falso positivo).", 30)
        elif sus >= 1:
            add("virustotal", f"VirusTotal: {sus} motores lo consideran sospechoso.", 10)

    # --- Antigüedad del dominio (OSINT/WHOIS)
    reg_domain = registrable_domain(host)
    restricted = any(reg_domain == s or reg_domain.endswith("." + s) for s in RESTRICTED_SUFFIXES)
    is_trusted = tranco.is_tranco_top(reg_domain) and not threat_matches and not reputation_flagged

    if domain_age_days is None:
        # Si el dominio es de gobierno/educación o está en Tranco Top, la falta de WHOIS no se penaliza
        if not restricted and not is_trusted:
            add("age_unknown", "No se pudo determinar la antigüedad del dominio (WHOIS protegido o no disponible).", 10)
    elif domain_age_days < 30:
        add("age_lt_30", f"Dominio muy reciente ({domain_age_days} días): patrón típico de campañas de fraude.", 40)
    elif domain_age_days < 180:
        add("age_lt_180", f"Dominio reciente ({domain_age_days} días).", 20)
    elif domain_age_days < 365:
        add("age_lt_365", f"Dominio con menos de un año ({domain_age_days} días).", 8)

    # --- Antigüedad del Certificado SSL/TLS
    if parts.scheme == "https" and cert_age_days is not None:
        if cert_age_days < 3 and not is_trusted and (domain_age_days is None or domain_age_days < 90):
            add("cert_very_young", f"Certificado SSL recién emitido ({cert_age_days} días): común en campañas activas de phishing.", 15)
        elif cert_age_days >= 60 and (domain_age_days is None or domain_age_days >= 180):
            add("cert_established", f"Certificado SSL consolidado (emitido hace {cert_age_days} días).", -10)

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
        if ext.subdomain and ext.subdomain.count(".") >= 4:
            add("subdomains", "Cadena muy larga de subdominios, técnica común para esconder el dominio real.", 10)
        elif ext.subdomain and ext.subdomain.count(".") >= 2:
            add("subdomains", "Muchos subdominios anidados, técnica común para imitar marcas.", 5)
        if reg_domain in SHORTENERS:
            add("nested_shortener", "El destino final es otro acortador de URL (encadenamiento para ocultar el destino).", 10)

        # Suplantación de marca: la marca aparece en el host pero el dominio registrable no es suyo.
        sub_tokens = _tokens(ext.subdomain)
        dom_tokens = _tokens(ext.domain)
        host_tokens = set(sub_tokens) | set(dom_tokens)
        is_brand_domain = ext.domain in BRANDS or reg_domain in _all_official() or restricted
        brand_hit = None
        has_host_action = any(ACTION_WORDS.match(t) for t in host_tokens)
        if not is_brand_domain:
            for brand in BRANDS:
                if brand in COMMON_WORD_BRANDS and not has_host_action:
                    continue
                if brand in host_tokens or (brand in BRANDS_SUBSTRING and brand in ext.domain):
                    brand_hit = brand
                    add("brand_impersonation",
                        f"El dominio menciona la marca '{brand}' pero no pertenece a ella ({reg_domain}).", 30)
                    break
            if not brand_hit:
                typo = next((b for b in map(_typosquat, sub_tokens + dom_tokens) if b), None)
                if typo:
                    add("typosquatting", f"El dominio imita la marca '{typo}' con letras cambiadas o parecidas.", 30)

        if TLD_TOKENS_IN_SUBDOMAIN & set(sub_tokens):
            add("fake_domain_prefix",
                "El subdominio contiene '.com/.net/.org' para aparentar otro dominio (ej. banco.com-seguro.evil.net).", 15)

        if not is_trusted and any(reg_domain == f or host.endswith("." + f) or f in host for f in FREE_HOSTING):
            add("free_hosting", "Alojado en hosting gratuito, DNS dinámico o formularios públicos, muy usados en phishing.", 10)

    # '@' solo engaña en la parte de autoridad (http://banco.com@evil.com/).
    if "@" in (parts.netloc or ""):
        add("at_sign", "La URL contiene '@' antes del dominio, usado para disfrazar el dominio real.", 15)

    if not is_ip:
        sub_and_domain = _tokens(ext.subdomain) + _tokens(ext.domain)
        path_tokens = _tokens((parts.path or "") + " " + (parts.query or ""))
        host_actions = {t for t in sub_and_domain if ACTION_WORDS.match(t)}
        if len(host_actions) >= 2:
            add("keywords", f"El dominio acumula palabras típicas de phishing ({', '.join(sorted(host_actions))}).", 20)
        elif host_actions:
            add("keywords", "El dominio contiene palabras típicas de phishing (login, verificación, seguridad, etc.).", 10)
        elif not is_brand_domain and not is_trusted and any(ACTION_WORDS.match(t) for t in path_tokens):
            add("keywords", "La ruta contiene palabras típicas de phishing (login, verificación, etc.).", 5)

        # --- Ruta: señales de kit de phishing subido a un sitio ajeno
        if not is_brand_domain:
            path_brand = next((b for b in BRANDS if b in path_tokens), None)
            if path_brand:
                add("brand_in_path", f"La ruta menciona la marca '{path_brand}' en un sitio que no es suyo.", 10)
        path = parts.path or ""
        if CMS_KIT_PATH.search(path):
            add("cms_path", "La ruta está dentro de carpetas internas de un CMS (wp-content, administrator...), típico de sitios comprometidos.", 10)
        if HASH_DIR.search(path):
            add("hash_dir", "La ruta tiene una carpeta con un hash aleatorio, patrón de kits de phishing.", 10)
        brand_domain_in_path = not is_brand_domain and bool(BRAND_DOMAIN_IN_PATH.search(path))
        if DOMAIN_IN_PATH.search(path) or brand_domain_in_path:
            add("domain_in_path", "La ruta contiene otro nombre de dominio, para aparentar ser ese sitio.", 10)

        # Suplantación en el título de la página (phishing con dominio camuflado)
        if page_title and not is_brand_domain and not is_trusted:
            t_lower = page_title.lower()
            t_brand = None
            for brand in BRANDS:
                if brand in t_lower:
                    t_brand = brand
                    break
            if not t_brand and ("banco de crédito" in t_lower or "banco de credito" in t_lower):
                t_brand = "bcp"
            if t_brand:
                add("title_impersonation",
                    f"El título de la página ('{page_title[:60]}') contiene la marca '{t_brand}' en un dominio no oficial.", 35)

    # Atenuador de confianza Tranco si hubo factores leves no críticos
    if is_trusted and factors:
        add("tranco_trusted", "Atenuador de confianza: dominio de alta reputación y amplia trayectoria (Top Tranco).", -20)

    score = max(0, min(sum(f.points for f in factors), 100))
    return score, [asdict(f) for f in factors]
