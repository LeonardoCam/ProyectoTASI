"""Dataset sintético controlado (semilla fija): 100 enlaces legítimos y 100 simulaciones de ataque.

Incluye casos difíciles a propósito (≈20 %) para que las métricas no sean triviales:
  - legítimos "nuevos" (startups, campañas recientes) -> riesgo de falso positivo
  - phishing alojado en dominios antiguos/comprometidos con HTTPS -> riesgo de falso negativo
"""
import random

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rebrand.ly", "ow.ly", "shorturl.at"]
LEGIT_SITES = [
    ("www.wikipedia.org", 9000), ("github.com", 6000), ("www.upch.edu.pe", 7000), ("www.gob.pe", 4500),
    ("www.youtube.com", 7500), ("www.sunat.gob.pe", 6500), ("www.bcp.com.pe", 8000), ("www.linkedin.com", 8000),
    ("docs.google.com", 9500), ("www.mercadolibre.com.pe", 6000), ("www.elcomercio.pe", 9000),
    ("www.udemy.com", 5500), ("www.microsoft.com", 11000), ("zoom.us", 5200), ("www.rpp.pe", 8800),
]
BRANDS = ["bcp", "interbank", "bbva", "yape", "sunat", "reniec", "paypal", "netflix", "scotiabank"]
BAD_TLDS = ["xyz", "top", "click", "icu", "tk", "work", "cam"]
WORDS = ["login", "verifica", "seguro", "actualiza", "cuenta", "clave", "soporte", "premio"]


def _slug(rng, n=6):
    return "".join(rng.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(n))


def build(seed: int = 2026):
    rng = random.Random(seed)
    cases = []

    def chain(short, final, extra_hops):
        mids = [f"https://{rng.choice(['trk','go','l','redir'])}.{_slug(rng,5)}-cdn.com/r/{_slug(rng)}" for _ in range(extra_hops)]
        return [f"https://{short}/{_slug(rng,7)}"] + mids + [final]

    # --- 100 legítimos: 85 típicos, 15 difíciles (dominios nuevos)
    for i in range(100):
        short = rng.choice(SHORTENERS)
        if i < 85:
            host, age = rng.choice(LEGIT_SITES)
            age += rng.randint(-300, 300)
            final = f"https://{host}/{rng.choice(['', 'es/', 'blog/', 'curso/', 'noticias/'])}{_slug(rng,5)}"
            hops = rng.choice([0, 0, 1, 1, 2])
            hard = False
        else:   # startup/campaña reciente, legítima
            host = f"{rng.choice(['mi','nube','app','promo'])}{_slug(rng,4)}.com"
            age = rng.randint(8, 150)
            final = f"https://www.{host}/inicio"
            hops = rng.choice([0, 1, 2])
            hard = True
        cases.append(dict(label=0, hard=hard, urls=chain(short, final, hops), age=age,
                          domain=final.split("/")[2].split("www.", 1)[-1] if not final.split("/")[2].startswith(("docs.", "github")) else final.split("/")[2]))

    # --- 100 ataques: 80 típicos, 20 difíciles (dominio antiguo comprometido, https, sin palabras)
    for i in range(100):
        short = rng.choice(SHORTENERS)
        if i < 80:
            brand = rng.choice(BRANDS)
            kind = rng.choice(["tld", "tld", "http", "ip", "sub", "puny"])
            age = rng.choice([1, 2, 3, 5, 9, 14, 21, 27, 45, 90, 400 if kind == "ip" else 60])
            if kind == "ip":
                host = f"{rng.randint(11,200)}.{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}"
                final = f"http://{host}/{brand}/{rng.choice(WORDS)}"
                dom = host
            elif kind == "puny":
                host = f"{brand}{rng.choice('áéíóú')}-{_slug(rng,3)}.com".encode("idna").decode()
                final = f"https://{host}/{rng.choice(WORDS)}"
                dom = host
            elif kind == "sub":
                host = f"{brand}.{rng.choice(WORDS)}.cuenta.{_slug(rng,6)}.com"
                final = f"https://{host}/"
                dom = f"{_slug(rng,6)}.com"
                dom = host.split(".", 3)[-1]
            else:
                dom = f"{brand}-{rng.choice(WORDS)}-{_slug(rng,3)}.{rng.choice(BAD_TLDS)}"
                scheme = "http" if kind == "http" else "https"
                final = f"{scheme}://{dom}/{rng.choice(WORDS)}"
            hops = rng.choice([1, 2, 3, 4, 5, 6])
            hard = False
        else:   # comprometido: sitio viejo, https, ruta discreta
            dom = f"{rng.choice(['panaderia','clinica','estudio','ferreteria','colegio'])}{_slug(rng,3)}.com"
            age = rng.randint(1200, 4000)
            final = f"https://{dom}/wp-content/{_slug(rng,6)}.php"
            hops = rng.choice([0, 1, 1, 2])
            hard = True
        cases.append(dict(label=1, hard=hard, urls=chain(short, final, hops), age=age, domain=dom))
    rng.shuffle(cases)
    return cases
