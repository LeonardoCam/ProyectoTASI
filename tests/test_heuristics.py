import pytest

from app import heuristics as h


def ids(factors):
    return {f["id"] for f in factors}


def test_clean_old_https_domain_is_low():
    score, f = h.evaluate("https://www.example.com/", hops=1, domain_age_days=4000)
    assert score == 0 and f == [] and h.risk_level(score) == "BAJO"


def test_very_new_domain_is_high_when_combined():
    score, f = h.evaluate("http://secure-login-bcp.xyz/verify", hops=4, domain_age_days=3)
    assert {"age_lt_30", "no_https", "bad_tld", "keywords", "hops_some"} <= ids(f)
    assert h.risk_level(score) == "ALTO"


def test_unknown_age_is_not_silently_low():
    score, f = h.evaluate("https://example.org/", hops=0, domain_age_days=None)
    assert "age_unknown" in ids(f) and score == 10


# --- Falsos positivos detectados con el dataset de Kaggle (eval/kaggle_eval.py)

def test_unknown_age_plus_http_alone_is_not_medium():
    # Caso típico .pe: WHOIS no soportado + sitio HTTP, sin ninguna otra señal.
    score, _ = h.evaluate("http://www.elcomercio.pe/", 0, None)
    assert h.risk_level(score) == "BAJO"


def test_restricted_suffix_skips_unknown_age():
    _, f = h.evaluate("https://www.sunat.gob.pe/", 0, None)
    assert "age_unknown" not in ids(f)


def test_at_sign_in_path_is_not_flagged():
    for url in ("https://medium.com/@usuario/post", "https://flickr.com/photos/41976766@N00/1"):
        assert "at_sign" not in ids(h.evaluate(url, 0, 4000)[1])


def test_keywords_match_whole_tokens_only():
    # "plin" dentro de "discipline", "login" dentro de "blogin" no deben contar.
    assert "keywords" not in ids(h.evaluate("https://example.com/self-discipline", 0, 4000)[1])
    assert "keywords" not in ids(h.evaluate("https://bloginfo.com/", 0, 4000)[1])
    assert "keywords" in ids(h.evaluate("https://example.com/account/login", 0, 4000)[1])


def test_official_brand_domains_are_not_impersonation():
    for url in ("https://www.paypal.com/signin", "https://bcpzonasegura.viabcp.com/", "https://www.bcp.com.pe/",
                "https://www.interbank.pe/", "https://www.yape.com.pe/"):
        score, f = h.evaluate(url, 0, None)
        assert "brand_impersonation" not in ids(f) and h.risk_level(score) == "BAJO", url


def test_brand_impersonation_detected():
    for url in ("https://paypal.com.cgi-bin.webscr.evil.com/", "https://bcp-zonasegura.xyz/", "https://paypalverify.net/",
                "https://yape-premios.com/"):
        assert "brand_impersonation" in ids(h.evaluate(url, 0, 4000)[1]), url
    assert "brand_impersonation" not in ids(h.evaluate("https://pineapple.com/", 0, 4000)[1])


def test_ip_host_punycode_at_sign():
    _, f = h.evaluate("http://1.2.3.4/", 0, 1000)
    assert "ip_host" in ids(f)
    _, f = h.evaluate("https://xn--pypal-4ve.com/", 0, 1000)
    assert "punycode" in ids(f)
    _, f = h.evaluate("https://google.com@evil.com/", 0, 1000)
    assert "at_sign" in ids(f)


def test_reputation_flag_forces_high():
    score, _ = h.evaluate("https://example.com/", 0, 5000, reputation_flagged=True)
    assert h.risk_level(score) == "ALTO"


def test_score_capped_and_every_nonzero_has_factors():
    score, f = h.evaluate("http://a.b.c.d.evil.tk/login@x", 9, 1, reputation_flagged=True)
    assert score == 100 and all(x["points"] > 0 and x["description"] for x in f)


def test_levels_boundaries():
    assert [h.risk_level(s) for s in (0, 29, 30, 59, 60, 100)] == ["BAJO", "BAJO", "MEDIO", "MEDIO", "ALTO", "ALTO"]


def test_registrable_domain():
    assert h.registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert h.registrable_domain("www.example.com") == "example.com"


# --- Falsos negativos del dataset de Kaggle (phishing que salía BAJO). Con WHOIS OK y HTTPS,
#     es decir, solo con la forma de la URL, deben llegar al menos a MEDIO.

@pytest.mark.parametrize("url", [
    "https://br-icloud.com.br/",                                        # marca en dominio ajeno
    "https://linkedln.sahajcare.org/",                                  # typosquatting (l -> ln)
    "https://www.apple.com-support-assistenza-account.information.upoert.com/ap/",  # .com falso
    "https://www.bimovia.com/wp-admin/user/www.bankofamerica.com.login.update/",    # kit en CMS
    "https://account.details.upgrade.helpdata.information.center.security.service.protection.ecospringsmelbourne.com/",
    "https://hassanalsheikh.com/wp-content/wppa-depot/admin/www.paypal.com/restore.php",
    "https://us.battle.net.login.zh-gvk.in/login.html",
    "https://faceb00k.new.fr/",
])
def test_kaggle_phishing_reaches_medium(url):
    score, f = h.evaluate(url, 0, 4000)
    assert h.risk_level(score) != "BAJO", (url, score, ids(f))


# --- Falsos positivos reales encontrados al revisar los resultados de Kaggle

@pytest.mark.parametrize("url", [
    "https://www.freebsd.org/auditors.html",           # etiquetadas "phishing" en el dataset, pero legítimas
    "https://tools.ietf.org/html/rfc2617",
    "https://www.microsoft.com/mscorp/java/",
    "https://amazon.ca/Ghost-Mr-Chicken/dp/6304005512",  # marca con otro ccTLD
    "https://pco-bcp.gc.ca/index.asp?lang=eng",        # gobierno de Canadá, no BCP
    "https://finance.boston.com/boston/quote",         # "finance" no es typosquat de "binance"
    "https://charley-chase.com/",
    "https://festival-outlook.consequenceofsound.net/fests/view/503",
    "https://officea-z.com/",
    "https://sites.google.com/a/woodplanning.com/www/",
    "https://www.viabcp.com/", "https://bcpzonasegura.viabcp.com/",
])
def test_legit_urls_stay_low(url):
    score, f = h.evaluate(url, 0, 4000)
    assert h.risk_level(score) == "BAJO", (url, score, ids(f))


def test_typosquat_helper():
    assert h._typosquat("linkedln") == "linkedin"
    assert h._typosquat("paypa1") == "paypal"
    assert h._typosquat("g00gle") == "google"
    assert h._typosquat("paypall") == "paypal"
    assert h._typosquat("paypal") is None and h._typosquat("finance") is None
