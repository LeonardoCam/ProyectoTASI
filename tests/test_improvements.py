"""Pruebas unitarias para las mejoras del proyecto:

1. Escudo de confianza Tranco (Top Dominios) y atenuación de riesgo.
2. Reglas compuestas contra falsos positivos en rutas de autenticación (/login, /account).
3. Detección de typosquatting dinámico por distancia de Levenshtein.
4. Inspección de antigüedad de certificados TLS/SSL.
"""
from app import heuristics as h
from app import tranco


def ids(factors):
    return {f["id"] for f in factors}


def test_tranco_top_domains_loaded():
    assert tranco.tranco_count() > 100
    assert tranco.is_tranco_top("github.com")
    assert tranco.is_tranco_top("upch.edu.pe")
    assert tranco.is_tranco_top("sub.upch.edu.pe")
    assert not tranco.is_tranco_top("dominio-malicioso-random.xyz")


def test_tranco_trusted_domain_login_is_low():
    # En un dominio Tranco, tener /login no debe disparar falsos positivos
    score, f = h.evaluate("https://github.com/login", hops=0, domain_age_days=None)
    assert h.risk_level(score) == "BAJO"
    assert "keywords" not in ids(f)
    assert "age_unknown" not in ids(f)
    assert score == 0


def test_tranco_trusted_domain_with_redirect_gets_trust_atenuator():
    # Si un dominio confiable tiene varios saltos, el atenuador Tranco reduce el puntaje
    score, f = h.evaluate("https://upch.edu.pe/portal", hops=3, domain_age_days=None)
    assert "tranco_trusted" in ids(f)
    assert score == 0
    assert h.risk_level(score) == "BAJO"


def test_dynamic_typosquatting_levenshtein():
    # Detecta variaciones por inserción, duplicación o sustitución
    assert h._typosquat("netfflix") == "netflix"
    assert h._typosquat("amazzon") == "amazon"
    assert h._typosquat("viabc") == "viabcp"
    assert h._typosquat("paypaal") == "paypal"
    # Palabras legítimas similares no deben confundirse (falsos positivos mitigados)
    assert h._typosquat("finance") is None
    assert h._typosquat("pine") is None
    assert h._typosquat("sample") is None


def test_typosquatting_triggers_in_evaluation():
    score, f = h.evaluate("https://netfflix-verify.com/", hops=0, domain_age_days=1000)
    assert "typosquatting" in ids(f)
    assert score >= 30


def test_cert_age_factors():
    # Certificado recién nacido (< 3 días) en dominio desconocido: suma riesgo
    score, f = h.evaluate("https://nuevo-sitio-phishing.com/", hops=0, domain_age_days=None, cert_age_days=1)
    assert "cert_very_young" in ids(f)

    # Certificado consolidado (>= 60 días) en dominio maduro: aporta atenuador
    score_mature, f_mature = h.evaluate("https://sitio-maduro.com/info", hops=3, domain_age_days=500, cert_age_days=120)
    assert "cert_established" in ids(f_mature)


def test_title_impersonation():
    # Título que contiene una marca bancaria en un dominio no oficial
    score, f = h.evaluate("https://portal-sorteo-premios.com/", hops=0, domain_age_days=1000,
                          page_title="Bienvenido a tu Banca por Internet BCP")
    assert "title_impersonation" in ids(f)
    assert score >= 35

    # Título en dominio oficial de la marca: no debe marcarse suplantación
    score_of, f_of = h.evaluate("https://bcpzonasegura.viabcp.com/", hops=0, domain_age_days=1000,
                                page_title="Banca por Internet BCP")
    assert "title_impersonation" not in ids(f_of)


def test_score_never_negative():
    # Puntaje nunca baja de 0 incluso si los atenuadores superan los puntos
    score, f = h.evaluate("https://github.com/", hops=0, domain_age_days=4000, cert_age_days=100)
    assert score == 0


def test_shannon_entropy_and_dga_detection():
    # Entropía de palabra natural vs DGA aleatorio
    assert h.shannon_entropy("universidad") < 3.2
    assert h.shannon_entropy("xkj918fa92zq") >= 3.38

    # Dominio con patrón DGA suma factor de alta entropía
    score, f = h.evaluate("https://xkj918fa92zq.info/", hops=0, domain_age_days=100)
    assert "high_entropy_domain" in ids(f)


def test_executable_download_detection():
    # URL que apunta a ejecutable malicioso directo (.exe / .apk / .scr)
    score, f = h.evaluate("https://portal-descargas.com/setup.exe", hops=0, domain_age_days=100)
    assert "executable_download" in ids(f)
    assert score >= 45

    # Cabecera Content-Disposition con archivo ejecutable
    score_cd, f_cd = h.evaluate("https://sitio-actualiza.com/get", hops=0, domain_age_days=100,
                                content_disposition='attachment; filename="update.apk"')
    assert "executable_download" in ids(f_cd)


def test_strong_security_headers_recognition():
    headers = {"hsts": True, "csp": True, "x_frame_options": True, "x_content_type_options": True}
    score, f = h.evaluate("https://portal-seguro.com/login", hops=2, domain_age_days=300,
                          security_headers=headers)
    assert "strong_security_headers" in ids(f)
