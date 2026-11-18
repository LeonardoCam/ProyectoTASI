"""Listas de amenazas y VirusTotal, sin red (transportes y listas simulados)."""
import base64

import httpx
import pytest

from app import api, config, heuristics, resolver, threat_intel
from app.threat_intel import FEEDS, ThreatIntel, VTResult
from test_api import client  # noqa: F401  (reutiliza el fixture de test_api.py)

URLHAUS = """# Title: Malicious Domains Blocklist
# Source: https://urlhaus.abuse.ch/api/
malware-descargas.example
cdn.payload-evil.example
"""
BLACKBOOK = "c2-server.example\n"
PHISH_FILTER = "! comentario\nbcp-zonasegura.example\n"
OPENPHISH = "https://sites.example.app/login/paypal/\nhttp://www.evil-host.example/x.php?id=1\n"
BODIES = {"URLhaus": URLHAUS, "blackbook": BLACKBOOK, "phishing-filter": PHISH_FILTER, "OpenPhish": OPENPHISH}


def _transport(fail: set[str] = frozenset()):
    by_url = {f.url: BODIES[f.name] for f in FEEDS}

    def handler(request: httpx.Request):
        name = next(f.name for f in FEEDS if f.url == str(request.url))
        if name in fail:
            return httpx.Response(503)
        return httpx.Response(200, text=by_url[str(request.url)])
    return httpx.MockTransport(handler)


@pytest.fixture
async def intel(tmp_path):
    ti = ThreatIntel(tmp_path)
    await ti.refresh(transport=_transport())
    return ti


async def test_lookup_domain_lists(intel):
    assert [m.category for m in intel.lookup("http://malware-descargas.example/bot.exe")] == ["malware"]
    assert intel.lookup("https://sub.cdn.payload-evil.example/a")[0].matched == "cdn.payload-evil.example"
    assert intel.lookup("https://c2-server.example/")[0].source == "blackbook"
    assert intel.lookup("https://bcp-zonasegura.example/")[0].category == "phishing"


async def test_lookup_does_not_overmatch(intel):
    # Listar cdn.payload-evil.example no marca a su dominio padre ni a hermanos.
    assert intel.lookup("https://payload-evil.example/") == []
    assert intel.lookup("https://otro.payload-evil.example/") == []
    assert intel.lookup("https://www.google.com/") == []
    assert intel.lookup("javascript:alert(1)") == []


async def test_lookup_openphish_by_url(intel):
    assert intel.lookup("https://sites.example.app/login/paypal")[0].source == "OpenPhish"
    assert intel.lookup("http://WWW.EVIL-HOST.example/x.php?id=1")
    assert intel.lookup("https://sites.example.app/otra-pagina") == []   # solo la URL reportada


async def test_failed_download_keeps_disk_copy(tmp_path):
    ti = ThreatIntel(tmp_path)
    await ti.refresh(transport=_transport())
    fresh = ThreatIntel(tmp_path)                       # simula un reinicio sin red
    await fresh.refresh(transport=_transport(fail={f.name for f in FEEDS}))
    assert fresh.lookup("http://malware-descargas.example/")
    assert fresh.status()["URLhaus"]["entradas"] == 2


def test_heuristics_threat_and_virustotal_factors():
    m = threat_intel.Match("URLhaus", "malware", "malware-descargas.example")
    score, f = heuristics.evaluate("https://malware-descargas.example/", 0, 4000, threat_matches=[m])
    assert heuristics.risk_level(score) == "ALTO" and "malware" in f[0]["description"]

    vt = VTResult(malicious=12, suspicious=1, engines=90, permalink="x")
    assert heuristics.risk_level(heuristics.evaluate("https://x.example/", 0, 4000, virustotal=vt)[0]) == "ALTO"
    vt1 = VTResult(malicious=1, suspicious=0, engines=90, permalink="x")
    assert heuristics.risk_level(heuristics.evaluate("https://x.example/", 0, 4000, virustotal=vt1)[0]) == "MEDIO"
    clean = VTResult(malicious=0, suspicious=0, engines=90, permalink="x")
    assert heuristics.evaluate("https://x.example/", 0, 4000, virustotal=clean)[0] == 0


async def test_virustotal_client(monkeypatch):
    monkeypatch.setattr(config, "VIRUSTOTAL_API_KEY", "clave-de-prueba")
    threat_intel._vt_cache.clear()
    url = "http://malo.example/x"
    seen = {}

    def handler(request: httpx.Request):
        seen["key"] = request.headers["x-apikey"]
        seen["id"] = str(request.url).rsplit("/", 1)[-1]
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {
            "malicious": 7, "suspicious": 2, "harmless": 60, "undetected": 21}}}})

    r = await threat_intel.virustotal(url, transport=httpx.MockTransport(handler))
    assert (r.malicious, r.suspicious, r.engines) == (7, 2, 90)
    assert seen["key"] == "clave-de-prueba"
    assert seen["id"] == base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


async def test_virustotal_disabled_without_key(monkeypatch):
    monkeypatch.setattr(config, "VIRUSTOTAL_API_KEY", "")
    assert await threat_intel.virustotal("http://x.example/") is None


def test_api_listed_url_is_not_visited(client, monkeypatch):  # noqa: F811
    """Una URL reportada se califica ALTO sin conectarse a ella (ni resolver su DNS)."""
    ti = ThreatIntel(threat_intel.intel.cache_dir)
    ti.domains["URLhaus"] = {"malware-descargas.example"}
    monkeypatch.setattr(threat_intel, "intel", ti)

    async def must_not_expand(url, transport=None):
        raise AssertionError("no debe visitar una URL de malware conocida")

    monkeypatch.setattr(resolver, "expand", must_not_expand)
    body = client.post("/api/v1/expand", json={"url": "malware-descargas.example/bot.exe"}).json()
    assert body["risk_level"] == "ALTO"
    assert body["threat_intel"]["destination_visited"] is False
    assert body["threat_intel"]["matches"][0]["category"] == "malware"
    api.cache.clear()


async def test_feed_update_notifies_only_when_content_changes(tmp_path):
    ti = ThreatIntel(tmp_path)
    calls = []
    ti.on_update.append(calls.append)
    await ti.refresh(transport=_transport())      # primera carga: no hay "antes" con qué comparar
    await ti.refresh(transport=_transport())      # mismo contenido: no se avisa
    assert calls == []
    BODIES["URLhaus"] = URLHAUS + "nuevo-malware.example\n"
    try:
        await ti.refresh(transport=_transport())
    finally:
        BODIES["URLhaus"] = URLHAUS
    assert calls == [["URLhaus"]]


def test_cache_cleared_when_feeds_update(client):  # noqa: F811
    client.post("/api/v1/expand", json={"url": "https://bit.ly/abc"})
    assert len(api.cache) == 1
    api._on_feeds_updated(["URLhaus"])
    assert len(api.cache) == 0
    body = client.post("/api/v1/expand", json={"url": "https://bit.ly/abc"}).json()
    assert body["cached"] is False


def test_cached_result_rechecked_against_current_lists(client, monkeypatch):  # noqa: F811
    """Guardado como limpio, pero el destino entra luego a una lista: no se sirve el resultado viejo."""
    first = client.post("/api/v1/expand", json={"url": "https://bit.ly/abc"}).json()
    assert first["threat_intel"]["matches"] == [] and first["cache_expires_in_s"] == api.cache.ttl
    second = client.post("/api/v1/expand", json={"url": "https://bit.ly/abc"}).json()
    assert second["cached"] is True and 0 < second["cache_expires_in_s"] <= api.cache.ttl
    assert second["analyzed_at"] == first["analyzed_at"]

    ti = ThreatIntel(threat_intel.intel.cache_dir)
    ti.domains["URLhaus"] = {"destino.example"}           # el destino de fake_expand
    monkeypatch.setattr(threat_intel, "intel", ti)
    third = client.post("/api/v1/expand", json={"url": "https://bit.ly/abc"}).json()
    assert third["cached"] is False and third["risk_level"] == "ALTO"
    api.cache.clear()


def test_api_flags_malware_hop_in_chain(client, monkeypatch):  # noqa: F811
    """Un acortador limpio que redirige a un dominio de malware se marca por el salto."""
    ti = ThreatIntel(threat_intel.intel.cache_dir)
    ti.domains["blackbook"] = {"c2-server.example"}
    monkeypatch.setattr(threat_intel, "intel", ti)

    async def fake_expand(url, transport=None):
        return resolver.Expansion(final_url="https://c2-server.example/p", chain=[url, "https://c2-server.example/p"])

    monkeypatch.setattr(resolver, "expand", fake_expand)
    body = client.post("/api/v1/expand", json={"url": "https://bit.ly/limpio"}).json()
    assert body["risk_level"] == "ALTO" and body["threat_intel"]["destination_visited"] is True
    api.cache.clear()
