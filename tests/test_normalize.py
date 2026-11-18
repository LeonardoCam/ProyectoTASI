import pytest

from app import api, resolver
from app.normalize import normalize_url
from test_api import client  # noqa: F401  (reutiliza el fixture de test_api.py)


@pytest.mark.parametrize("raw,expected,added", [
    ("bit.ly/abc", "https://bit.ly/abc", True),
    ("www.google.com", "https://www.google.com", True),
    ("  tinyurl.com/x  ", "https://tinyurl.com/x", True),
    ("//bit.ly/abc", "https://bit.ly/abc", True),
    ("example.com:443/a", "https://example.com:443/a", True),
    ("https://bit.ly/abc", "https://bit.ly/abc", False),
    ("HTTP://Bit.ly/abc", "HTTP://Bit.ly/abc", False),
    ("hxxps://bit[.]ly/abc", "https://bit.ly/abc", False),
    ("hxxp://evil(.)com/login", "http://evil.com/login", False),
    ("https[:]//phish[.]example/x", "https://phish.example/x", False),
    ("bit[dot]ly/abc", "https://bit.ly/abc", True),
])
def test_normalize(raw, expected, added):
    assert normalize_url(raw) == (expected, added)


@pytest.mark.parametrize("raw", ["javascript:alert(1)", "file:///etc/passwd", "data:text/html,x", "mailto:a@b.com"])
def test_dangerous_schemes_untouched(raw):
    assert normalize_url(raw) == (raw, False)


def test_api_accepts_url_without_scheme(client):  # noqa: F811
    body = client.post("/api/v1/expand", json={"url": "bit.ly/abc"}).json()
    assert body["input_url"] == "bit.ly/abc"
    assert body["original_url"] == "https://bit.ly/abc"


def test_api_falls_back_to_http(client, monkeypatch):  # noqa: F811
    tried = []

    async def fake_expand(url, transport=None):
        tried.append(url)
        if url.startswith("https://"):
            raise resolver.UpstreamError("No se pudo conectar con el destino.")
        return resolver.Expansion(final_url=url, chain=[url], status_code=200)

    monkeypatch.setattr(resolver, "expand", fake_expand)
    body = client.post("/api/v1/expand", json={"url": "solo-http.example/x"}).json()
    assert tried == ["https://solo-http.example/x", "http://solo-http.example/x"]
    assert body["original_url"] == "http://solo-http.example/x"


def test_api_no_fallback_when_scheme_given(client, monkeypatch):  # noqa: F811
    async def fake_expand(url, transport=None):
        raise resolver.UpstreamError("No se pudo conectar con el destino.")

    monkeypatch.setattr(resolver, "expand", fake_expand)
    r = client.post("/api/v1/expand", json={"url": "https://caido.example/"})
    # Sin reintento por http (el usuario escribió https) y, en vez de un error, un análisis sin visita.
    body = r.json()
    assert r.status_code == 200 and body["reachable"] is False and body["original_url"] == "https://caido.example/"
    assert body["threat_intel"]["destination_visited"] is False and "no respondió" in body["dns_note"]


def test_api_still_blocks_javascript_scheme(client):  # noqa: F811
    r = client.post("/api/v1/expand", json={"url": "javascript:alert(1)"})
    assert r.status_code == 400 and r.json()["detail"]["code"] == "scheme_not_allowed"
    api.cache.clear()
