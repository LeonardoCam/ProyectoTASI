import pytest
from fastapi.testclient import TestClient

from app import api, domain_info, resolver, security


@pytest.fixture
def client(monkeypatch):
    api.cache.clear()
    api.limiter._hits.clear()
    calls = {"expand": 0}

    async def fake_resolve(host, port):
        return ["93.184.216.34"]

    async def fake_expand(url, transport=None):
        calls["expand"] += 1
        return resolver.Expansion(final_url="https://destino.example/", chain=[url, "https://destino.example/"], status_code=200)

    async def fake_age(domain):
        return 10

    monkeypatch.setattr(security, "_resolve", fake_resolve)
    monkeypatch.setattr(resolver, "expand", fake_expand)
    monkeypatch.setattr(domain_info, "domain_age_days", fake_age)
    c = TestClient(api.app)
    c.calls = calls
    return c


def test_expand_ok_and_explains(client):
    r = client.post("/api/v1/expand", json={"url": "https://bit.ly/abc"})
    body = r.json()
    assert r.status_code == 200
    assert body["final_url"] == "https://destino.example/" and body["hops"] == 1
    assert body["risk_level"] == "MEDIO" and body["risk_score"] == 40
    assert body["cached"] is False and body["factors"]  # resultados Medio/Alto siempre justificados


def test_second_request_hits_cache(client):
    client.post("/api/v1/expand", json={"url": "https://bit.ly/abc"})
    body = client.post("/api/v1/expand", json={"url": "https://bit.ly/abc"}).json()
    assert body["cached"] is True and client.calls["expand"] == 1


@pytest.mark.parametrize("url", ["http://127.0.0.1/", "http://169.254.169.254/", "ftp://x.com", "http://2130706433/"])
def test_ssrf_returns_400_with_code(client, monkeypatch, url):
    monkeypatch.undo()  # usar DNS real para IPs numéricas
    api.cache.clear()
    r = client.post("/api/v1/expand", json={"url": url})
    assert r.status_code == 400 and r.json()["detail"]["code"] in ("blocked_address", "scheme_not_allowed")


def test_rate_limit(client, monkeypatch):
    monkeypatch.setattr(api.limiter, "per_minute", 2)
    codes = [client.post("/api/v1/expand", json={"url": "https://bit.ly/abc"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_health(client):
    assert client.get("/api/v1/health").json()["status"] == "ok"
