"""Resolución DNS robusta: DoH, IPs numéricas, IDN, www, dominios inexistentes y limpieza de entrada."""
import httpx
import pytest

from app import api, config, resolver, security
from app.normalize import normalize_url
from app.security import DomainNotFound, UnsafeURLError, assert_safe_url, parse_numeric_ipv4, to_ascii_host
from test_api import client  # noqa: F401  (reutiliza el fixture de test_api.py)


@pytest.mark.parametrize("host,ip", [
    ("2130706433", "127.0.0.1"), ("0177.0.0.1", "127.0.0.1"), ("0x7f.0.0.1", "127.0.0.1"),
    ("0x7f000001", "127.0.0.1"), ("127.1", "127.0.0.1"), ("3232235777", "192.168.1.1"),
    ("8.8.8.8", "8.8.8.8"),
])
def test_numeric_ipv4_forms(host, ip):
    assert parse_numeric_ipv4(host) == ip


@pytest.mark.parametrize("host", ["example.com", "999.1.1.1", "1.2.3.4.5", "0x", "08.1.1.1", "4294967296"])
def test_numeric_ipv4_rejects_non_ips(host):
    assert parse_numeric_ipv4(host) is None


def test_idn_hosts_to_ascii():
    assert to_ascii_host("münchen.de") == "xn--mnchen-3ya.de"
    assert to_ascii_host("ÑANDÚ.pe") == to_ascii_host("ñandú.pe")
    assert to_ascii_host("Example.COM.") == "example.com"


@pytest.mark.parametrize("raw,expected", [
    ("<https://example.com>", "https://example.com"),
    ("https://example.com,", "https://example.com"),
    ("bit.ly/abc).", "https://bit.ly/abc"),
    ("(ver bit.ly/abc)", "https://bit.ly/abc"),          # paréntesis de un mensaje
    ('"https://x.com/a"', "https://x.com/a"),
    ("https://EXAMPLE.com.", "https://EXAMPLE.com"),
    ("https://es.wikipedia.org/wiki/Lima_(Perú)", "https://es.wikipedia.org/wiki/Lima_(Perú)"),  # paréntesis propios
    ("«www.sitio.pe»", "https://www.sitio.pe"),
    ("Mira esto: bit.ly/abc gana premios!!", "https://bit.ly/abc"),   # frase pegada de un chat
    ("Tu cuenta fue bloqueada, entra a https://bcp-seguro.xyz/login.", "https://bcp-seguro.xyz/login"),
    ("revisa hxxps://evil[.]com/x por favor", "https://evil.com/x"),
])
def test_strips_pasted_punctuation(raw, expected):
    assert normalize_url(raw)[0] == expected


async def test_doh_resolution_and_nxdomain(monkeypatch):
    """DoH: respuesta válida -> IPs; NXDOMAIN -> DomainNotFound; servidor caído -> el siguiente."""
    security._dns_cache.clear()
    calls = []

    def handler(request: httpx.Request):
        calls.append(request.url.host)
        if request.url.host == "cloudflare-dns.com":
            return httpx.Response(503)                      # primer servidor caído
        name, rtype = request.url.params["name"], request.url.params["type"]
        if name == "noexiste.example":
            return httpx.Response(200, json={"Status": 3})
        ans = [{"type": 5, "data": "cdn.example."}]         # CNAME: se ignora
        ans += [{"type": 1, "data": "93.184.216.34"}] if rtype == "A" else [{"type": 28, "data": "2606:2800::1"}]
        return httpx.Response(200, json={"Status": 0, "Answer": ans})

    real_client = httpx.AsyncClient
    monkeypatch.setattr(security.httpx, "AsyncClient",
                        lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
    assert await security._resolve("ok.example", 443) == ["93.184.216.34", "2606:2800::1"]
    assert "dns.google" in calls
    with pytest.raises(DomainNotFound):
        await security._resolve("noexiste.example", 443)


async def test_falls_back_to_system_dns_when_doh_unreachable(monkeypatch):
    security._dns_cache.clear()

    async def doh_down(host):
        return None

    async def system(host, port):
        return ["93.184.216.34"]

    monkeypatch.setattr(security, "_resolve_doh", doh_down)
    monkeypatch.setattr(security, "_resolve_system", system)
    assert await security._resolve("sitio.example", 443) == ["93.184.216.34"]


async def test_local_names_blocked_without_dns(monkeypatch):
    async def boom(host, port):
        raise AssertionError("no debe consultar DNS")

    monkeypatch.setattr(security, "_resolve", boom)
    for url in ("http://localhost/", "http://printer.local/", "http://db.internal/", "http://2130706433/"):
        with pytest.raises(UnsafeURLError) as e:
            await assert_safe_url(url)
        assert e.value.code == "blocked_address"


async def test_not_found_code(monkeypatch):
    async def nx(host, port):
        raise DomainNotFound(host)

    monkeypatch.setattr(security, "_resolve", nx)
    with pytest.raises(UnsafeURLError) as e:
        await assert_safe_url("https://noexiste.example/")
    assert e.value.code == "domain_not_found"


def test_pinned_request_keeps_host_and_sni():
    url, headers, ext = resolver._pinned("https://www.example.com/a?b=1", ["2606:2800::1", "93.184.216.34"])
    assert str(url) == "https://93.184.216.34/a?b=1"           # prefiere IPv4
    assert headers == {"Host": "www.example.com"} and ext == {"sni_hostname": "www.example.com"}
    url, headers, ext = resolver._pinned("http://münchen.de/", ["194.246.166.100"])
    assert headers == {"Host": "xn--mnchen-3ya.de"} and ext == {}


def _dns(table):
    async def fake(host, port):
        if host in table:
            return table[host]
        raise DomainNotFound(host)
    return fake


def test_api_tries_www_variant(client, monkeypatch):  # noqa: F811
    monkeypatch.setattr(security, "_resolve", _dns({"www.sunat.example": ["93.184.216.34"]}))
    body = client.post("/api/v1/expand", json={"url": "sunat.example"}).json()
    assert body["original_url"] == "https://www.sunat.example"
    assert body["domain_exists"] is True and "www.sunat.example" in body["dns_note"]
    api.cache.clear()


def test_api_analyzes_nonexistent_domain_instead_of_error(client, monkeypatch):  # noqa: F811
    monkeypatch.setattr(security, "_resolve", _dns({}))

    async def must_not_expand(url, transport=None):
        raise AssertionError("no hay nada que visitar")

    monkeypatch.setattr(resolver, "expand", must_not_expand)
    r = client.post("/api/v1/expand", json={"url": "paypal-verify-cuenta.example/login"})
    body = r.json()
    assert r.status_code == 200 and body["domain_exists"] is False
    ids = {f["id"] for f in body["factors"]}
    assert {"domain_not_found", "brand_impersonation", "keywords"} <= ids
    assert body["risk_level"] in ("MEDIO", "ALTO")
    api.cache.clear()


@pytest.mark.parametrize("url", ["https://hola", "https://x", "https://a..com", "https://-a.com", "https://a-.com"])
async def test_text_that_is_not_a_domain_is_invalid(url, monkeypatch):
    async def boom(host, port):
        raise AssertionError("no debe consultar DNS")

    monkeypatch.setattr(security, "_resolve", boom)
    with pytest.raises(UnsafeURLError) as e:
        await assert_safe_url(url)
    assert e.value.code == "invalid_url"


def test_api_redirect_loop_is_analyzed_not_error(client, monkeypatch):  # noqa: F811
    async def looping(url, transport=None):
        raise resolver.RedirectLoopError("Bucle de redirección detectado.")

    monkeypatch.setattr(resolver, "expand", looping)
    r = client.post("/api/v1/expand", json={"url": "https://bucle.example/"})
    body = r.json()
    assert r.status_code == 200 and body["reachable"] is False
    assert "redirect_loop" in {f["id"] for f in body["factors"]}
    api.cache.clear()


def test_api_no_http_retry_after_https_timeout(client, monkeypatch):  # noqa: F811
    tried = []

    async def slow(url, transport=None):
        tried.append(url)
        raise resolver.UpstreamTimeout("Tiempo de espera agotado al resolver el enlace.")

    monkeypatch.setattr(resolver, "expand", slow)
    body = client.post("/api/v1/expand", json={"url": "lento.example"}).json()
    assert tried == ["https://lento.example"] and body["reachable"] is False
    api.cache.clear()


def test_doh_can_be_disabled(monkeypatch):
    monkeypatch.setattr(config, "DNS_USE_DOH", False)
    assert config.DNS_USE_DOH is False
