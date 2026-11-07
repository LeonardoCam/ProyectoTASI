import httpx
import pytest

from app import config, resolver, security


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    real = security._resolve

    async def fake(host, port):
        if host.endswith(".test"):
            return ["93.184.216.34"]
        return await real(host, port)

    monkeypatch.setattr(security, "_resolve", fake)


def transport(routes):
    def handler(request: httpx.Request):
        status, location = routes[str(request.url)]
        return httpx.Response(status, headers={"location": location} if location else {})
    return httpx.MockTransport(handler)


async def test_follows_chain():
    t = transport({
        "https://a.test/x": (301, "https://b.test/y"),
        "https://b.test/y": (302, "/z"),
        "https://b.test/z": (200, None),
    })
    exp = await resolver.expand("https://a.test/x", transport=t)
    assert exp.final_url == "https://b.test/z"
    assert exp.hops == 2
    assert exp.chain == ["https://a.test/x", "https://b.test/y", "https://b.test/z"]


async def test_detects_loop():
    t = transport({"https://a.test/": (302, "https://b.test/"), "https://b.test/": (302, "https://a.test/")})
    with pytest.raises(resolver.RedirectLoopError):
        await resolver.expand("https://a.test/", transport=t)


async def test_too_many_redirects(monkeypatch):
    monkeypatch.setattr(config, "MAX_REDIRECTS", 3)
    routes = {f"https://h{i}.test/": (302, f"https://h{i+1}.test/") for i in range(20)}
    with pytest.raises(resolver.TooManyRedirectsError):
        await resolver.expand("https://h0.test/", transport=transport(routes))


async def test_redirect_to_internal_is_blocked():
    """Ataque SSRF clásico: un enlace público redirige hacia metadatos cloud/red interna."""
    t = transport({"https://evil.test/": (302, "http://169.254.169.254/latest/meta-data/")})
    with pytest.raises(security.UnsafeURLError) as e:
        await resolver.expand("https://evil.test/", transport=t)
    assert e.value.code == "blocked_address"


async def test_redirect_to_other_scheme_is_blocked():
    t = transport({"https://evil.test/": (302, "file:///etc/passwd")})
    with pytest.raises(security.UnsafeURLError):
        await resolver.expand("https://evil.test/", transport=t)


async def test_invalid_punycode_location_is_controlled_error():
    """Regresión: un Location con punycode inválido no debe producir un 500 sin control."""
    t = transport({"https://a.test/": (302, "https://xn--bad-.com/")})
    with pytest.raises(resolver.UpstreamError):
        await resolver.expand("https://a.test/", transport=t)
