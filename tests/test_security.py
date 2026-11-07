import pytest

from app import security
from app.security import UnsafeURLError, assert_safe_url


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    """DNS sin red: dominios de prueba -> IP pública; IPs numéricas las normaliza getaddrinfo real."""
    real = security._resolve

    async def fake(host, port):
        if host in ("example.com", "bit.ly"):
            return ["93.184.216.34"]
        if host == "rebind.test":
            return ["93.184.216.34", "127.0.0.1"]
        return await real(host, port)

    monkeypatch.setattr(security, "_resolve", fake)


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://localhost/", "http://[::1]/", "http://10.0.0.5/",
    "http://192.168.1.1/", "http://172.16.0.1/", "http://169.254.169.254/latest/meta-data/",
    "http://2130706433/",          # 127.0.0.1 en decimal
    "http://0177.0.0.1/",          # octal
    "http://0x7f.0.0.1/",          # hexadecimal
    "http://0.0.0.0/", "http://100.64.0.1/", "http://[::ffff:127.0.0.1]/",
    "http://rebind.test/",         # un registro DNS público + uno interno
])
async def test_blocks_internal_targets(url):
    with pytest.raises(UnsafeURLError) as e:
        await assert_safe_url(url)
    assert e.value.code == "blocked_address"


@pytest.mark.parametrize("url,code", [
    ("ftp://example.com/", "scheme_not_allowed"),
    ("file:///etc/passwd", "scheme_not_allowed"),
    ("javascript:alert(1)", "scheme_not_allowed"),
    ("http://user:pass@example.com/", "credentials_in_url"),
    ("http://example.com:22/", "port_not_allowed"),
    ("http://example.com:6379/", "port_not_allowed"),
    ("https://exa mple.com/", "invalid_url"),
    ("http://", "invalid_url"),
    ("https://example.com/" + "a" * 3000, "invalid_url"),
])
async def test_rejects_invalid(url, code):
    with pytest.raises(UnsafeURLError) as e:
        await assert_safe_url(url)
    assert e.value.code == code


async def test_allows_public():
    await assert_safe_url("https://example.com/path?q=1")
    await assert_safe_url("http://8.8.8.8/")
