"""Controles anti-SSRF y validación de URLs (OWASP SSRF, RFC 3986).

Cada salto de la cadena de redirección se valida con `assert_safe_url`, que devuelve las IPs
validadas para que el resolver se conecte EXACTAMENTE a ellas (IP fijada: evita DNS rebinding).

Resolución DNS: primero DNS público cifrado (DNS-over-HTTPS de Cloudflare y Google) y, si no
responde, el DNS del sistema. Así el análisis ve lo mismo que una víctima en internet y no lo que
devuelva el DNS de la red local (p. ej. una intranet que resuelve su dominio a IPs privadas).
"""
import asyncio
import ipaddress
import socket
from typing import Optional
from urllib.parse import urlsplit

import httpx
import idna

from . import config
from .net import SSL_CONTEXT
from .cache import TTLCache


class UnsafeURLError(Exception):
    """La URL fue rechazada por política de seguridad. `code` es estable para el cliente."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class DomainNotFound(Exception):
    """El nombre no existe en DNS (NXDOMAIN) o no tiene direcciones."""


DOH_SERVERS = ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve")
_dns_cache = TTLCache(ttl=300)
# Nombres que nunca son públicos: se bloquean sin consultar DNS.
_LOCAL_NAMES = ("localhost", ".localhost", ".local", ".internal", ".lan", ".home.arpa", ".intranet")


def _is_public(ip: ipaddress._BaseAddress) -> bool:
    # is_global excluye privadas, loopback, link-local (169.254.169.254), CGNAT, reservadas, etc.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def parse_numeric_ipv4(host: str) -> Optional[str]:
    """Interpreta formas numéricas de IPv4 como inet_aton: 2130706433, 0177.0.0.1, 0x7f.1...

    glibc las acepta al conectar, Windows no; por eso se convierten aquí y no se deja al sistema.
    """
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or not all(parts):
        return None
    nums = []
    for p in parts:
        try:
            if p.lower().startswith("0x"):
                nums.append(int(p, 16))
            elif len(p) > 1 and p.startswith("0"):
                nums.append(int(p, 8))
            else:
                nums.append(int(p, 10))
        except ValueError:
            return None
    # Las primeras partes son bytes; la última ocupa los bytes restantes (a.b.c.d / a.b.c / a.b / a)
    if any(n > 255 for n in nums[:-1]) or nums[-1] >= 256 ** (5 - len(nums)):
        return None
    value = 0
    for n in nums[:-1]:
        value = value * 256 + n
    value = value * 256 ** (5 - len(nums)) + nums[-1]
    return str(ipaddress.IPv4Address(value))


def to_ascii_host(host: str) -> str:
    """Dominio en ASCII para DNS (IDNA 2008 + UTS46): 'ñandú.pe' -> 'xn--and-6ma2c.pe'."""
    host = host.strip(".").lower()
    if host.isascii():
        return host
    try:
        return idna.encode(host, uts46=True).decode()
    except idna.IDNAError:
        raise UnsafeURLError("invalid_url", "El dominio contiene caracteres no válidos.")


async def _doh(host: str, rtype: str, client: httpx.AsyncClient, server: str) -> tuple[int, list[str]]:
    r = await client.get(server, params={"name": host, "type": rtype}, headers={"accept": "application/dns-json"})
    r.raise_for_status()
    data = r.json()
    want = 1 if rtype == "A" else 28
    return int(data.get("Status", 2)), [a["data"] for a in data.get("Answer", []) if a.get("type") == want]


async def _resolve_doh(host: str) -> Optional[list[str]]:
    """IPs por DNS-over-HTTPS; [] si el nombre no existe; None si ningún servidor respondió."""
    async with httpx.AsyncClient(timeout=config.DNS_TIMEOUT, verify=SSL_CONTEXT) as client:
        for server in DOH_SERVERS:
            try:
                (st4, a), (st6, aaaa) = await asyncio.gather(
                    _doh(host, "A", client, server), _doh(host, "AAAA", client, server))
            except Exception:
                continue  # probar el siguiente servidor
            if st4 in (0, 3):     # NOERROR o NXDOMAIN: respuesta definitiva (puede venir vacía)
                return a + (aaaa if st6 == 0 else [])
    return None


async def _resolve_system(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        # Con límite de tiempo: getaddrinfo corre en el grupo de hilos compartido y, si este se
        # llena, la espera sería indefinida.
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=config.DNS_TIMEOUT)
    except (socket.gaierror, asyncio.TimeoutError):
        return []
    return list(dict.fromkeys(info[4][0] for info in infos))


async def _resolve(host: str, port: int) -> list[str]:
    """Resuelve `host` (ASCII). Lanza DomainNotFound si no existe; UnsafeURLError si el DNS falla."""
    cached = _dns_cache.get(host)
    if cached is not None:
        return cached[0]
    ips: Optional[list[str]] = None
    if config.DNS_USE_DOH:
        ips = await _resolve_doh(host)
    if ips is None:  # DoH desactivado o caído: DNS del sistema
        ips = await _resolve_system(host, port)
    if not ips:
        raise DomainNotFound(host)
    _dns_cache.set(host, (ips,))
    return ips


async def assert_safe_url(url: str) -> list[str]:
    """Lanza UnsafeURLError si la URL no es segura de consultar; devuelve las IPs validadas."""
    if not url or len(url) > config.MAX_URL_LENGTH:
        raise UnsafeURLError("invalid_url", "URL vacía o demasiado larga.")
    if any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise UnsafeURLError("invalid_url", "La URL contiene espacios o caracteres de control.")

    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise UnsafeURLError("invalid_url", "URL malformada.")

    if parts.scheme not in ("http", "https"):
        raise UnsafeURLError("scheme_not_allowed", "Solo se permiten URLs http:// o https://.")
    if not parts.hostname:
        raise UnsafeURLError("invalid_url", "La URL no contiene un host.")
    if parts.username or parts.password:
        raise UnsafeURLError("credentials_in_url", "No se permiten credenciales dentro de la URL.")

    port = port or (443 if parts.scheme == "https" else 80)
    if port not in config.ALLOWED_PORTS:
        raise UnsafeURLError("port_not_allowed", f"Puerto {port} no permitido.")

    blocked = UnsafeURLError(
        "blocked_address", "Destino bloqueado: apunta a una dirección privada, local o reservada.")
    host = parts.hostname.strip(".")
    if host == "localhost" or host.endswith(_LOCAL_NAMES):
        raise blocked

    # IP literal (incluidas formas decimal/octal/hex) -> no hace falta DNS
    literal = None
    try:
        literal = str(ipaddress.ip_address(host))
    except ValueError:
        literal = parse_numeric_ipv4(host)
    if literal is not None:
        addresses = [literal]
    else:
        # "hola", "x", "a..com", "-a.com": no es un dominio; no tiene sentido consultar el DNS.
        labels = host.split(".")
        if (len(labels) < 2 or len(host) > 253
                or any(not lab or len(lab) > 63 or lab.startswith("-") or lab.endswith("-") for lab in labels)):
            raise UnsafeURLError("invalid_url", "Eso no parece un enlace válido (ejemplo: bit.ly/abc o www.sitio.com).")
        try:
            addresses = await _resolve(to_ascii_host(host), port)
        except DomainNotFound:
            raise UnsafeURLError("domain_not_found", "El dominio no existe (no tiene registros DNS).")
        except (socket.gaierror, UnicodeError):
            raise UnsafeURLError("dns_failure", "No se pudo resolver el dominio.")

    if not addresses:
        raise UnsafeURLError("dns_failure", "No se pudo resolver el dominio.")
    for addr in addresses:
        try:
            ip = ipaddress.ip_address(addr.split("%")[0])
        except ValueError:
            raise UnsafeURLError("blocked_address", "Dirección de destino no válida.")
        if not _is_public(ip):
            raise blocked
    return addresses
