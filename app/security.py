"""Controles anti-SSRF y validación de URLs (OWASP SSRF, RFC 3986).

Cada salto de la cadena de redirección se valida con `assert_safe_url`.
"""
import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

from . import config


class UnsafeURLError(Exception):
    """La URL fue rechazada por política de seguridad. `code` es estable para el cliente."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _is_public(ip: ipaddress._BaseAddress) -> bool:
    # is_global excluye privadas, loopback, link-local (169.254.169.254), CGNAT, reservadas, etc.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


async def _resolve(host: str, port: int) -> list[str]:
    """Resuelve el host (incluye formas numéricas decimal/octal/hex que getaddrinfo normaliza)."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list({info[4][0] for info in infos})


async def assert_safe_url(url: str) -> None:
    """Lanza UnsafeURLError si la URL no es segura de consultar."""
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

    host = parts.hostname
    try:
        addresses = await _resolve(host, port)
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
            raise UnsafeURLError(
                "blocked_address",
                "Destino bloqueado: apunta a una dirección privada, local o reservada.",
            )
