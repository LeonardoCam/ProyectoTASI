"""Expansión asíncrona de redirecciones HTTP (RFC 9110: 301, 302, 303, 307, 308).

Se siguen los saltos manualmente para validar CADA destino contra SSRF antes de conectar,
detectar bucles y no descargar el cuerpo de las respuestas.
"""
import random
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

import httpx

from . import config
from .net import SSL_CONTEXT
from .security import UnsafeURLError, assert_safe_url

REDIRECT_CODES = {301, 302, 303, 307, 308}


class RedirectLoopError(Exception):
    pass


class TooManyRedirectsError(Exception):
    pass


class UpstreamError(Exception):
    pass


class UpstreamTimeout(UpstreamError):
    """El destino no contestó a tiempo (a diferencia de rechazar la conexión al instante)."""


@dataclass
class Expansion:
    final_url: str
    chain: list[str] = field(default_factory=list)   # URLs visitadas, incluida la inicial y la final
    status_code: Optional[int] = None
    title: Optional[str] = None
    security_headers: dict[str, bool] = field(default_factory=dict)
    content_disposition: Optional[str] = None

    @property
    def hops(self) -> int:
        return max(len(self.chain) - 1, 0)


def _pinned(url: str, ips: list[str]) -> tuple[httpx.URL, dict, dict]:
    """URL dirigida a la IP validada, conservando Host, SNI y la verificación del certificado."""
    u = httpx.URL(url)
    ip = next((a for a in ips if ":" not in a), ips[0])  # preferir IPv4: más redes la soportan
    pinned = u.copy_with(host=ip)
    host_header = u.raw_host.decode() + (f":{u.port}" if u.port else "")
    ext = {"sni_hostname": u.raw_host.decode()} if u.scheme == "https" else {}
    return pinned, {"Host": host_header}, ext


async def expand(url: str, transport: Optional[httpx.AsyncBaseTransport] = None) -> Expansion:
    headers = {
        "User-Agent": random.choice(config.USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    }
    chain = [url]
    seen = {url}
    current = url

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=config.REQUEST_TIMEOUT,
        headers=headers,
        transport=transport,
        trust_env=False,
        verify=SSL_CONTEXT,   # contexto TLS compartido: crear el cliente no bloquea el servidor
    ) as client:
        for _ in range(config.MAX_REDIRECTS + 1):
            ips = await assert_safe_url(current)  # validación SSRF en cada salto
            # Con la red real se conecta a la IP ya validada (no se vuelve a resolver el nombre):
            # cierra el DNS rebinding y usa el DNS público aunque el de la red local difiera.
            req_url, extra_headers, extensions = (
                _pinned(current, ips) if transport is None and ips else (current, {}, {}))
            try:
                # stream=True: solo cabeceras, el cuerpo nunca se descarga
                async with client.stream("GET", req_url, headers=extra_headers, extensions=extensions) as resp:
                    status = resp.status_code
                    location = resp.headers.get("location")
            except httpx.TimeoutException:
                raise UpstreamTimeout("Tiempo de espera agotado al resolver el enlace.")
            except (httpx.HTTPError, httpx.InvalidURL, UnicodeError, ValueError):
                # incluye Location malformado o con punycode inválido (httpx lo valida al construir el salto)
                raise UpstreamError("No se pudo conectar con el destino.")

            if status in REDIRECT_CODES and location:
                nxt = urljoin(current, location)
                if nxt in seen:
                    raise RedirectLoopError("Bucle de redirección detectado.")
                seen.add(nxt)
                chain.append(nxt)
                current = nxt
                continue

            # Extracción segura de título HTML (primeros 4 KB de la respuesta final, sin descargar archivos grandes)
            title = None
            try:
                ctype = resp.headers.get("content-type", "").lower()
                if "text/html" in ctype or not ctype:
                    chunk = await anext(resp.aiter_bytes(), b"")
                    if chunk:
                        text = chunk[:4096].decode("utf-8", errors="replace")
                        m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
                        if m:
                            title = " ".join(m.group(1).split())[:120]
            except Exception:
                pass

            # Inspección de cabeceras de seguridad y descarga
            sec_headers = {
                "hsts": "strict-transport-security" in resp.headers,
                "csp": "content-security-policy" in resp.headers,
                "x_frame_options": "x-frame-options" in resp.headers,
                "x_content_type_options": "x-content-type-options" in resp.headers,
            }
            cdisp = resp.headers.get("content-disposition")

            return Expansion(
                final_url=current,
                chain=chain,
                status_code=status,
                title=title,
                security_headers=sec_headers,
                content_disposition=cdisp,
            )

    raise TooManyRedirectsError(f"La cadena supera el máximo de {config.MAX_REDIRECTS} saltos.")
