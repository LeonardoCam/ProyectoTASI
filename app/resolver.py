"""Expansión asíncrona de redirecciones HTTP (RFC 9110: 301, 302, 303, 307, 308).

Se siguen los saltos manualmente para validar CADA destino contra SSRF antes de conectar,
detectar bucles y no descargar el cuerpo de las respuestas.
"""
import random
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

import httpx

from . import config
from .security import UnsafeURLError, assert_safe_url

REDIRECT_CODES = {301, 302, 303, 307, 308}


class RedirectLoopError(Exception):
    pass


class TooManyRedirectsError(Exception):
    pass


class UpstreamError(Exception):
    pass


@dataclass
class Expansion:
    final_url: str
    chain: list[str] = field(default_factory=list)   # URLs visitadas, incluida la inicial y la final
    status_code: Optional[int] = None

    @property
    def hops(self) -> int:
        return max(len(self.chain) - 1, 0)


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
    ) as client:
        for _ in range(config.MAX_REDIRECTS + 1):
            await assert_safe_url(current)  # validación SSRF en cada salto
            try:
                # stream=True: solo cabeceras, el cuerpo nunca se descarga
                async with client.stream("GET", current) as resp:
                    status = resp.status_code
                    location = resp.headers.get("location")
            except httpx.TimeoutException:
                raise UpstreamError("Tiempo de espera agotado al resolver el enlace.")
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
            return Expansion(final_url=current, chain=chain, status_code=status)

    raise TooManyRedirectsError(f"La cadena supera el máximo de {config.MAX_REDIRECTS} saltos.")
