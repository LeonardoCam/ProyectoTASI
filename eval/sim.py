"""Entorno simulado reutilizable: DNS, WHOIS y web falsos para evaluar el pipeline REAL sin red.

El motor (validación SSRF, resolución de saltos, heurística, caché, API) es el código de producción;
solo se sustituyen las tres fronteras de red: DNS, servidores HTTP y WHOIS.
"""
import asyncio
import random

import httpx

from app import domain_info, resolver, security

RTT_PER_HOP = 0.06   # s, red simulada
WHOIS_DELAY = 0.15   # s, WHOIS simulado


class World:
    def __init__(self):
        self.routes: dict[str, tuple[int, str | None]] = {}   # url -> (status, location)
        self.ages: dict[str, int | None] = {}                  # dominio registrable -> días
        self.delay = True

    def add_chain(self, urls: list[str], final_status: int = 200):
        for a, b in zip(urls, urls[1:]):
            self.routes[a] = (302 if random.random() < .5 else 301, b)
        self.routes[urls[-1]] = (final_status, None)

    def transport(self):
        async def handler(request: httpx.Request):
            if self.delay:
                await asyncio.sleep(RTT_PER_HOP)
            url = str(request.url)
            if url not in self.routes:
                raise httpx.ConnectError("sin ruta", request=request)
            status, loc = self.routes[url]
            return httpx.Response(status, headers={"location": loc} if loc else {})
        return httpx.MockTransport(handler)

    def install(self, monkeypatch=None):
        """Parchea DNS/WHOIS/transporte. Devuelve función de restauración."""
        world = self
        orig_resolve = security._resolve
        orig_expand = resolver.expand
        orig_age = domain_info.domain_age_days

        async def fake_dns(host, port):
            import re
            if re.fullmatch(r"[0-9a-fx.:]+", host.lower()) and any(ch.isdigit() for ch in host):
                return await orig_resolve(host, port)   # formas numéricas (decimal/octal/hex/IPv6): getaddrinfo real
            if host in ("localhost",):
                return ["127.0.0.1"]
            if host.startswith("internal."):
                return ["10.0.0.7"]
            return ["93.184.216.34"]

        async def fake_expand(url, transport=None):
            return await orig_expand(url, transport=world.transport())

        async def fake_age(domain):
            if world.delay:
                await asyncio.sleep(WHOIS_DELAY)
            return world.ages.get(domain)

        security._resolve = fake_dns
        resolver.expand = fake_expand
        domain_info.domain_age_days = fake_age

        def restore():
            security._resolve = orig_resolve
            resolver.expand = orig_expand
            domain_info.domain_age_days = orig_age
        return restore
