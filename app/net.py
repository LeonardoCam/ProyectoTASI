"""Recursos de red compartidos.

Crear un `httpx.AsyncClient` sin pasarle un contexto TLS obliga a cargar todos los certificados
raíz desde disco: ~250 ms de CPU que BLOQUEAN el event loop. Cada análisis creaba varios clientes
(DNS-over-HTTPS, expansión, VirusTotal...), así que con varias consultas simultáneas se encolaban
y una petición llegaba a tardar más de 60 s. Con un contexto compartido, crear un cliente cuesta
~0,1 ms. El contexto verifica certificados igual que el de httpx por defecto (certifi).
"""
import ssl

import certifi

SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
