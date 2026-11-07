# Sistema de expansión automática de URLs acortadas y evaluación heurística del riesgo (MVP)

Proyecto de *Temas Avanzados de Seguridad Informática* (UPCH). Backend FastAPI + cliente web Angular.

## Qué hace
1. Recibe una URL (acortada o no) y **sigue la cadena de redirecciones** (301/302/303/307/308) sin descargar contenido.
2. **Valida cada salto contra SSRF**: solo http/https, solo puertos 80/443, sin credenciales en la URL, bloqueo de IPs privadas/loopback/link-local/reservadas (incluye `169.254.169.254` y formas decimal/octal/hex), límite de saltos, detección de bucles, timeouts.
3. Calcula un **puntaje de riesgo 0–100** (BAJO < 30 ≤ MEDIO < 60 ≤ ALTO) con **factores explicables**: antigüedad WHOIS, HTTPS, nº de saltos, IP como host, punycode, TLD sospechoso, subdominios, `@`, palabras de phishing, acortador encadenado y reputación externa (Google Safe Browsing, opcional).
4. **Caché TTL** ("memoria inteligente") para enlaces virales, y **límite de peticiones por IP**.

## Backend
```bash
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
uvicorn main:app --reload
pytest                                              # 48 pruebas
```
Variables de entorno (opcionales): `ALLOWED_ORIGINS`, `SAFE_BROWSING_API_KEY`, `MAX_REDIRECTS` (10), `REQUEST_TIMEOUT` (8), `TOTAL_TIMEOUT` (20), `CACHE_TTL` (3600), `RATE_LIMIT_PER_MIN` (30).

API: `POST /api/v1/expand {"url": "..."}` · `GET /api/v1/health`

## Frontend
Requisito: **Node.js ≥ 22.22.3** (o ≥ 24.15) — lo exige Angular CLI 22.
```bash
cd frontend && npm install && npm start     # http://localhost:4200
npm test
```
En desarrollo la web llama a la API con una ruta relativa (`/api/v1`, en `frontend/src/environments/environment.ts`) y `ng serve` la reenvía al backend mediante `frontend/proxy.conf.json` (por defecto `http://127.0.0.1:8001`; cámbialo a `8000` si tu backend corre ahí). La URL de producción está en `environment.production.ts` y se usa con `ng build`.

## Compartir la app con otra persona (túnel)
Para que alguien fuera de tu red use la app sin desplegarla, se expone **solo el frontend** con un túnel de Cloudflare; la API va por el proxy, así que basta un único link.
```bash
# 1) Backend
uvicorn main:app --port 8001
# 2) Frontend (usa proxy.conf.json)
cd frontend && npm start
# 3) Túnel (sin cuenta) — imprime una URL https://<algo>.trycloudflare.com
cloudflared tunnel --url http://localhost:4200
```
`angular.json` permite los hosts `*.trycloudflare.com` (`allowedHosts` del dev-server y `security.allowedHosts` de SSR); sin eso Angular rechaza las peticiones que llegan por el túnel.

Notas: el link cambia cada vez que se reinicia el túnel y solo funciona mientras tu PC esté encendida. Detrás del túnel todas las peticiones llegan desde `127.0.0.1`, así que el límite por IP (30/min) es compartido entre todos los visitantes. Comparte el link solo con quien corresponda: el servicio hace peticiones salientes desde tu máquina.

## Cambios de la rama `cambios`
- Proxy de desarrollo (`frontend/proxy.conf.json`) y `apiUrl` relativa para no depender de un puerto fijo ni de CORS.
- `angular.json`: proxy activado y hosts del túnel permitidos.
- Documentación de requisitos de Node y del uso con túnel.
- Pendiente conocido: en **Windows** fallan 4 pruebas (`http://2130706433/`, `0177.0.0.1`, `0x7f.0.0.1`) porque `getaddrinfo` de Windows no normaliza IPs en forma decimal/octal/hex; la URL igual se rechaza, pero con código `dns_failure` en vez de `blocked_address`. En Linux/Docker pasan.

## Docker / despliegue
`docker compose up --build` → API en :8000, web en :8080. `render.yaml` define el backend para Render.

## Pruebas de API (Karate)
`karate/expand.feature` contiene los escenarios Gherkin (SSRF, factores, caché).

## Limitaciones conocidas
- La validación SSRF resuelve el DNS antes de conectar; no fija la IP validada (riesgo residual de *DNS rebinding*). Mitigación recomendada: transporte con IP fijada o egress firewall en el contenedor.
- La inspección es por cabeceras HTTP; no ejecuta JavaScript ni sortea CAPTCHAs/anti-bots, y no usa sandbox de navegador.
- WHOIS puede estar protegido/no disponible: se trata como factor de riesgo moderado (+15), no como "bajo".
- Caché y limitador son en memoria (una instancia); usar Redis si se escala.

## Evaluación (Cap. V)
`python -m eval.run_eval` ejecuta el pipeline real sobre un dataset sintético reproducible (200 casos, 35 difíciles) con DNS, WHOIS y web simulados, y escribe `eval/results.json` con recall, precisión, F1, FPR, AUC, SSRF, bucles, caché, latencia y carga.
`python -m eval.demo_server` levanta la API con una web simulada para demostraciones (ver `eval/demo_server.py`).
Resultado actual: recall 0,80 (meta 0,85, **no cumple**); precisión 0,94; F1 0,86; FPR 0,05; AUC 0,87; SSRF 25/25.
