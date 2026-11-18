# Sistema de expansión automática de URLs acortadas y evaluación heurística del riesgo (MVP)

Proyecto de *Temas Avanzados de Seguridad Informática* (UPCH). Backend FastAPI + cliente web Angular.

## Qué hace
1. Recibe una URL (acortada o no) y **sigue la cadena de redirecciones** (301/302/303/307/308) sin descargar contenido.
2. **Valida cada salto contra SSRF**: solo http/https, solo puertos 80/443, sin credenciales en la URL, bloqueo de IPs privadas/loopback/link-local/reservadas (incluye `169.254.169.254` y formas decimal/octal/hex), límite de saltos, detección de bucles, timeouts.
3. Calcula un **puntaje de riesgo 0–100** (BAJO < 30 ≤ MEDIO < 60 ≤ ALTO) con **factores explicables**: antigüedad WHOIS, HTTPS, nº de saltos, IP como host, punycode, TLD sospechoso, subdominios, `@`, palabras de phishing, acortador encadenado y reputación externa (Google Safe Browsing, opcional).
4. **Caché TTL** ("memoria inteligente") para enlaces virales, y **límite de peticiones por IP**. Cada resultado se guarda mientras el servidor está activo (`CACHE_TTL`, 1 h por defecto, máx. `CACHE_MAX_ENTRIES`) con la hora del análisis (`analyzed_at`) y el tiempo que le queda (`cache_expires_in_s`). Se elimina al caducar, al reiniciar el servidor y **cuando las listas de amenazas se actualizan con datos nuevos**; además, antes de responder desde la caché se revisa el enlace contra las listas vigentes, para no servir un "BAJO" de un sitio que ya fue reportado.

## Backend
```bash
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
uvicorn main:app --reload
pytest                                              # 48 pruebas
```
Variables de entorno (opcionales): `ALLOWED_ORIGINS`, `SAFE_BROWSING_API_KEY`, `MAX_REDIRECTS` (10), `REQUEST_TIMEOUT` (8), `TOTAL_TIMEOUT` (20), `CACHE_TTL` (3600), `RATE_LIMIT_PER_MIN` (30), `VIRUSTOTAL_API_KEY`, `THREAT_FEEDS_ENABLED` (1), `THREAT_FEEDS_REFRESH_HOURS` (6), `DNS_USE_DOH` (1), `DNS_TIMEOUT` (4), `WHOIS_TIMEOUT` (5), `REQUEST_DEADLINE` (40).

API: `POST /api/v1/expand {"url": "..."}` · `GET /api/v1/health`

## Frontend
Requisito: **Node.js ≥ 22.22.3** (o ≥ 24.15) — lo exige Angular CLI 22.
```bash
cd frontend && npm install && npm start     # http://localhost:4200 (debajo del resultado: historial de la sesión con el % de riesgo; se borra al recargar)
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
- Las IPs en forma decimal/octal/hex (`http://2130706433/`, `0x7f.0.0.1`) se interpretan en el propio código, así que se bloquean igual en Windows y en Linux.

## Docker / despliegue
`docker compose up --build` → API en :8000, web en :8080. `render.yaml` define el backend para Render.

## Pruebas de API (Karate)
`karate/expand.feature` contiene los escenarios Gherkin (SSRF, factores, caché).

## Limitaciones conocidas
- La IP validada se fija en la conexión (sin *DNS rebinding*), pero el egreso sigue dependiendo de la red del host: una red que bloquee ciertos sitios los verá como "no respondió".
- La inspección es por cabeceras HTTP; no ejecuta JavaScript ni sortea CAPTCHAs/anti-bots, y no usa sandbox de navegador.
- WHOIS puede estar protegido/no disponible: se trata como factor de riesgo leve (+10), no como "bajo". `python-whois` no soporta varios ccTLD (todos los `.pe`, `.co.uk`, `.de`), así que en esos dominios este factor aparece siempre; en sufijos de registro restringido (`gob.pe`, `edu.pe`, `.gov`, `.edu`…) se omite.
- Caché y limitador son en memoria (una instancia); usar Redis si se escala.

## Evaluación (Cap. V)
`python -m eval.run_eval` ejecuta el pipeline real sobre un dataset sintético reproducible (200 casos, 35 difíciles) con DNS, WHOIS y web simulados, y escribe `eval/results.json` con recall, precisión, F1, FPR, AUC, SSRF, bucles, caché, latencia y carga.
`python -m eval.demo_server` levanta la API con una web simulada para demostraciones (ver `eval/demo_server.py`).
Resultado actual: recall 0,80 (meta 0,85, **no cumple**); precisión 0,94; F1 0,86; FPR 0,05; AUC 0,88; SSRF 25/25.

## Rendimiento con varias consultas a la vez
Una prueba de carga (150 URLs reales, 8 simultáneas) encontró dos fallas que dejaban consultas colgadas más de 60 s:
- Cada cliente HTTPS cargaba los certificados raíz desde disco (~250 ms que **bloqueaban todo el servidor**). Ahora se comparte un contexto TLS (`app/net.py`): 0,1 ms.
- El intérprete de `python-whois` tiene expresiones regulares con retroceso catastrófico: la respuesta WHOIS de `trilltrill.jp` (1,3 KB) consumía **91 s de CPU** sin soltar el GIL y congelaba el servidor. Ahora la librería solo descarga la respuesta y la fecha se extrae con un lector propio lineal (`app/domain_info.py`), validado contra la librería en 58 dominios con 0 diferencias. WHOIS corre además en su propio grupo de hilos.

Resultado: p50 5,1 s → **1,7 s**, p95 60,8 s → **8,5 s**, 0 consultas colgadas. Además, ninguna petición puede superar `REQUEST_DEADLINE` (40 s). Nota: NIC.PE no publica la fecha de creación de los dominios `.pe`, por eso su antigüedad aparece como desconocida.

## Resolución DNS y enlaces que "no se pueden resolver"
`app/security.py` resuelve con **DNS-over-HTTPS público** (Cloudflare y, de respaldo, Google) y, si no responde, con el DNS del sistema (`DNS_USE_DOH=0` lo desactiva). La conexión se hace **a la IP ya validada**, conservando `Host`, SNI y la verificación del certificado. Así el análisis ve lo mismo que una víctima en internet y no lo que devuelva la red local. Ejemplo real: en la red de la UPCH, el DNS interno resuelve `upch.edu.pe` a IPs privadas `172.x` (y el SSRF lo bloqueaba); el DNS público da su IP real.

Antes, todo esto terminaba en "No se pudo resolver el dominio":

| Entrada | Ahora |
|---|---|
| `sunat.gob.pe` (solo existe con `www`) | Se prueba la variante con/sin `www` y se informa en `dns_note` |
| `https://ejemplo.com,` · `<https://x.com>` · `bit.ly/abc).` | Se limpia la puntuación pegada al copiar |
| `Mira esto: bit.ly/abc gana premios` | Se extrae el enlace de la frase |
| `münchen.de`, `ñandú.pe` | Dominios con tildes/ñ convertidos con IDNA 2008 (UTS46) |
| `http://2130706433/` | IP decimal/octal/hex interpretada → `blocked_address` |
| Dominio inexistente (phishing dado de baja) | **Se analiza igual** sin visitarlo (`domain_exists: false`, factor `domain_not_found`) |
| Sitio caído, bloqueado o con certificado inválido | **Se analiza igual** sin visitarlo (`reachable: false`) |

Solo se rechazan con error las URLs inseguras (IP privada, puerto o esquema no permitidos).
## Detección de malware: listas de amenazas y VirusTotal
Un sitio que distribuye malware casi nunca se delata por la forma de su URL, así que el motor consulta inteligencia de amenazas (`app/threat_intel.py`):

| Fuente | Contenido | Clave |
|---|---|---|
| [URLhaus](https://urlhaus.abuse.ch) (vía [malware-filter](https://gitlab.com/malware-filter/urlhaus-filter)) | ~18 000 dominios que distribuyen malware | No |
| [blackbook](https://github.com/stamparm/blackbook) (maltrail) | ~18 000 dominios de malware y servidores C2 | No |
| [phishing-filter](https://gitlab.com/malware-filter/phishing-filter) (OpenPhish + PhishTank + PhishStats) | ~21 000 dominios de phishing | No |
| [OpenPhish](https://openphish.com) (feed público) | URLs de phishing activas | No |
| [VirusTotal](https://www.virustotal.com) | Veredicto de ~90 antivirus | Sí (gratuita) |

- Las listas se descargan al arrancar la API y se refrescan cada 6 h (`THREAT_FEEDS_REFRESH_HOURS`); se guardan en `data/threat_feeds/` para funcionar tras un reinicio sin red. Su estado aparece en `GET /api/v1/health`.
- Se eligieron porque **no listan sitios populares** (verificado contra el top 10 000 de Tranco). Se descartó Phishing.Database porque incluye dominios legítimos (`gravatar.com`, `mercadolibre.com.ar`).
- Se compara por host exacto o dominio padre listado: `x.duckdns.org` listado no marca a `y.duckdns.org`.
- **Una URL listada no se visita**: se califica ALTO antes de resolver su DNS o conectarse. También se revisa cada salto de la cadena (un acortador limpio que lleva a malware).
- Factores: `threat_intel` +80; `virustotal` +80 con ≥3 motores, +30 con 1–2, +10 si solo hay "sospechoso". Si el sitio no responde pero VirusTotal lo conoce, se informa igual.

**Activar VirusTotal**: crea una cuenta gratuita en virustotal.com → tu perfil → *API Key*, y arranca la API con la variable `VIRUSTOTAL_API_KEY` (PowerShell: `$env:VIRUSTOTAL_API_KEY="..."`). La clave gratuita permite 4 consultas por minuto y 500 por día; los resultados se guardan 6 h en caché. Desactivar las listas: `THREAT_FEEDS_ENABLED=0`.

### Evaluación con datos reales (Kaggle)
`python -m eval.kaggle_eval --download` descarga el [Malicious URLs dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset) (651 191 URLs: benign, phishing, defacement, malware) a `eval/data/` (ignorado por git) y evalúa la parte **léxica** del motor sin visitar ninguna URL. Escribe `eval/kaggle_results.json`. Usa `--limit N` para una muestra estratificada.

**El dataset tiene mucho ruido de etiqueta, en ambos sentidos**, y por eso se evalúa sobre subconjuntos de alta confianza:
- Muchas URLs "phishing" **sin esquema** son páginas legítimas antiguas (`www.freebsd.org/auditors.html`, `tools.ietf.org/html/rfc2617`, `www.microsoft.com/mscorp/java/`). Marcarlas sería un falso positivo. Las URLs "phishing" **con** `http(s)://` explícito sí son phishing real (16 de 16 en una muestra revisada a mano), así que el recall se mide sobre esas 24 852.
- Miles de URLs "benign" son kits de phishing evidentes (`paypal.com.cgi.bin.webscr…otro.com`, `us.battle.net.login.zh-gvk.in`). Se descuentan con un patrón, pero quedan más: en una revisión manual de 40 "falsos positivos" restantes con WHOIS disponible, **los 40 eran phishing real**.
- El esquema filtra la etiqueta (las benignas casi nunca lo traen y el defacement siempre es `http://`), así que estas métricas excluyen el factor `no_https`.

Resultados (umbral MEDIO = 30; escenarios `whois_ok`: antigüedad conocida y antigua, `whois_none`: WHOIS no disponible, como en `.pe`):

| Métrica (alta confianza) | Original | Actual |
|---|---|---|
| AUC léxico (separación phishing/benigna) | 0,660 | **0,771** |
| Recall phishing, WHOIS no disponible | 8,1 % | **16,4 %** |
| Recall phishing, WHOIS disponible | 0,5 % | **7,8 %** |
| Benignas marcadas, WHOIS no disponible (FPR bruta incl. `no_https`) | 9,44 % | **2,93 %** |
| Benignas limpias marcadas, WHOIS disponible (casi todo ruido de etiqueta) | 0,02 % | 0,61 % |

El recall léxico es bajo porque la mayoría del phishing del dataset vive en sitios legítimos comprometidos, sin nada raro en la URL; ahí actúan los factores en vivo (antigüedad del dominio, `no_https`, redirecciones, Safe Browsing). En la evaluación sintética (`run_eval`) recall 0,80 y precisión 0,94 se mantienen, y el AUC sube de 0,87 a 0,96.

**Falsos positivos corregidos** (todos con prueba en `tests/test_heuristics.py`):
- Palabras clave por **subcadena** (`plin` en *discipline*, `bcp`/`interbank`/`paypal` en sus dominios oficiales): ahora se comparan palabras completas de acción (login, verify, account…).
- **`@` en la ruta** (`medium.com/@usuario`): solo cuenta antes del dominio.
- **WHOIS no disponible + HTTP** sumaban MEDIO sin evidencia: `age_unknown` baja a 10 y no aplica en `gob.pe`, `edu.pe`, `.gov`, `gc.ca`…
- Marca en otro ccTLD oficial (`amazon.ca`), palabras comunes (`festival-outlook…`, `charley-chase.com`), `finance` confundido con `binance`, `sites.google.com/a/empresa.com/`.

**Señales nuevas contra falsos negativos**, con su frecuencia medida (% benignas vs % phishing):

| Factor | Ejemplo | Benignas | Phishing | Puntos |
|---|---|---|---|---|
| `brand_impersonation` | `br-icloud.com.br`, `paypal-germany.de` | 0,3 % | 5,2 % | 30 |
| `typosquatting` | `linkedln.…`, `faceb00k.…`, `paypa1.…` | 0,1 % | 0,6 % | 30 |
| `fake_domain_prefix` | `apple.com-support….upoert.com` | 0,5 % | 6,8 % | 15 |
| `free_hosting` | `pastehtml.com`, `ddnsfree.com`, `16mb.com` | 0,7 % | 8,6 % | 10 |
| `cms_path` | `/wp-content/…`, `/administrator/…` | 1,4 % | 16,3 % | 10 |
| `hash_dir` | `/e56508df639f6ce7d55c81ee3fcd5ba8/` | 0,8 % | 8,6 % | 10 |
| `brand_in_path` | `…/wp-admin/js/paypal/index.html` | 1,2 % | 11,1 % | 10 |
| `domain_in_path` | `/www.bankofamerica.com.login.update/` | 0,6 % | 4,8 % | 10 |
| `keywords` (2+ en el dominio) | `account.…security.…` | 0,1 % | 0,5 % | 20 |
| `subdomains` (5+ niveles) | `a.b.c.d.e.evil.com` | — | — | 10 |

Que la URL termine en `.html`/`.php` **no** se usa como señal: aparece en el 9 % de las benignas y apenas distingue (LR 2,4).
### ¿Y el machine learning de los notebooks de Kaggle?
Los notebooks públicos de este dataset (y trabajos como [Informatica 2025](https://informatica.si/index.php/informatica/article/download/9106/4601), que reporta LightGBM con 98,46 %) extraen ~21 conteos de la URL (`count_http`, `count_www`, `url_length`, `hostname_length`…) y entrenan árboles. `python -m eval.train_ml --tranco top-1m.csv` reproduce ese enfoque y lo verifica (`eval/ml_results.json`):

| Prueba | Resultado |
|---|---|
| Reproducción (Random Forest, split 80/20) | **97,7 %** de exactitud, como los notebooks |
| Características más importantes | `count_http`, `count_www` (si la URL trae `http://` o `www`) |
| Modelo que **solo** mira esquema y `www` | 86,3 %: la exactitud viene de la fuga del esquema |
| Modelo sin esas columnas, en Kaggle | 87,2 % (AUC 0,94) |
| **Datos de hoy** (5 000 amenazas activas de URLhaus/blackbook/phishing-filter/OpenPhish vs 5 000 sitios legítimos de Tranco), AUC | notebook **0,26**, modelo honesto **0,27**, **heurística del proyecto 0,76** |

Los modelos entrenados con Kaggle aprenden particularidades de ese dataset y con amenazas actuales rinden peor que el azar, así que **no se integran**: la detección real se apoya en la heurística (que con datos de hoy detecta el 54 % con un 5 % de falsas alarmas) y en las listas de amenazas/VirusTotal, que se actualizan solas.