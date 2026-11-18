# Mira a dónde va un enlace antes de abrirlo
### Sistema de expansión automática de URLs acortadas y evaluación heurística del riesgo del destino

**Universidad Peruana Cayetano Heredia (UPCH)**  
*Facultad de Ingeniería Informática*  
*Temas Avanzados de Seguridad Informática*

---

## 👥 Integrantes y Docente

| Rol | Nombre Completo |
| :--- | :--- |
| **Estudiante** | Victor Nikolai Huarcaya Pumacayo |
| **Estudiante** | Leonardo Mejia López |
| **Estudiante** | Rodrigo Alonso Rodriguez Reategui |
| **Estudiante** | Valery Krystal Siccha Huayanay |
| **Estudiante** | Ruben Cabrera Cermeñoño |
| **Profesor del Curso** | Lider Jen Cotrina |

---

## 📖 Visión General del Proyecto

Los atacantes informáticos suelen utilizar servicios de acortamiento de URLs (bit.ly, tinyurl, etc.) o cadenas complejas de redirección para ocultar destinos maliciosos (sitios de phishing, distribución de malware o vectores de ataque interno tipo SSRF).

Este sistema es una solución integral que:
1. **Inspecciona enlaces de forma segura:** Rastrea y expande toda la cadena de redirecciones HTTP (códigos 301, 302, 303, 307, 308) examinando únicamente las cabeceras de respuesta, **sin descargar archivos ejecutables ni renderizar scripts maliciosos**.
2. **Protección activa anti-SSRF:** Bloquea de inmediato direcciones IP privadas, loopback (`127.0.0.1`), link-local (`169.254.169.254`), esquemas no web y variantes en notación decimal, octal o hexadecimal.
3. **Cálculo de Riesgo Heurístico Explicable:** Evalúa el enlace final en una escala objetiva de 0 a 100 puntos (**BAJO** < 30 ≤ **MEDIO** < 60 ≤ **ALTO**), detallando con precisión cada factor de riesgo detectado.
4. **Inteligencia de Amenazas en Tiempo Real:** Cruza los dominios analizados contra bases de datos globales de amenazas activas (URLhaus, OpenPhish, Maltrail Blackbook) y veredictos de antivirus mediante VirusTotal.
5. **Caché Inteligente con TTL:** Almacena resultados en memoria para consultas recurrentes, invalidando entradas automáticamente si las listas de amenazas se actualizan.

---

## 🏗️ Arquitectura y Tecnologías

```
┌─────────────────────────────────┐       HTTP / Proxy       ┌─────────────────────────────────┐
│        Frontend (Angular)       │ ───────────────────────> │        Backend (FastAPI)        │
│  - Interfaz de escáner          │       (localhost:4200)   │  - Validación SSRF              │
│  - Métricas e historial         │                          │  - Resolución DNS / DoH         │
│  - Alertas de riesgo por color  │                          │  - Motor heurístico + WHOIS     │
└─────────────────────────────────┘                          │  - Feeds de amenazas + Cache    │
                                                             └─────────────────────────────────┘
```

* **Backend:** Python 3.12+, FastAPI, Uvicorn, HTTPX (asíncrono con contexto TLS optimizado), DNS-over-HTTPS (Cloudflare/Google).
* **Frontend:** Angular 22+, TypeScript, diseño moderno y responsivo con tema visual adaptativo.
* **Testing:** Pytest (160 pruebas unitarias en backend), Vitest (pruebas de frontend).
* **Evaluación:** Scripts de evaluación con datasets reales (Kaggle Malicious URLs y feeds de amenazas).

---

## ⚙️ Requisitos Previos

Antes de comenzar, asegúrate de contar con el siguiente software instalado en tu sistema:

* **Python:** Versión `3.12` o superior ([Descargar Python](https://www.python.org/downloads/)).
* **Node.js:** Versión `≥ 22.22.3` o `≥ 24.15` (requerido por Angular CLI 22) ([Descargar Node.js](https://nodejs.org/)).
* **Git:** Para clonar y gestionar ramas del repositorio.
* *(Opcional)* **Cloudflared:** Si deseas compartir tu entorno local mediante un túnel público seguro.

---

## 🚀 Guía Paso a Paso de Instalación y Ejecución

Sigue estos pasos para poner en marcha el proyecto en tu máquina local:

### 1. Clonar el repositorio y acceder a la rama

```bash
# Clonar el repositorio
git clone https://github.com/LeonardoCam/ProyectoTASI.git

# Ingresar al directorio del proyecto
cd ProyectoTASI

# Cambiar a la rama de avance del proyecto
git checkout Avance-Proyecto
```

---

### 2. Configurar y Levantar el Backend (FastAPI)

Abre una terminal en la raíz del proyecto (`ProyectoTASI`):

1. **Crear y activar el entorno virtual:**
   ```bash
   # En Windows (PowerShell):
   python -m venv venv
   .\venv\Scripts\Activate.ps1

   # En Linux / macOS:
   python3 -m venv venv
   source venv/bin/activate
   ```

2. **Instalar dependencias:**
   ```bash
   pip install -r requirements.txt -r requirements-dev.txt
   ```

3. **Ejecutar el servidor del Backend:**
   ```bash
   # Ejecutar en el puerto 8001 (usado por el proxy de desarrollo de Angular)
   uvicorn main:app --reload --port 8001
   ```
   > [!NOTE]
   > El backend quedará disponible en `http://127.0.0.1:8001`. Puedes consultar su documentación interactiva Swagger en `http://127.0.0.1:8001/docs`.

---

### 3. Configurar y Levantar el Frontend (Angular)

Abre **una segunda terminal** y navega a la carpeta `frontend`:

1. **Ingresar a la carpeta e instalar dependencias de Node:**
   ```bash
   cd frontend
   npm install
   ```

2. **Iniciar el servidor de desarrollo web:**
   ```bash
   npm start
   ```

3. **Abrir en el navegador:**
   Ingresa a [http://localhost:4200](http://localhost:4200).  
   *Las peticiones a `/api/v1` serán redirigidas automáticamente por el proxy configurado en `frontend/proxy.conf.json` hacia el backend en el puerto 8001.*

---

## 🖥️ Guía de Uso del Sistema

### A. Desde la Interfaz Web (Escáner de Enlaces)
1. Abre [http://localhost:4200](http://localhost:4200).
2. Pega en el campo de texto el enlace sospechoso o acortado (ejemplo: `https://bit.ly/...` o un dominio con caracteres especiales).
3. Haz clic en **Escanear**.
4. La interfaz presentará:
   * **Veredicto Visual:** Nivel de riesgo (**BAJO** en verde, **MEDIO** en amarillo o **ALTO** en rojo) junto con el porcentaje estimado.
   * **Cadena de Saltos (Redirecciones):** Lista ordenada de cada salto con su código de estado HTTP (301, 302, etc.) hasta la URL de destino final.
   * **Factores de Riesgo Explicables:** Desglose punto por punto (ej. antigüedad del dominio en WHOIS, falta de certificado HTTPS, uso de palabras clave sospechosas, coincidencia con listas de amenazas).
   * **Historial de la Sesión:** Registro temporal en la parte inferior para comparar múltiples enlaces analizados.

---

### B. Desde la API REST

El backend expone endpoints estructurados en formato JSON:

#### 1. Analizar y Expandir URL
* **Método:** `POST`
* **Ruta:** `/api/v1/expand`
* **Cuerpo de la Petición:**
  ```json
  {
    "url": "https://bit.ly/ejemplo-enlace"
  }
  ```
* **Respuesta de Ejemplo:**
  ```json
  {
    "original_url": "https://bit.ly/ejemplo-enlace",
    "final_url": "https://sitio-destino-final.com/login",
    "risk_level": "MEDIO",
    "risk_score": 45,
    "hops": [
      { "url": "https://bit.ly/ejemplo-enlace", "status": 301 },
      { "url": "https://sitio-destino-final.com/login", "status": 200 }
    ],
    "factors": [
      { "id": "domain_age_young", "label": "Dominio registrado recientemente (< 6 meses)", "points": 25 },
      { "id": "brand_in_path", "label": "Marca bancaria mencionada en la ruta", "points": 20 }
    ],
    "analyzed_at": "2026-11-17T20:00:00Z",
    "cached": false
  }
  ```

#### 2. Estado de Salud y Feeds
* **Método:** `GET`
* **Ruta:** `/api/v1/health`
* Devuelve el estado de la API, el tamaño de la caché en memoria y la última actualización de las listas de amenazas.

---

## 🧪 Ejecución de Pruebas Automatizadas

El proyecto cuenta con cobertura rigurosa tanto en Backend como en Frontend:

### Pruebas del Backend (FastAPI / Pytest)
Con el entorno virtual activado, ejecuta desde la raíz:
```bash
pytest
```
*Se ejecutarán **167 pruebas unitarias** que validan:*
* Protección contra inyecciones SSRF y bypasses numéricos de IP (octal, decimal, hexadecimal).
* Motor de heurísticas de riesgo con atenuadores de confianza Tranco y reglas compuestas.
* Detección de typosquatting dinámico por distancia de Levenshtein.
* Inspección de antigüedad y madurez de certificados TLS/SSL.
* Resolución DoH resiliente (con/sin `www`, dominios IDNA con tildes y caracteres especiales).
* Funcionamiento de la caché TTL e inteligencia de amenazas.

### Pruebas del Frontend (Angular / Vitest)
Desde el directorio `frontend/`:
```bash
npm test
```
*Ejecuta las pruebas unitarias de los componentes visuales del escáner y los servicios de red.*

---

## 🌐 Compartir la App con Terceros (Túnel Cloudflare)

Para permitir que evaluadores o compañeros prueben la aplicación en vivo sin necesidad de un despliegue en la nube:

1. **Levanta el Backend:** `uvicorn main:app --port 8001`
2. **Levanta el Frontend:** `cd frontend && npm start`
3. **Inicia el túnel de Cloudflare hacia el Frontend:**
   ```bash
   cloudflared tunnel --url http://localhost:4200
   ```
4. Cloudflare generará una URL pública segura (ejemplo: `https://palabra-aleatoria.trycloudflare.com`).  
   *Al abrir esa URL, el frontend consumirá el backend a través del proxy local de forma transparente.*

---

## 🛡️ Variables de Entorno (Opcionales)

Puedes personalizar el comportamiento del sistema mediante un archivo `.env` o variables de entorno del sistema:

| Variable | Valor por defecto | Descripción |
| :--- | :---: | :--- |
| `ALLOWED_ORIGINS` | `*` | Orígenes permitidos para CORS en el backend. |
| `VIRUSTOTAL_API_KEY` | *(vacío)* | Clave gratuita de VirusTotal para verificar URLs con más de 90 motores antivirus. |
| `THREAT_FEEDS_ENABLED` | `1` | Activa la descarga automática de feeds de malware y phishing (URLhaus, OpenPhish, Blackbook). |
| `THREAT_FEEDS_REFRESH_HOURS` | `6` | Frecuencia de actualización en horas de las listas de amenazas. |
| `DNS_USE_DOH` | `1` | Usa DNS-over-HTTPS (Cloudflare y Google) para evitar envenenamiento o bloqueos de la red local. |
| `CACHE_TTL` | `3600` | Tiempo de vida de resultados en caché (en segundos). |
| `RATE_LIMIT_PER_MIN` | `30` | Límite máximo de peticiones por minuto por dirección IP. |
| `MAX_REDIRECTS` | `10` | Límite máximo de saltos HTTP permitidos antes de cortar el rastreo. |
| `REQUEST_DEADLINE` | `40` | Tiempo máximo absoluto en segundos asignado a un análisis antes de timeout. |

---

## 📊 Evaluación y Resultados del Modelo de Riesgo

El proyecto incluye scripts en la carpeta `eval/` para reproducir las evaluaciones comparativas:

* **Evaluación sintética controlada:** `python -m eval.run_eval` evalúa el pipeline con 200 casos de prueba (obteniendo **94% de precisión**, **AUC de 0.88** y **25/25 casos SSRF mitigados**).
* **Evaluación con el dataset de Kaggle (Malicious URLs):** `python -m eval.kaggle_eval --download` analiza el rendimiento frente a 650 000 enlaces reales.
* **Optimización de rendimiento:** Se implementó reutilización de contextos TLS compartidos (`app/net.py`) y un extractor lineal de fechas WHOIS (`app/domain_info.py`) para evitar retrocesos catastróficos por regex, reduciendo la latencia de respuesta mediana de **5.1 s a 1.7 s**.
