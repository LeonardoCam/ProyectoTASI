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
* **Machine Learning:** Modelo honesto `HistGradientBoostingClassifier` (Scikit-Learn, Joblib) con 17 características léxicas inmunes a fugas de datos de protocolo.
* **Frontend:** Angular 22+, TypeScript, diseño moderno y responsivo con tema visual adaptativo.
* **Testing:** Pytest (179 pruebas unitarias en backend), Vitest (pruebas de frontend).
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

## 🖥️ Tutorial Completo de Uso del Proyecto (Paso a Paso)

Este sistema permite auditar cualquier enlace web de forma segura antes de abrirlo, expandiendo redirecciones ocultas, verificando defensas contra SSRF y evaluando heurísticamente la probabilidad de fraude o malware.

---

### 📍 Paso 1: Acceso a la Interfaz Web
Abre tu navegador web e ingresa a:
👉 **[http://localhost:4200](http://localhost:4200)**  
*(Asegúrate de que el backend esté activo en el puerto 8001 y el frontend en el 4200).*

---

### 📍 Paso 2: Ejecución de un Análisis

Tienes dos alternativas para realizar una prueba:

#### Opción A: Probar con los Botones de Demo Rápida (1 Clic)
Justo debajo de la barra de búsqueda encontrarás botones preconfigurados para demostraciones y sustentaciones:
* 🟢 **UPCH (Seguro):** Evalúa `https://upch.edu.pe`. Observarás cómo el **Escudo Tranco** reconoce la institución y aplica un factor atenuador en verde (`-20 pts`), clasificándolo en **BAJO (0/100)**.
* 🟢 **GitHub Login (Atenuado):** Evalúa `https://github.com/login`. Demuestra que una ruta `/login` en un dominio consolidado no genera falsos positivos.
* 🟢 **BCP Oficial:** Evalúa `https://bcpzonasegura.viabcp.com`. Comprueba que los dominios legítimos de entidades bancarias son reconocidos como oficiales.
* 🔴 **Suplantación Marca:** Evalúa `https://netfflix-verify.com`. Observarás el motor de **Typosquatting Dinámico (Levenshtein)** detectando la imitación de Netflix y clasificándolo en **ALTO**.

#### Opción B: Analizar tu propio enlace manual
1. Pega en la caja de texto cualquier enlace sospechoso, acortado (ej. `bit.ly/ejemplo`, `t.co/abc`) o URL completa.
2. Presiona la tecla `Enter` o haz clic en el botón **Verificar Destino**.

---

### 📍 Paso 3: Interpretación de los Resultados

La tarjeta de resultados presenta los siguientes componentes visuales:

#### 1. Semáforo y Puntaje de Riesgo (0 a 100)
| Nivel | Rango | Color | Recomendación al usuario |
| :---: | :---: | :---: | :--- |
| **BAJO** | 0 – 29 pts | 🟢 Verde | Enlace seguro. No se detectaron anomalías ni listas de bloqueo. |
| **MEDIO** | 30 – 59 pts | 🟡 Amarillo | Proceder con cautela. Presenta factores sospechosos (falta de HTTPS, saltos múltiples o dominio reciente). |
| **ALTO** | 60 – 100 pts | 🔴 Rojo | **¡Peligro!** Enlace con alta probabilidad de phishing o malware. El enlace se desactiva para evitar clics accidentales. |

#### 2. Factores Explicables
El sistema detalla el porqué de cada puntuación:
* **Puntos rojos (`+pts`):** Factores de riesgo acumulados (suplantación de marca, certificado recién creado, presencia en listas negras).
* **Puntos verdes (`-pts`):** Atenuadores de confianza (dominio registrado en el Top de Tranco, certificado SSL maduro con meses de vigencia).

#### 3. Metadatos Forenses de Red
* **Título web:** Extrae el `<title>` real de la página sin ejecutar scripts peligrosos. Si intenta suplantar una marca bancaria, el motor lo alertará de inmediato.
* **Certificado SSL:** Muestra la fecha exacta y días de emisión del certificado digital.
* **Antigüedad WHOIS:** Días de creación del dominio (patrón clave: dominios de menos de 30 días tienen alta correlación con campañas activas de phishing).
* **Trazabilidad de Saltos:** Detalle cronológico de cada redirección HTTP intermedia (301, 302, etc.) hasta el servidor de destino final.

---

### 📍 Paso 4: Exportación del Reporte Forense
Para sustentar laboratorios, informes académicos o auditorías de seguridad:
1. Haz clic en el botón azul **📋 Copiar Reporte Forense** situado en la parte superior del resultado.
2. El sistema copiará automáticamente al portapapeles un informe formateado en Markdown listo para pegar en Word, Notion o GitHub:
   ```markdown
   # Reporte Forense de Evaluación de Enlace (TASI - UPCH)
   - Fecha y hora: 2026-11-17T20:45:00Z
   - Enlace ingresado: https://bit.ly/ejemplo
   - Destino final: https://sitio-final.com/
   - Nivel de riesgo: BAJO (0/100)
   - Protocolo: HTTPS (Cifrado)
   - Certificado SSL: emitido hace 84 días
   - Factores evaluados:
     * [-20] Atenuador de confianza: dominio en el Top Tranco.
   ```
3. El botón confirmará la acción mostrando temporalmente: `✅ ¡Reporte Forense Copiado!`.

---

### 📍 Paso 5: Calibración y Reporte de Falsos Positivos
Si consideras que un enlace legítimo fue calificado con demasiado riesgo, utiliza los botones interactivos de feedback:
* Haz clic en **`👍 Sí`** para confirmar que el veredicto fue acertado.
* Haz clic en **`⚠️ Reportar`** para registrar un falso positivo. Esto enviará la URL al endpoint de auditoría (`POST /api/v1/feedback`) para su posterior análisis.

---

### 📍 Paso 6: Uso Directo mediante la API REST (Terminal / Scripts)

Si deseas integrar el escáner en scripts de Python o mediante la consola:

#### Petición con cURL:
```bash
curl -X POST "http://127.0.0.1:8001/api/v1/expand" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://upch.edu.pe"}'
```

#### Petición con Python:
```python
import requests

resp = requests.post("http://127.0.0.1:8001/api/v1/expand", json={"url": "https://github.com/login"})
data = resp.json()

print(f"Destino: {data['final_url']}")
print(f"Riesgo: {data['risk_level']} ({data['risk_score']}/100)")
for factor in data["factors"]:
    print(f" - [{factor['points']} pts] {factor['description']}")
```

---

## 🧪 Ejecución de Pruebas Automatizadas

El proyecto cuenta con cobertura rigurosa tanto en Backend como en Frontend:

### Pruebas del Backend (FastAPI / Pytest)
Con el entorno virtual activado, ejecuta desde la raíz:
```bash
pytest
```
*Se ejecutarán **171 pruebas unitarias** que validan:*
* Protección contra inyecciones SSRF y bypasses numéricos de IP (octal, decimal, hexadecimal).
* Motor de heurísticas de riesgo con atenuadores de confianza Tranco y reglas compuestas.
* Detección de typosquatting dinámico por distancia de Levenshtein.
* Inspección de antigüedad y madurez de certificados TLS/SSL.
* Detección de descargas de ejecutables maliciosos (`.exe`, `.apk`, `.scr`, `.bat`, etc.).
* Cálculo de entropía matemática de Shannon para detección de DGAs de malware.
* Auditoría de cabeceras de seguridad web (HSTS, CSP, Anti-Clickjacking).
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

## 🤖 Inteligencia Artificial y Machine Learning Híbrido (Capa 2)

El sistema incorpora una **arquitectura híbrida defensiva** que combina un motor determinista explicable (Capa 1) con un modelo estadístico de Machine Learning calibrado (Capa 2):

### 1. El problema de la fuga de datos en datasets de Kaggle (Data Leakage)
En los datasets públicos más citados (como *Malicious URLs dataset* de Kaggle con 651 000 registros):
* Casi todas las URLs benignas provienen de directorios tipo DMOZ **sin esquema** (`ejemplo.com/articulo`).
* Todas las URLs maliciosas provienen de repositorios tipo Zone-H **con prefijo HTTP** (`http://malicioso.xyz`).
* Los modelos clásicos en notebooks de Kaggle obtienen un engañoso **98% de exactitud** simplemente aprendiendo a contar `count_http`, `count_https` y `count_www`.
* Al evaluar esos mismos modelos frente a amenazas activas en tráfico real de 2026, su capacidad predictiva se desploma a **ROC-AUC 0.26** (peor que el azar).

### 2. Extractor de Características Honestas (17 Atributos Léxicos)
En `eval/ml_features.py` se implementó una extracción honesta (`honest=True`):
* Se despoja por completo cualquier esquema (`http://`, `https://`) y prefijo `www.` inicial.
* Se eliminan las columnas tramposas y se extraen 17 atributos matemáticos y estructurales intrínsecos:
  * `use_of_ip`, `count_dot`, `count_at`, `count_dir`, `count_embed_domain`, `short_url`, `count_percent`, `count_ques`, `count_hyphen`, `count_equal`, `url_length`, `hostname_length`, `sus_url`, `fd_length`, `tld_length`, `count_digits`, `count_letters`.

### 3. Modelo Ligero en Producción (`HistGradientBoostingClassifier`)
Mediante `scripts/train_production_model.py`, se entrenó un clasificador de gradient boosting optimizado sobre más de **107 000 muestras consolidadas**:
* Muestras benignas balanceadas (Kaggle limpio + dominios top de Tranco y peruanos con rutas habituales).
* Muestras maliciosas modernas (Kaggle phishing/malware + feeds en vivo de URLhaus, OpenPhish, phishing-filter y blackbook).
* **Métricas en conjunto de prueba:**
  * Exactitud (*Accuracy*): **89.33%**
  * Área bajo la curva (*ROC-AUC*): **0.9623**
  * Tamaño del modelo: **321 KB** en `app/models/url_model.joblib` (arranque ultrarrápido sin impacto en memoria).

### 4. Calibración en la "Zona Gris"
El modelo de Machine Learning no reemplaza la explicabilidad de las heurísticas de seguridad, sino que actúa como **árbitro en zonas de incertidumbre**:
* **Alta certeza benigna:** Si el dominio pertenece a Tranco o posee trayectoria sólida, el escudo de confianza prevalece.
* **Alta certeza maliciosa:** Si el enlace coincide con listas negras activas o malware confirmado, se asigna riesgo crítico directo.
* **Zona Gris (puntuaciones entre 15 y 55 puntos sin amenazas críticas):**
  * Si el modelo ML detecta una estructura léxica anómala con alta probabilidad ($\ge 65\%$), añade el factor explicable `ml_lexical_risk` (**+15 puntos**).
  * Si el modelo ML confirma una estructura consistente con sitios legítimos ($\le 25\%$), aplica el factor atenuador `ml_lexical_benign` (**-10 puntos**).
* **Visibilidad Forense:** El veredicto del modelo se incluye en cada respuesta JSON (`ml_analysis`) y se proyecta en la interfaz web de Angular con distintivos visuales y en el reporte descargable/copiable.

---

## 🔍 Análisis Forense Profundo y Evasión en URLs

El sistema implementa mecanismos avanzados especializados en la estructura, sintaxis y comportamiento de las **URLs**:

### 1. Detección de Técnicas de Evasión en la URL
* **Doble Codificación Porcentual (`double_url_encoding`):** Identifica secuencias anidadas (como `%252f`, `%253f`, `%252e%252e`) utilizadas comúnmente por ciberdelincuentes para evadir filtros de cortafuegos de aplicaciones web (WAF) e inspección de proxys.
* **Caracteres Invisibles y Homóglifos Unicode (`unicode_stealth_chars`):** Detecta la inyección encubierta de espacios de ancho cero (`\u200b`, `\u200c`, `\u200d`, `\ufeff`), guiones suaves (`\u00ad`) o caracteres de inversión de texto bidireccional (`\u202e`), diseñados para engañar a la vista humana simulando nombres legítimos.
* **Direcciones IP en Formato Numérico Ofuscado (`obfuscated_ip`):** Identifica hosts representados en formato decimal entero Dword (ej. `http://2130706433/` $\rightarrow$ `127.0.0.1`), hexadecimal (`0x7f000001`) u octal, técnicas empleadas para evadir listas negras textuales.
* **Parámetros de Redirección Abierta (`open_redirect_param`):** Examina si la cadena de consulta (*query string*) transporta parámetros de salto (`?redirect=`, `?url=`, `?next=`, `?dest=`) dirigidos hacia dominios externos no verificados.

### 2. Desglose Estructural de la URL (Anatomía Completa)
Cada consulta descompone automáticamente la URL analizada en sus componentes normalizados:
* **Esquema:** Protocolo utilizado (`http`, `https`).
* **Subdominio:** Prefijos anidados (`portal.seguridad`).
* **Dominio Registrable:** Entidad titular reconocida por la lista de sufijos públicos (`banco-oficial`).
* **TLD:** Extensión de nivel superior (`.pe`, `.com`, `.gob.pe`).
* **Ruta y Consulta:** Recursos internos invocados y parámetros transmitidos.

### 3. Trazabilidad Visual de Redirecciones (Interactive Stepper)
Sustituye las listas planas de texto por un diagrama de flujo interactivo que expone:
* Cada salto con su respectivo código de estado HTTP (`301`, `302`, `307`, `308`, `200`).
* Protocolo por salto (`HTTPS` cifrado vs `HTTP` degradado).
* Detección inmediata de **Cruce de Dominio (*Cross-Domain Redirect*)**, advirtiendo si un enlace cambia de propietario entre el acortador y el destino.

### 4. Sanitización Automática de Enlaces (*Defanged URLs*)
Permite a los analistas de incidentes y usuarios copiar con un solo clic el enlace en formato neutralizado de seguridad pericial (`hxxps://dominio[.]com/ruta`), garantizando que pueda compartirse en correos, tickets de Jira o Slack sin riesgo de apertura accidental.

---

## 📊 Evaluación y Resultados del Modelo de Riesgo

El proyecto incluye scripts en la carpeta `eval/` para reproducir las evaluaciones comparativas:

* **Evaluación sintética controlada:** `python -m eval.run_eval` evalúa el pipeline con 200 casos de prueba (obteniendo **94% de precisión**, **AUC de 0.88** y **25/25 casos SSRF mitigados**).
* **Evaluación con el dataset de Kaggle (Malicious URLs):** `python -m eval.kaggle_eval --download` analiza el rendimiento frente a 650 000 enlaces reales.
* **Optimización de rendimiento:** Se implementó reutilización de contextos TLS compartidos (`app/net.py`) y un extractor lineal de fechas WHOIS (`app/domain_info.py`) para evitar retrocesos catastróficos por regex, reduciendo la latencia de respuesta mediana de **5.1 s a 1.7 s**.
