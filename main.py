import datetime
import asyncio
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import httpx
import whois
from urllib.parse import urlparse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Motor de Expansión de URLs y Heurística",
    description="Microservicio MVP para resolver URLs acortadas de forma asíncrona y evaluar riesgos."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

# Función auxiliar para ejecutar whois sin bloquear el servidor
def fetch_whois(domain):
    return whois.whois(domain)

@app.post("/api/v1/expand")
async def expand_url(req: URLRequest):
    # Limpiar espacios en blanco invisibles al inicio y al final
    req.url = req.url.strip()
    
    # 0. Validación básica
    if not req.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="La URL debe comenzar con http:// o https://")

    # 1. Resolución Asíncrona de la URL
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    }
    
    try:
        async with httpx.AsyncClient(follow_redirects=True, max_redirects=5, timeout=10.0) as client:
            response = await client.get(req.url, headers=headers)
            final_url = str(response.url)
            redirect_chain = [str(r.url) for r in response.history]
    except httpx.TooManyRedirects:
        raise HTTPException(status_code=400, detail="Bucle de redirección infinito detectado.")
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"Error de red al intentar resolver el enlace: {str(e)}")

    # 2. Análisis Heurístico Básico (Edad del Dominio)
    domain = urlparse(final_url).netloc
    risk_level = "BAJO"
    domain_age_days = None

    try:
        # Ejecutamos whois en un hilo separado para que no congele FastAPI
        domain_info = await asyncio.to_thread(fetch_whois, domain)
        creation_date = domain_info.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            domain_age_days = (datetime.datetime.now() - creation_date).days
            if domain_age_days < 30:
                risk_level = "ALTO"
            elif domain_age_days < 180:
                risk_level = "MEDIO"
    except Exception:
        risk_level = "DESCONOCIDO (Datos protegidos)"

    # 3. Retorno
    return {
        "original_url": req.url,
        "final_url": final_url,
        "redirect_chain": redirect_chain,
        "domain": domain,
        "domain_age_days": domain_age_days,
        "risk_level": risk_level
    }