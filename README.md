# Sistema de Expansión de URLs y Evaluación Heurística (MVP)

Este proyecto contiene el MVP desarrollado para la asignatura de Temas Avanzados de Seguridad Informática. Se compone de un microservicio en Python (FastAPI) y un cliente web en Angular.

## Requisitos Previos
- [Python 3.8+](https://www.python.org/downloads/)
- [Node.js y npm](https://nodejs.org/)
- [Angular CLI](https://angular.io/cli) (`npm install -g @angular/cli`)

## 1. Instalación y Ejecución del Backend (Python)
Abre una terminal en la raíz del proyecto y ejecuta:
```bash
# Opcional pero recomendado: Crear entorno virtual
python -m venv venv
# Activar entorno (Windows)
venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt

# Levantar el servidor
uvicorn main:app --reload