# OSINT_LLM — Motor de inteligencia de fuentes abiertas

Herramienta en Python que **recolecta y correlaciona información de fuentes abiertas**
usando LLM para interpretar y resumir los hallazgos.

## Qué hace

A partir de entidades (personas, empresas, dominios), construye un grafo de relaciones
consultable a partir de datos públicos, y usa un modelo de lenguaje para resumir y
detectar conexiones no obvias.

## Stack

- Python 3
- Estructura `src/` con tests
- Integración con LLM para análisis semántico

## Estructura

```
OSINT_LLM/
├── main.py       punto de entrada
├── src/          lógica de recolección y correlación
└── tests/        pruebas
```

## Cómo correrlo

```bash
pip install -r requirements.txt
python main.py
```

## Qué demuestra

- Diseño de un pipeline de datos con separación de responsabilidades
- Trabajo con fuentes heterogéneas y normalización
- Uso de LLM no como chatbot sino como motor de análisis
- Suite de tests
