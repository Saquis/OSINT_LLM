import requests
import json
from src.config import OLLAMA_HOST, OLLAMA_MODEL, OLLAMA_CODE_MODEL

class OllamaClient:
    def __init__(self):
        self.host = OLLAMA_HOST
        self.model = OLLAMA_MODEL
        self.code_model = OLLAMA_CODE_MODEL

    def _generate(self, prompt: str, model: str, system: str = None) -> str:
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False
        }
        if system:
            payload["system"] = system

        try:
            response = requests.post(
                f"{self.host}/api/generate",
                json=payload,
                timeout=120
            )
            response.raise_for_status()
            return response.json().get("response", "")
        except requests.exceptions.RequestException as e:
            return f"[ERROR] Ollama: {str(e)}"

    def analyze_credential(self, credential: str) -> dict:
        system = "Eres un analista de ciberseguridad. Responde solo en JSON."
        prompt = f"""Analiza esta credencial y determina si es real o un placeholder.
Credencial: {credential}

Responde SOLO con este JSON:
{{
  "is_real": true/false,
  "confidence": 0.0-1.0,
  "reason": "explicacion breve"
}}"""
        result = self._generate(prompt, self.model, system)
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"is_real": False, "confidence": 0.0, "reason": result}

    def assign_cvss(self, vulnerability: str) -> dict:
        system = "Eres un experto en CVSS v3.1. Responde solo en JSON."
        prompt = f"""Asigna un score CVSS a esta vulnerabilidad:
{vulnerability}

Responde SOLO con este JSON:
{{
  "cvss_score": 0.0-10.0,
  "severity": "NONE/LOW/MEDIUM/HIGH/CRITICAL",
  "vector": "CVSS:3.1/...",
  "justification": "explicacion breve"
}}"""
        result = self._generate(prompt, self.model, system)
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"cvss_score": 0.0, "severity": "UNKNOWN", "vector": "", "justification": result}

    def analyze_code(self, code: str) -> dict:
        system = "Eres un experto en seguridad de código. Responde solo en JSON."
        prompt = f"""Analiza este fragmento de código en busca de vulnerabilidades:
{code}

Responde SOLO con este JSON:
{{
  "vulnerabilities": ["lista de vulnerabilidades encontradas"],
  "risk_level": "LOW/MEDIUM/HIGH/CRITICAL",
  "recommendations": ["lista de recomendaciones"]
}}"""
        result = self._generate(prompt, self.code_model, system)
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"vulnerabilities": [], "risk_level": "UNKNOWN", "recommendations": []}

    def generate_attack_chain(self, context: str) -> str:
        system = "Eres un analista de seguridad ofensiva."
        prompt = f"""Dado este contexto OSINT, genera posibles vectores de ataque:
{context}

Describe paso a paso un escenario de ataque realista."""
        return self._generate(prompt, self.model, system)