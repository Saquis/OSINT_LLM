import os
from dotenv import load_dotenv

load_dotenv()

# Ollama config (corre en Windows, nos conectamos desde WSL2)
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://172.17.0.1:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")
OLLAMA_CODE_MODEL = os.getenv("OLLAMA_CODE_MODEL", "codellama:7b")

# Scraping config
MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "50"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))
JITTER_MIN = float(os.getenv("JITTER_MIN", "0.5"))
JITTER_MAX = float(os.getenv("JITTER_MAX", "3.0"))

# Storage
DB_PATH = os.getenv("DB_PATH", "osint_results.db")

# Reports
REPORTS_DIR = os.getenv("REPORTS_DIR", "reports/")