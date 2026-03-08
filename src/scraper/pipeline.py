import asyncio
import re
from typing import List, Dict
from src.scraper.async_engine import AsyncScraper, GoogleDorker
from src.scraper.storage import OSINTStorage
from src.scraper.subdomain import SubdomainEnumerator
from src.llm.client import OllamaClient
from rich.console import Console

console = Console()

PATTERNS = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "credential": r"(?:password|passwd|pwd|secret|key|token)\s*[:=]\s*\S+",
    "subdomain": r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}",
    "api_key": r"(?:api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
    "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}

class OSINTPipeline:
    def __init__(self, target: str, engine: str = "duckduckgo", use_llm: bool = True, url_limit: int = 10):
        self.target = target
        self.engine = engine
        self.use_llm = use_llm
        self.url_limit = url_limit
        self.scraper = AsyncScraper()
        self.storage = OSINTStorage()
        self.llm = OllamaClient()

    def _extract_findings(self, content: str, url: str) -> List[Dict]:
        findings = []
        for finding_type, pattern in PATTERNS.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in set(matches):
                if finding_type == "subdomain" and self.target not in match:
                    continue
                findings.append({
                    "type": finding_type,
                    "value": match,
                    "source_url": url
                })
        return findings

    def run(self):
        console.print(f"\n[bold cyan]🔍 OSINT Engine — Target: {self.target}[/bold cyan]\n")

        # Fase 1 — Scraping
        console.print("[yellow]→ Generando dorks...[/yellow]")
        dorker = GoogleDorker(self.target)
        urls = dorker.generate_urls(self.engine)[:self.url_limit]
        console.print(f"[yellow]→ Scraping {len(urls)} URLs...[/yellow]")

        results = self.scraper.run(urls)

        total_findings = 0
        for result in results:
            if result.get("status") in [200, 202] and result.get("content"):
                self.storage.save_raw(result, self.target, self.engine)
                findings = self._extract_findings(result["content"], result["url"])
                for finding in findings:
                    saved = self.storage.save_finding(
                        target=self.target,
                        type=finding["type"],
                        value=finding["value"],
                        source_url=finding["source_url"]
                    )
                    if saved:
                        total_findings += 1

        console.print(f"[green]✓ {total_findings} findings únicos extraídos[/green]")

        # Fase 2 — Análisis LLM
        findings = self.storage.get_findings(self.target)
        credentials = [f for f in findings if f["type"] == "credential"]

        if credentials and self.use_llm:
            console.print(f"\n[yellow]→ Analizando {len(credentials)} credenciales con LLM...[/yellow]")
            for cred in credentials[:5]:
                analysis = self.llm.analyze_credential(cred["value"])
                console.print(f"  [dim]{cred['value'][:50]}[/dim] → Real: {analysis.get('is_real')} ({analysis.get('confidence', 0):.0%})")

        # Fase 3 — Subdomain enumeration
        console.print(f"\n[yellow]→ Enumerando subdominios...[/yellow]")
        enumerator = SubdomainEnumerator(self.target)
        subdomains = enumerator.run()
        console.print(f"[green]✓ {len(subdomains)} subdominios encontrados[/green]")
        for s in subdomains[:5]:
            console.print(f"  [dim]{s['subdomain']}[/dim] → {s['ips']}")
        if len(subdomains) > 5:
            console.print(f"  [dim]... y {len(subdomains) - 5} más[/dim]")

        # Stats finales
        stats = self.storage.stats(self.target)
        console.print(f"\n[bold green]✓ Completado[/bold green]")
        console.print(f"  Raw results: {stats['raw_results']}")
        console.print(f"  Findings: {stats['findings']}")