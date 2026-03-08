import asyncio
import aiodns
import time
from typing import List, Dict
from src.scraper.storage import OSINTStorage

# Wordlist de subdominios comunes
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "webmail", "smtp", "pop", "imap",
    "vpn", "remote", "dev", "staging", "test", "api", "portal", "secure",
    "blog", "shop", "store", "app", "mobile", "m", "cdn", "static",
    "media", "images", "img", "assets", "upload", "download", "files",
    "backup", "db", "database", "mysql", "redis", "mongo", "elastic",
    "jenkins", "gitlab", "github", "jira", "confluence", "wiki",
    "intranet", "internal", "corp", "extranet", "partner", "support",
    "help", "docs", "documentation", "status", "monitor", "dashboard",
    "analytics", "tracking", "log", "logs", "audit", "report",
    "ns1", "ns2", "mx", "mx1", "mx2", "relay", "gateway", "proxy",
    "firewall", "router", "switch", "network", "wifi", "wireless",
    "ssh", "rdp", "citrix", "exchange", "outlook", "office",
]

class SubdomainEnumerator:
    def __init__(self, target: str):
        self.target = target
        self.storage = OSINTStorage()
        self.found = []

    async def _resolve(self, resolver: aiodns.DNSResolver, subdomain: str) -> Dict:
        fqdn = f"{subdomain}.{self.target}"
        try:
            result = await resolver.query(fqdn, 'A')
            ips = [r.host for r in result]
            return {
                "subdomain": fqdn,
                "ips": ips,
                "status": "found"
            }
        except aiodns.error.DNSError:
            return {"subdomain": fqdn, "status": "not_found"}

    async def _enumerate(self, wordlist: List[str]) -> List[Dict]:
        resolver = aiodns.DNSResolver()
        tasks = [self._resolve(resolver, sub) for sub in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return [r for r in results if r["status"] == "found"]

    def run(self, wordlist: List[str] = None) -> List[Dict]:
        if wordlist is None:
            wordlist = COMMON_SUBDOMAINS

        found = asyncio.run(self._enumerate(wordlist))

        # Guardar en SQLite
        for item in found:
            for ip in item.get("ips", []):
                self.storage.save_finding(
                    target=self.target,
                    type="subdomain",
                    value=item["subdomain"],
                    context=f"IP: {ip}",
                    source_url="dns_enum"
                )

        self.found = found
        return found