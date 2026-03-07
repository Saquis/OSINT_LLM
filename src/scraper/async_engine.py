import asyncio
import aiohttp
import aiofiles
import random
import time
from typing import List, Dict
from src.config import (
    MAX_CONCURRENT_REQUESTS,
    REQUEST_TIMEOUT,
    JITTER_MIN,
    JITTER_MAX
)

# Headers rotativos para evasión básica
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 Safari/604.1",
]

class AsyncScraper:
    def __init__(self):
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        self.results = []
        self.errors = []

    def _get_headers(self) -> Dict:
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "DNT": "1",
        }

    async def _jitter_delay(self):
        delay = random.uniform(JITTER_MIN, JITTER_MAX)
        await asyncio.sleep(delay)

    async def fetch(self, session: aiohttp.ClientSession, url: str) -> Dict:
        async with self.semaphore:
            await self._jitter_delay()
            try:
                async with session.get(
                    url,
                    headers=self._get_headers(),
                    timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
                    ssl=False
                ) as response:
                    content = await response.text()
                    return {
                        "url": url,
                        "status": response.status,
                        "content": content[:5000],  # primeros 5000 chars
                        "headers": dict(response.headers),
                        "timestamp": time.time()
                    }
            except asyncio.TimeoutError:
                return {"url": url, "status": "timeout", "content": "", "error": "timeout"}
            except Exception as e:
                return {"url": url, "status": "error", "content": "", "error": str(e)}

    async def fetch_all(self, urls: List[str]) -> List[Dict]:
        connector = aiohttp.TCPConnector(
            limit=MAX_CONCURRENT_REQUESTS,
            ssl=False
        )
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.fetch(session, url) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=False)
            return results

    def run(self, urls: List[str]) -> List[Dict]:
        return asyncio.run(self.fetch_all(urls))


class GoogleDorker:
    """Genera Google Dorks para un objetivo dado"""

    def __init__(self, target: str):
        self.target = target

    def generate_dorks(self) -> List[str]:
        dorks = [
            f"site:{self.target} filetype:pdf",
            f"site:{self.target} filetype:xlsx OR filetype:csv",
            f"site:{self.target} inurl:admin",
            f"site:{self.target} inurl:login",
            f"site:{self.target} intitle:index.of",
            f"site:{self.target} ext:sql OR ext:db",
            f"site:{self.target} intext:password OR intext:passwd",
            f"\"{self.target}\" site:pastebin.com",
            f"\"{self.target}\" site:github.com password OR secret OR key",
            f"site:{self.target} inurl:config OR inurl:env OR inurl:.git",
        ]
        return dorks

    def generate_urls(self, search_engine: str = "bing") -> List[str]:
        dorks = self.generate_dorks()
        urls = []
        for dork in dorks:
            encoded = dork.replace(" ", "+").replace(":", "%3A").replace('"', "%22")
            if search_engine == "bing":
                urls.append(f"https://www.bing.com/search?q={encoded}")
            elif search_engine == "duckduckgo":
                urls.append(f"https://html.duckduckgo.com/html/?q={encoded}")
        return urls