import asyncio
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs
import re
import httpx
from bs4 import BeautifulSoup
from loguru import logger
from ..core.config import ScannerConfig
from .fingerprints import fingerprint_from_headers, fingerprint_from_paths

class WebDiscovery:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.visited = set()
        self.discovered: List[str] = []
        self.forms: Dict[str, List[Dict[str, Any]]] = {}
        self.headers_seen: Dict[str, Dict[str, str]] = {}

    async def detect_technology_stack(self, url: str) -> Dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=self.config.testing.timeout, verify=self.config.testing.verify_ssl, follow_redirects=True) as client:
                resp = await client.get(url)
                self.headers_seen[url] = dict(resp.headers)
                tech = fingerprint_from_headers(dict(resp.headers))
                path_hits = fingerprint_from_paths(self.discovered)
                if path_hits:
                    tech.setdefault("frameworks", []).extend(path_hits)
                return tech
        except Exception as e:
            logger.debug(f"Tech fingerprint failed for {url}: {e}")
            return {"frameworks": [], "server": None, "confidence": 0.0}

    async def discover_endpoints(self, url: str, max_depth: int = 3) -> List[str]:
        self.visited.clear()
        self.discovered.clear()
        async with httpx.AsyncClient(timeout=self.config.testing.timeout, verify=self.config.testing.verify_ssl, follow_redirects=True) as client:
            await self._crawl(client, url, 0, max_depth)
        return list(dict.fromkeys(self.discovered))

    async def _crawl(self, client: httpx.AsyncClient, url: str, depth: int, max_depth: int):
        if depth > max_depth or url in self.visited:
            return
        self.visited.add(url)
        try:
            resp = await client.get(url)
            if resp.status_code >= 400:
                return
            self.discovered.append(url)
            self.headers_seen[url] = dict(resp.headers)
            ctype = resp.headers.get('content-type', '')
            if 'text/html' in ctype:
                soup = BeautifulSoup(resp.text, 'lxml')
                # anchor links
                for a in soup.find_all('a', href=True):
                    href = a['href']
                    if href.startswith('#'):
                        continue
                    next_url = urljoin(url, href)
                    if urlparse(next_url).netloc == urlparse(url).netloc:
                        await self._crawl(client, next_url, depth+1, max_depth)
                # forms
                for form in soup.find_all('form'):
                    method = (form.get('method') or 'GET').upper()
                    action = urljoin(url, form.get('action') or url)
                    inputs = []
                    for inp in form.find_all(['input','textarea','select']):
                        name = inp.get('name')
                        if not name:
                            continue
                        itype = inp.get('type','text')
                        inputs.append({"name": name, "type": itype})
                    self.forms.setdefault(action, []).append({"method": method, "inputs": inputs})
        except Exception as e:
            logger.debug(f"Discovery error {url}: {e}")

    async def analyze_authentication(self, url: str) -> Dict[str, Any]:
        mechanisms = []
        # look for login forms and common auth endpoints
        for endpoint, forms in self.forms.items():
            if re.search(r"login|signin|oauth|authorize|token", endpoint, re.I):
                mechanisms.append({"type": "form", "endpoint": endpoint})
        # headers suggesting auth
        for u, headers in self.headers_seen.items():
            if 'www-authenticate' in {k.lower(): v for k,v in headers.items()}:
                mechanisms.append({"type": "basic", "endpoint": u})
        return {"mechanisms": mechanisms}

    async def enumerate_parameters(self, urls: List[str]) -> Dict[str, Any]:
        params: Dict[str, List[str]] = {}
        for u in urls:
            q = urlparse(u).query
            if q:
                for k, v in parse_qs(q).items():
                    params.setdefault(k, []).extend(v)
        for action, forms in self.forms.items():
            for f in forms:
                for inp in f["inputs"]:
                    params.setdefault(inp["name"], []).append("")
        total = sum(len(v) for v in params.values())
        return {"count": total, "parameters": params}
