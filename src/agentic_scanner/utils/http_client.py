import asyncio
from typing import Dict, Optional, Any
import httpx
from loguru import logger

class HttpClient:
    def __init__(self, timeout: int = 30, verify_ssl: bool = True, follow_redirects: bool = True):
        self.client = httpx.AsyncClient(timeout=timeout, verify=verify_ssl, follow_redirects=follow_redirects)

    async def request(self, method: str, url: str, **kwargs) -> Optional[httpx.Response]:
        try:
            r = await self.client.request(method, url, **kwargs)
            return r
        except Exception as e:
            logger.warning(f"HTTP error for {url}: {e}")
            return None

    async def close(self):
        await self.client.aclose()
