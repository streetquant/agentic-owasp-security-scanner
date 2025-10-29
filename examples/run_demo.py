import asyncio
import json
from pathlib import Path
from typing import Optional
from loguru import logger

from agentic_scanner.core.config import ScannerConfig
from agentic_scanner.core.scanner import AgenticScanner

def run_demo_scan():
    target = "https://example.com"
    cfg = ScannerConfig.from_env(target_url=target)

    async def _run():
        async with AgenticScanner(cfg) as scanner:
            session = await scanner.run_full_assessment()
            print("Findings:", len(session.findings))
    asyncio.run(_run())

if __name__ == "__main__":
    run_demo_scan()
