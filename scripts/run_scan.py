import asyncio
from pathlib import Path
from typing import Optional
from loguru import logger

from agentic_scanner.core.config import ScannerConfig
from agentic_scanner.core.scanner import AgenticScanner

async def main(target: str, config: Optional[str] = None):
    if config:
        cfg = ScannerConfig.from_file(Path(config), target_url=target)
    else:
        cfg = ScannerConfig.from_env(target_url=target)
    async with AgenticScanner(cfg) as scanner:
        await scanner.run_full_assessment()

if __name__ == "__main__":
    asyncio.run(main("https://example.com"))
