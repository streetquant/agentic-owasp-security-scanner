import asyncio
from agentic_scanner.core.config import ScannerConfig, APIConfig
from agentic_scanner.core.scanner import AgenticScanner

async def demo():
    config = ScannerConfig.from_env(target_url="https://example.com")
    async with AgenticScanner(config) as scanner:
        await scanner.run_full_assessment()

if __name__ == "__main__":
    asyncio.run(demo())
