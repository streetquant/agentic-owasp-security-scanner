from typer import Typer
from typing import Optional
import asyncio
from agentic_scanner.core.config import ScannerConfig
from agentic_scanner.core.scanner import AgenticScanner

app = Typer(help="Agentic OWASP Security Scanner CLI")

@app.command()
def scan(target: str, config_path: Optional[str] = None):
    """Run a scan against TARGET URL."""
    if config_path:
        cfg = ScannerConfig.from_file(config_path=config_path, target_url=target)
    else:
        cfg = ScannerConfig.from_env(target_url=target)

    async def run():
        async with AgenticScanner(cfg) as scanner:
            await scanner.run_full_assessment()
    asyncio.run(run())

def main():
    app()

if __name__ == "__main__":
    main()
