import asyncio
import json
from pathlib import Path
from typing import Dict, Any

from agentic_scanner.core.config import ScannerConfig
from agentic_scanner.core.reasoning import ReasoningEngine, AnalysisContext
from agentic_scanner.core.config import OWASPCategory, APIConfig

async def smoke_ai():
    cfg = ScannerConfig.from_env(target_url="https://example.com")
    engine = ReasoningEngine(cfg.api)
    await engine.initialize()
    ctx = AnalysisContext(
        target_url="https://example.com",
        technology_stack={"server":"nginx"},
        request_method="GET",
        request_headers={},
        request_data=None,
        response_status=200,
        response_headers={},
        response_body="Hello",
        test_payload="",
        owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
    )
    res = await engine.analyze_vulnerability(ctx)
    print(res)

if __name__ == "__main__":
    asyncio.run(smoke_ai())
