import pytest
from agentic_scanner.core.config import ScannerConfig, APIConfig

def test_config_env_loading(monkeypatch):
    monkeypatch.setenv("GOOGLE_AI_API_KEY", "x"*40)
    cfg = ScannerConfig.from_env(target_url="https://example.com")
    assert cfg.api.google_ai_key.startswith("x")
    assert cfg.testing.max_depth == 5
