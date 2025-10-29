"""
Unit tests for configuration management.
"""

import os
import tempfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.agentic_scanner.core.config import (
    ScannerConfig,
    APIConfig,
    TestingConfig,
    OWASPCategory,
    ConfigManager
)


class TestAPIConfig:
    """Test API configuration validation."""
    
    def test_valid_api_config(self):
        """Test creation of valid API config."""
        config = APIConfig(
            google_ai_key="test-key-12345678901234567890",
            rate_limit=60,
            timeout=30
        )
        assert config.google_ai_key == "test-key-12345678901234567890"
        assert config.rate_limit == 60
        assert config.timeout == 30
    
    def test_invalid_api_key(self):
        """Test validation of invalid API key."""
        with pytest.raises(ValidationError, match="Invalid Google AI API key"):
            APIConfig(google_ai_key="short")
    
    def test_api_key_from_env(self, monkeypatch):
        """Test API key loading from environment."""
        monkeypatch.setenv("GOOGLE_AI_API_KEY", "env-key-12345678901234567890")
        config = APIConfig(google_ai_key=os.getenv("GOOGLE_AI_API_KEY"))
        assert config.google_ai_key == "env-key-12345678901234567890"


class TestTestingConfig:
    """Test testing configuration validation."""
    
    def test_valid_testing_config(self):
        """Test creation of valid testing config."""
        config = TestingConfig(
            max_depth=5,
            concurrent_requests=10,
            timeout=30
        )
        assert config.max_depth == 5
        assert config.concurrent_requests == 10
        assert config.timeout == 30
    
    def test_invalid_concurrent_requests(self):
        """Test validation of concurrent requests limit."""
        with pytest.raises(ValidationError, match="Concurrent requests must be between 1 and 100"):
            TestingConfig(concurrent_requests=150)
        
        with pytest.raises(ValidationError, match="Concurrent requests must be between 1 and 100"):
            TestingConfig(concurrent_requests=0)
    
    def test_default_values(self):
        """Test default configuration values."""
        config = TestingConfig()
        assert config.max_depth == 5
        assert config.concurrent_requests == 10
        assert config.user_agent == "Agentic-OWASP-Scanner/0.1.0"
        assert ".jpg" in config.excluded_extensions


class TestScannerConfig:
    """Test main scanner configuration."""
    
    def test_valid_scanner_config(self):
        """Test creation of valid scanner config."""
        config = ScannerConfig(
            target_url="https://example.com",
            api=APIConfig(google_ai_key="test-key-12345678901234567890")
        )
        assert config.target_url == "https://example.com"
        assert len(config.categories) == 10  # All OWASP categories by default
    
    def test_invalid_target_url(self):
        """Test validation of target URL."""
        with pytest.raises(ValidationError, match="Target URL must start with http"):
            ScannerConfig(
                target_url="ftp://example.com",
                api=APIConfig(google_ai_key="test-key-12345678901234567890")
            )
    
    def test_from_env(self, monkeypatch):
        """Test configuration creation from environment variables."""
        monkeypatch.setenv("GOOGLE_AI_API_KEY", "env-key-12345678901234567890")
        monkeypatch.setenv("MAX_DEPTH", "3")
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")
        
        config = ScannerConfig.from_env("https://test.example.com")
        
        assert config.target_url == "https://test.example.com"
        assert config.api.google_ai_key == "env-key-12345678901234567890"
        assert config.testing.max_depth == 3
        assert config.logging.level.value == "DEBUG"
    
    def test_from_file(self):
        """Test configuration loading from YAML file."""
        yaml_content = """
target_url: https://test.example.com
api:
  google_ai_key: file-key-12345678901234567890
  rate_limit: 30
testing:
  max_depth: 3
  concurrent_requests: 5
logging:
  level: WARNING
        """
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            
            config = ScannerConfig.from_file(Path(f.name), "https://override.example.com")
            
            assert config.target_url == "https://override.example.com"  # Override
            assert config.api.google_ai_key == "file-key-12345678901234567890"
            assert config.api.rate_limit == 30
            assert config.testing.max_depth == 3
            assert config.logging.level.value == "WARNING"
        
        os.unlink(f.name)
    
    def test_to_dict_and_save(self, temp_dir):
        """Test configuration serialization and saving."""
        config = ScannerConfig(
            target_url="https://example.com",
            api=APIConfig(google_ai_key="test-key-12345678901234567890")
        )
        
        config_dict = config.to_dict()
        assert "target_url" in config_dict
        assert "api" in config_dict
        
        config_file = temp_dir / "config.yaml"
        config.save_to_file(config_file)
        
        assert config_file.exists()
        
        # Load and verify
        loaded_config = ScannerConfig.from_file(config_file, "https://example.com")
        assert loaded_config.api.google_ai_key == config.api.google_ai_key


class TestConfigManager:
    """Test configuration manager singleton."""
    
    def test_singleton_behavior(self):
        """Test that ConfigManager is a singleton."""
        manager1 = ConfigManager()
        manager2 = ConfigManager()
        assert manager1 is manager2
    
    def test_config_management(self):
        """Test setting and getting configuration."""
        manager = ConfigManager()
        
        assert not manager.is_configured()
        assert manager.get_config() is None
        
        config = ScannerConfig(
            target_url="https://example.com",
            api=APIConfig(google_ai_key="test-key-12345678901234567890")
        )
        
        manager.set_config(config)
        
        assert manager.is_configured()
        retrieved_config = manager.get_config()
        assert retrieved_config is config
        assert retrieved_config.target_url == "https://example.com"


class TestOWASPCategories:
    """Test OWASP category enumeration."""
    
    def test_all_categories_present(self):
        """Test that all OWASP Top 10 categories are defined."""
        expected_categories = [
            "A01", "A02", "A03", "A04", "A05",
            "A06", "A07", "A08", "A09", "A10"
        ]
        
        actual_categories = [cat.value for cat in OWASPCategory]
        
        for expected in expected_categories:
            assert expected in actual_categories
        
        assert len(actual_categories) == 10
    
    def test_category_creation(self):
        """Test OWASP category creation and properties."""
        sqli_category = OWASPCategory.A03_INJECTION
        assert sqli_category.value == "A03"
        assert str(sqli_category) == "A03"
