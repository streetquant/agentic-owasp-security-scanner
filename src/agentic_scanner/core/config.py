"""
Configuration management for the Agentic OWASP Security Scanner.

This module handles all configuration settings including API keys, testing parameters,
reporting options, and system-wide settings.
"""

import os
from typing import Optional, Dict, Any, List
from pathlib import Path
from pydantic import BaseModel, Field, validator
from enum import Enum


class LogLevel(str, Enum):
    """Logging levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ReportFormat(str, Enum):
    """Supported report formats."""
    HTML = "html"
    JSON = "json"
    PDF = "pdf"
    XML = "xml"


class OWASPCategory(str, Enum):
    """OWASP Top 10 2021 categories."""
    A01_BROKEN_ACCESS_CONTROL = "A01"
    A02_CRYPTOGRAPHIC_FAILURES = "A02"
    A03_INJECTION = "A03"
    A04_INSECURE_DESIGN = "A04"
    A05_SECURITY_MISCONFIGURATION = "A05"
    A06_VULNERABLE_COMPONENTS = "A06"
    A07_AUTH_FAILURES = "A07"
    A08_DATA_INTEGRITY_FAILURES = "A08"
    A09_LOGGING_FAILURES = "A09"
    A10_SSRF = "A10"


class APIConfig(BaseModel):
    """API configuration settings."""
    google_ai_key: str = Field(..., description="Google AI API key for Gemini Flash")
    rate_limit: int = Field(60, description="API requests per minute")
    timeout: int = Field(30, description="API timeout in seconds")
    max_retries: int = Field(3, description="Maximum retry attempts")
    
    @validator('google_ai_key')
    def validate_api_key(cls, v):
        if not v or len(v) < 20:
            raise ValueError('Invalid Google AI API key')
        return v


class TestingConfig(BaseModel):
    """Testing configuration parameters."""
    max_depth: int = Field(5, description="Maximum crawling depth")
    max_pages: int = Field(1000, description="Maximum pages to scan")
    timeout: int = Field(30, description="HTTP request timeout")
    concurrent_requests: int = Field(10, description="Maximum concurrent requests")
    user_agent: str = Field(
        "Agentic-OWASP-Scanner/0.1.0", 
        description="User agent string"
    )
    follow_redirects: bool = Field(True, description="Follow HTTP redirects")
    verify_ssl: bool = Field(True, description="Verify SSL certificates")
    custom_headers: Dict[str, str] = Field(
        default_factory=dict, 
        description="Custom HTTP headers"
    )
    excluded_extensions: List[str] = Field(
        default_factory=lambda: [".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".ico"],
        description="File extensions to exclude from scanning"
    )
    excluded_paths: List[str] = Field(
        default_factory=lambda: ["/logout", "/admin/delete"],
        description="URL paths to exclude from scanning"
    )
    
    @validator('concurrent_requests')
    def validate_concurrent_requests(cls, v):
        if v < 1 or v > 100:
            raise ValueError('Concurrent requests must be between 1 and 100')
        return v


class AuthConfig(BaseModel):
    """Authentication configuration."""
    enabled: bool = Field(False, description="Enable authentication")
    username: Optional[str] = Field(None, description="Username for basic auth")
    password: Optional[str] = Field(None, description="Password for basic auth")
    token: Optional[str] = Field(None, description="Bearer token")
    cookies: Dict[str, str] = Field(
        default_factory=dict, 
        description="Session cookies"
    )
    login_url: Optional[str] = Field(None, description="Login endpoint URL")
    login_data: Dict[str, str] = Field(
        default_factory=dict,
        description="Login form data"
    )


class ReportingConfig(BaseModel):
    """Reporting configuration."""
    format: ReportFormat = Field(ReportFormat.HTML, description="Report format")
    output_dir: Path = Field(Path("./reports"), description="Output directory")
    include_screenshots: bool = Field(False, description="Include screenshots")
    include_payloads: bool = Field(True, description="Include test payloads")
    severity_filter: List[str] = Field(
        default_factory=lambda: ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        description="Severity levels to include"
    )


class MemoryConfig(BaseModel):
    """Memory and caching configuration."""
    redis_url: str = Field(
        "redis://localhost:6379", 
        description="Redis connection URL"
    )
    cache_ttl: int = Field(3600, description="Cache TTL in seconds")
    max_memory_usage: int = Field(512, description="Max memory usage in MB")
    persist_sessions: bool = Field(True, description="Persist scan sessions")


class LoggingConfig(BaseModel):
    """Logging configuration."""
    level: LogLevel = Field(LogLevel.INFO, description="Logging level")
    file: Optional[Path] = Field(None, description="Log file path")
    max_size: int = Field(10, description="Max log file size in MB")
    backup_count: int = Field(3, description="Number of backup log files")
    format: str = Field(
        "{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message}",
        description="Log format string"
    )


class ScannerConfig(BaseModel):
    """Main configuration class for the Agentic OWASP Scanner."""
    
    # Core settings
    target_url: str = Field(..., description="Target URL to scan")
    scan_id: Optional[str] = Field(None, description="Unique scan identifier")
    categories: List[OWASPCategory] = Field(
        default_factory=lambda: list(OWASPCategory),
        description="OWASP categories to test"
    )
    
    # Component configurations
    api: APIConfig
    testing: TestingConfig = Field(default_factory=TestingConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    
    # Advanced settings
    debug_mode: bool = Field(False, description="Enable debug mode")
    dry_run: bool = Field(False, description="Perform dry run without actual testing")
    
    @validator('target_url')
    def validate_target_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('Target URL must start with http:// or https://')
        return v
    
    @classmethod
    def from_env(cls, target_url: str, **kwargs) -> "ScannerConfig":
        """Create configuration from environment variables."""
        api_config = APIConfig(
            google_ai_key=os.getenv("GOOGLE_AI_API_KEY", ""),
            rate_limit=int(os.getenv("API_RATE_LIMIT", "60")),
            timeout=int(os.getenv("API_TIMEOUT", "30"))
        )
        
        testing_config = TestingConfig(
            max_depth=int(os.getenv("MAX_DEPTH", "5")),
            concurrent_requests=int(os.getenv("MAX_CONCURRENT_TESTS", "10")),
            timeout=int(os.getenv("REQUEST_TIMEOUT", "30"))
        )
        
        memory_config = MemoryConfig(
            redis_url=os.getenv("REDIS_URL", "redis://localhost:6379")
        )
        
        logging_config = LoggingConfig(
            level=LogLevel(os.getenv("LOG_LEVEL", "INFO"))
        )
        
        return cls(
            target_url=target_url,
            api=api_config,
            testing=testing_config,
            memory=memory_config,
            logging=logging_config,
            **kwargs
        )
    
    @classmethod
    def from_file(cls, config_path: Path, target_url: str) -> "ScannerConfig":
        """Load configuration from YAML file."""
        import yaml
        
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f)
        
        # Update with target URL
        config_data['target_url'] = target_url
        
        return cls(**config_data)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return self.dict()
    
    def save_to_file(self, config_path: Path) -> None:
        """Save configuration to YAML file."""
        import yaml
        
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_path, 'w') as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False)


class ConfigManager:
    """Configuration manager for centralized config handling."""
    
    _instance = None
    _config: Optional[ScannerConfig] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def set_config(self, config: ScannerConfig) -> None:
        """Set the global configuration."""
        self._config = config
    
    def get_config(self) -> Optional[ScannerConfig]:
        """Get the global configuration."""
        return self._config
    
    def is_configured(self) -> bool:
        """Check if configuration is set."""
        return self._config is not None
