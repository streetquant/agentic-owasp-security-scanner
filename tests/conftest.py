"""
Pytest configuration and shared fixtures.

This module provides common fixtures used across the test suite including
mock HTTP servers, Redis instances, and synthetic vulnerable endpoints.
"""

import asyncio
import json
import os
import tempfile
from pathlib import Path
from typing import AsyncGenerator, Dict, Any, List
from unittest.mock import AsyncMock, Mock

import aiohttp
import pytest
import aioredis
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient

from src.agentic_scanner.core.config import ScannerConfig, APIConfig, TestingConfig
from src.agentic_scanner.core.memory import MemoryManager
from src.agentic_scanner.agents.base import VulnerabilityFinding, TestPayload


@pytest.fixture
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test artifacts."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def mock_config(temp_dir: Path) -> ScannerConfig:
    """Create a mock configuration for testing."""
    return ScannerConfig(
        target_url="https://test.example.com",
        api=APIConfig(
            google_ai_key="test-key-12345678901234567890",
            rate_limit=10,
            timeout=5
        ),
        testing=TestingConfig(
            max_depth=2,
            concurrent_requests=2,
            timeout=5,
            user_agent="Test-Scanner/1.0"
        ),
        reporting={
            "format": "json",
            "output_dir": temp_dir / "reports"
        },
        memory={
            "redis_url": "redis://localhost:6379/15",  # Use test DB
            "cache_ttl": 300
        },
        logging={
            "level": "DEBUG",
            "file": temp_dir / "test.log"
        }
    )


@pytest.fixture
async def mock_redis():
    """Create a mock Redis connection for testing."""
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/15")
    try:
        redis = await aioredis.from_url(redis_url, decode_responses=True)
        await redis.ping()
        
        # Clean up test data
        await redis.flushdb()
        
        yield redis
        
        # Clean up after tests
        await redis.flushdb()
        await redis.close()
    except Exception:
        # Fall back to mock if Redis not available
        mock_redis = AsyncMock()
        mock_redis.ping.return_value = "PONG"
        mock_redis.get.return_value = None
        mock_redis.setex.return_value = True
        yield mock_redis


@pytest.fixture
async def memory_manager(mock_config: ScannerConfig, mock_redis) -> AsyncGenerator[MemoryManager, None]:
    """Create a memory manager instance for testing."""
    manager = MemoryManager(mock_config.memory)
    manager.redis = mock_redis  # Use mock Redis
    
    # Initialize with minimal setup for testing
    try:
        await manager.initialize()
        yield manager
    finally:
        await manager.cleanup()


@pytest.fixture
def vulnerable_app_handlers():
    """HTTP handlers for synthetic vulnerable endpoints."""
    
    async def sqli_vulnerable(request: web.Request) -> web.Response:
        """Handler with SQL injection vulnerability."""
        user_id = request.query.get('id', '1')
        
        # Simulate SQL injection vulnerability
        if "'" in user_id or "UNION" in user_id.upper():
            return web.Response(
                text=f"Database error: You have an error in your SQL syntax near '{user_id}'",
                status=500
            )
        
        return web.json_response({"user_id": user_id, "name": "Test User"})
    
    async def idor_vulnerable(request: web.Request) -> web.Response:
        """Handler with IDOR vulnerability."""
        doc_id = request.match_info.get('doc_id', '1')
        
        # Simulate IDOR - no authorization check
        documents = {
            '1': {'content': 'Public document', 'owner': 'user1'},
            '2': {'content': 'Private document', 'owner': 'admin'},
            '999': {'content': 'Secret admin document', 'owner': 'admin'}
        }
        
        doc = documents.get(doc_id)
        if doc:
            return web.json_response(doc)
        else:
            return web.Response(text="Document not found", status=404)
    
    async def xss_vulnerable(request: web.Request) -> web.Response:
        """Handler with XSS vulnerability."""
        name = request.query.get('name', 'Guest')
        
        # Vulnerable to reflected XSS
        html = f"""
        <html>
            <body>
                <h1>Hello {name}!</h1>
                <p>Welcome to our site.</p>
            </body>
        </html>
        """
        
        return web.Response(text=html, content_type='text/html')
    
    async def admin_panel(request: web.Request) -> web.Response:
        """Handler for admin panel (should be protected)."""
        # No authentication check - misconfiguration
        return web.json_response({
            "admin": True,
            "users": ["admin", "user1", "user2"],
            "system_info": {
                "version": "1.0.0",
                "debug": True
            }
        })
    
    async def ssrf_vulnerable(request: web.Request) -> web.Response:
        """Handler with SSRF vulnerability."""
        url = request.query.get('url')
        if not url:
            return web.Response(text="URL parameter required", status=400)
        
        # Simulate fetching URL (SSRF vulnerability)
        if url.startswith('http://169.254.169.254/'):
            # AWS metadata endpoint
            return web.json_response({
                "role": "admin-role",
                "credentials": "secret-key-12345"
            })
        elif url.startswith('http://localhost') or url.startswith('http://127.0.0.1'):
            # Internal service access
            return web.json_response({
                "internal": True,
                "services": ["database", "cache", "admin-api"]
            })
        
        return web.Response(text="External URL fetched successfully")
    
    return {
        'sqli': sqli_vulnerable,
        'idor': idor_vulnerable,
        'xss': xss_vulnerable,
        'admin': admin_panel,
        'ssrf': ssrf_vulnerable
    }


@pytest.fixture
async def vulnerable_app(vulnerable_app_handlers) -> AsyncGenerator[TestServer, None]:
    """Create a test server with vulnerable endpoints."""
    app = web.Application()
    
    # Add vulnerable routes
    app.router.add_get('/api/user', vulnerable_app_handlers['sqli'])
    app.router.add_get('/api/document/{doc_id}', vulnerable_app_handlers['idor'])
    app.router.add_get('/search', vulnerable_app_handlers['xss'])
    app.router.add_get('/admin', vulnerable_app_handlers['admin'])
    app.router.add_get('/fetch', vulnerable_app_handlers['ssrf'])
    
    # Add some safe endpoints
    app.router.add_get('/', lambda r: web.Response(text="Welcome to Test App"))
    app.router.add_get('/health', lambda r: web.json_response({"status": "ok"}))
    
    async with TestServer(app) as server:
        yield server


@pytest.fixture
def sample_payloads() -> List[TestPayload]:
    """Sample test payloads for different vulnerability categories."""
    from src.agentic_scanner.core.config import OWASPCategory
    
    return [
        TestPayload(
            name="SQLi Union Test",
            payload="' UNION SELECT 1,2,3--",
            description="Basic SQL injection union test",
            category=OWASPCategory.A03_INJECTION
        ),
        TestPayload(
            name="XSS Script Test",
            payload="<script>alert('xss')</script>",
            description="Basic reflected XSS test",
            category=OWASPCategory.A03_INJECTION
        ),
        TestPayload(
            name="IDOR Increment", 
            payload="999",
            description="IDOR test with incremented ID",
            category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL
        ),
        TestPayload(
            name="SSRF Internal",
            payload="http://127.0.0.1:8080/internal",
            description="SSRF test targeting internal services",
            category=OWASPCategory.A10_SSRF
        )
    ]


@pytest.fixture
def sample_findings() -> List[VulnerabilityFinding]:
    """Sample vulnerability findings for testing."""
    from src.agentic_scanner.agents.base import SeverityLevel, VulnerabilityStatus
    from src.agentic_scanner.core.config import OWASPCategory
    
    return [
        VulnerabilityFinding(
            id="test-001",
            category=OWASPCategory.A03_INJECTION,
            name="SQL Injection",
            description="Database query vulnerable to SQL injection",
            severity=SeverityLevel.HIGH,
            status=VulnerabilityStatus.CONFIRMED,
            url="https://test.example.com/api/user?id=1",
            method="GET",
            parameter="id",
            payload="' UNION SELECT 1,2,3--",
            evidence="Database error message: syntax error near '''",
            remediation="Use parameterized queries",
            cwe_id="CWE-89",
            cvss_score=8.2,
            confidence=0.95
        ),
        VulnerabilityFinding(
            id="test-002",
            category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
            name="Insecure Direct Object Reference",
            description="Direct access to objects without authorization",
            severity=SeverityLevel.MEDIUM,
            status=VulnerabilityStatus.PROBABLE,
            url="https://test.example.com/api/document/999",
            method="GET",
            parameter="doc_id",
            payload="999",
            evidence="Accessed admin document without authentication",
            remediation="Implement proper access controls",
            cwe_id="CWE-639",
            cvss_score=6.5,
            confidence=0.85
        )
    ]


@pytest.fixture
def golden_responses() -> Dict[str, Any]:
    """Golden test responses for deterministic testing."""
    return {
        "ai_analysis_sqli": {
            "vulnerability_detected": True,
            "confidence": 0.95,
            "severity": "HIGH",
            "vulnerability_name": "SQL Injection",
            "description": "The application is vulnerable to SQL injection",
            "evidence": ["Database error message", "Syntax error in query"],
            "remediation": "Use parameterized queries",
            "cwe_id": "CWE-89",
            "cvss_score": 8.2,
            "false_positive_likelihood": 0.05,
            "analysis_reasoning": "Clear SQL syntax error indicates injection"
        },
        "ai_analysis_benign": {
            "vulnerability_detected": False,
            "confidence": 0.1,
            "severity": "INFO",
            "vulnerability_name": "No Vulnerability",
            "description": "No security issues detected",
            "evidence": [],
            "remediation": "Continue monitoring",
            "false_positive_likelihood": 0.0,
            "analysis_reasoning": "Normal application response"
        }
    }


# Mock HTTP client for unit tests
@pytest.fixture
def mock_http_client():
    """Mock HTTP client for isolated unit tests."""
    mock = AsyncMock()
    mock.get.return_value = Mock(
        status=200,
        headers={'Content-Type': 'text/html'},
        text=asyncio.coroutine(lambda: '<html><body>Test</body></html>')
    )
    return mock


# Mock Gemini AI client
@pytest.fixture
def mock_gemini_client(golden_responses):
    """Mock Gemini Flash client for AI testing."""
    mock = AsyncMock()
    
    async def mock_generate(prompt: str):
        if "SQL" in prompt or "injection" in prompt:
            response = Mock()
            response.text = json.dumps(golden_responses["ai_analysis_sqli"])
            return response
        else:
            response = Mock()
            response.text = json.dumps(golden_responses["ai_analysis_benign"]) 
            return response
    
    mock.generate_content_async = mock_generate
    return mock
