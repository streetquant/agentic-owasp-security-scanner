"""
Base agent class for OWASP Top 10 security testing.

This module provides the foundational architecture for all security testing agents,
including common functionality for HTTP requests, result handling, and AI integration.
"""

import asyncio
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, AsyncGenerator, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
import hashlib

import aiohttp
from loguru import logger
from pydantic import BaseModel

from ..core.config import ScannerConfig, OWASPCategory


class SeverityLevel(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityStatus(str, Enum):
    """Vulnerability detection status."""
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"
    FALSE_POSITIVE = "FALSE_POSITIVE"


@dataclass
class TestPayload:
    """Represents a test payload for vulnerability detection."""
    name: str
    payload: str
    description: str
    category: OWASPCategory
    expected_response: Optional[str] = None
    content_type: str = "application/x-www-form-urlencoded"
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass 
class VulnerabilityFinding:
    """Represents a discovered vulnerability."""
    id: str
    category: OWASPCategory
    name: str
    description: str
    severity: SeverityLevel
    status: VulnerabilityStatus
    url: str
    method: str = "GET"
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    discovered_at: datetime = field(default_factory=datetime.now)
    confidence: float = 0.0
    
    def __post_init__(self):
        """Generate unique ID if not provided."""
        if not self.id:
            data = f"{self.category}:{self.url}:{self.parameter}:{self.payload}"
            self.id = hashlib.sha256(data.encode()).hexdigest()[:12]


@dataclass
class TestResult:
    """Result of a security test."""
    success: bool
    vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    execution_time: float = 0.0


class BaseSecurityAgent(ABC):
    """Base class for all OWASP security testing agents."""
    
    def __init__(self, config: ScannerConfig, session: Optional[aiohttp.ClientSession] = None):
        self.config = config
        self.session = session
        self.category = self._get_category()
        self.name = self.__class__.__name__
        self.findings: List[VulnerabilityFinding] = []
        self._payloads: List[TestPayload] = []
        self._initialize_payloads()
        
    @abstractmethod
    def _get_category(self) -> OWASPCategory:
        """Return the OWASP category this agent tests for."""
        pass
    
    @abstractmethod
    def _initialize_payloads(self) -> None:
        """Initialize test payloads specific to this agent."""
        pass
    
    @abstractmethod
    async def _analyze_response(self, response: aiohttp.ClientResponse, payload: TestPayload) -> List[VulnerabilityFinding]:
        """Analyze HTTP response for vulnerabilities using AI reasoning."""
        pass
    
    async def initialize(self) -> None:
        """Initialize the agent (setup session, load knowledge, etc.)."""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=self.config.testing.timeout)
            connector = aiohttp.TCPConnector(
                limit=self.config.testing.concurrent_requests,
                verify_ssl=self.config.testing.verify_ssl
            )
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers=self._get_default_headers()
            )
        
        logger.info(f"Initialized {self.name} agent for category {self.category.value}")
    
    async def cleanup(self) -> None:
        """Clean up resources."""
        if self.session and not self.session.closed:
            await self.session.close()
        logger.info(f"Cleaned up {self.name} agent")
    
    def _get_default_headers(self) -> Dict[str, str]:
        """Get default HTTP headers for requests."""
        headers = {
            "User-Agent": self.config.testing.user_agent,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive"
        }
        headers.update(self.config.testing.custom_headers)
        
        # Add authentication headers if configured
        if self.config.auth.enabled:
            if self.config.auth.token:
                headers["Authorization"] = f"Bearer {self.config.auth.token}"
            elif self.config.auth.username and self.config.auth.password:
                import base64
                auth_string = f"{self.config.auth.username}:{self.config.auth.password}"
                encoded_auth = base64.b64encode(auth_string.encode()).decode()
                headers["Authorization"] = f"Basic {encoded_auth}"
        
        return headers
    
    async def make_request(
        self, 
        url: str, 
        method: str = "GET",
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> Optional[aiohttp.ClientResponse]:
        """Make HTTP request with proper error handling."""
        try:
            request_headers = self._get_default_headers()
            if headers:
                request_headers.update(headers)
            
            request_cookies = self.config.auth.cookies.copy()
            if cookies:
                request_cookies.update(cookies)
            
            async with self.session.request(
                method=method,
                url=url,
                data=data,
                headers=request_headers,
                cookies=request_cookies,
                allow_redirects=self.config.testing.follow_redirects
            ) as response:
                # Read response content
                await response.read()
                return response
                
        except asyncio.TimeoutError:
            logger.warning(f"Request timeout for {url}")
            return None
        except Exception as e:
            logger.error(f"Request failed for {url}: {str(e)}")
            return None
    
    async def test_endpoint(
        self, 
        url: str, 
        method: str = "GET",
        parameters: Optional[Dict[str, str]] = None
    ) -> TestResult:
        """Test a single endpoint for vulnerabilities."""
        start_time = datetime.now()
        vulnerabilities = []
        errors = []
        
        try:
            logger.debug(f"Testing endpoint: {method} {url}")
            
            # Test each payload against the endpoint
            for payload in self._payloads:
                try:
                    # Prepare request data
                    request_data = self._prepare_request_data(payload, parameters)
                    
                    # Make request with payload
                    response = await self.make_request(
                        url=url,
                        method=payload.method,
                        data=request_data,
                        headers=payload.headers
                    )
                    
                    if response:
                        # Analyze response for vulnerabilities
                        found_vulns = await self._analyze_response(response, payload)
                        vulnerabilities.extend(found_vulns)
                        
                        # Rate limiting
                        await asyncio.sleep(0.1)
                    
                except Exception as e:
                    error_msg = f"Error testing payload {payload.name}: {str(e)}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return TestResult(
                success=len(errors) == 0,
                vulnerabilities=vulnerabilities,
                errors=errors,
                execution_time=execution_time,
                metadata={
                    "url": url,
                    "method": method,
                    "payloads_tested": len(self._payloads),
                    "agent": self.name
                }
            )
            
        except Exception as e:
            error_msg = f"Critical error in test_endpoint: {str(e)}"
            logger.error(error_msg)
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return TestResult(
                success=False,
                errors=[error_msg],
                execution_time=execution_time
            )
    
    def _prepare_request_data(
        self, 
        payload: TestPayload, 
        parameters: Optional[Dict[str, str]] = None
    ) -> Optional[Dict[str, Any]]:
        """Prepare request data by injecting payload into parameters."""
        if not parameters:
            return None
        
        request_data = parameters.copy()
        
        # Inject payload into each parameter
        for param_name in request_data:
            if payload.payload:
                request_data[param_name] = payload.payload
        
        return request_data
    
    async def run_comprehensive_test(
        self, 
        target_urls: List[str]
    ) -> AsyncGenerator[TestResult, None]:
        """Run comprehensive testing across multiple URLs."""
        logger.info(f"Starting comprehensive {self.category.value} testing on {len(target_urls)} URLs")
        
        for url in target_urls:
            if self._should_skip_url(url):
                continue
                
            result = await self.test_endpoint(url)
            yield result
            
            # Update findings
            self.findings.extend(result.vulnerabilities)
    
    def _should_skip_url(self, url: str) -> bool:
        """Check if URL should be skipped based on configuration."""
        for excluded_ext in self.config.testing.excluded_extensions:
            if url.lower().endswith(excluded_ext):
                return True
        
        for excluded_path in self.config.testing.excluded_paths:
            if excluded_path in url:
                return True
        
        return False
    
    async def get_ai_analysis(
        self, 
        context: str, 
        response_data: str,
        payload: TestPayload
    ) -> Dict[str, Any]:
        """Get AI analysis from Gemini Flash for vulnerability detection."""
        try:
            import google.generativeai as genai
            
            genai.configure(api_key=self.config.api.google_ai_key)
            model = genai.GenerativeModel('gemini-1.5-flash')
            
            prompt = self._build_ai_prompt(context, response_data, payload)
            
            response = await model.generate_content_async(prompt)
            
            # Parse AI response
            return self._parse_ai_response(response.text)
            
        except Exception as e:
            logger.error(f"AI analysis failed: {str(e)}")
            return {"vulnerability_detected": False, "confidence": 0.0}
    
    def _build_ai_prompt(
        self, 
        context: str, 
        response_data: str, 
        payload: TestPayload
    ) -> str:
        """Build prompt for AI analysis."""
        return f"""
        As a cybersecurity expert, analyze the following HTTP response for {self.category.value} vulnerabilities.
        
        Context: {context}
        
        Test Payload Information:
        - Name: {payload.name}
        - Payload: {payload.payload}
        - Description: {payload.description}
        - Category: {payload.category.value}
        
        HTTP Response Data:
        {response_data[:2000]}  # Limit response size
        
        Please provide a JSON response with the following structure:
        {{
            "vulnerability_detected": boolean,
            "confidence": float (0.0-1.0),
            "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
            "description": "Detailed description of the vulnerability",
            "evidence": "Specific evidence from the response",
            "remediation": "Recommended remediation steps",
            "cwe_id": "CWE identifier if applicable"
        }}
        
        Focus on detecting actual vulnerabilities and minimizing false positives.
        """
    
    def _parse_ai_response(self, ai_response: str) -> Dict[str, Any]:
        """Parse AI response JSON."""
        try:
            # Extract JSON from response if it contains additional text
            start_idx = ai_response.find('{')
            end_idx = ai_response.rfind('}') + 1
            
            if start_idx != -1 and end_idx != -1:
                json_str = ai_response[start_idx:end_idx]
                return json.loads(json_str)
            
            return {"vulnerability_detected": False, "confidence": 0.0}
            
        except json.JSONDecodeError:
            logger.error(f"Failed to parse AI response: {ai_response[:200]}...")
            return {"vulnerability_detected": False, "confidence": 0.0}
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of findings for this agent."""
        severity_counts = {}
        for severity in SeverityLevel:
            severity_counts[severity.value] = len([
                f for f in self.findings if f.severity == severity
            ])
        
        return {
            "agent": self.name,
            "category": self.category.value,
            "total_findings": len(self.findings),
            "severity_breakdown": severity_counts,
            "payloads_count": len(self._payloads)
        }
