"""
AI reasoning engine powered by Google's Gemini Flash for intelligent security analysis.

This module provides advanced reasoning capabilities for vulnerability detection,
pattern recognition, and decision-making in security testing scenarios.
"""

import asyncio
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import re

import google.generativeai as genai
from loguru import logger

from .config import APIConfig, OWASPCategory
from ..agents.base import SeverityLevel, VulnerabilityFinding, VulnerabilityStatus


@dataclass
class AnalysisContext:
    """Context information for AI analysis."""
    target_url: str
    technology_stack: Dict[str, Any]
    request_method: str
    request_headers: Dict[str, str]
    request_data: Optional[str]
    response_status: int
    response_headers: Dict[str, str]
    response_body: str
    test_payload: str
    owasp_category: OWASPCategory
    vulnerability_patterns: List[str] = None


@dataclass
class AIAnalysisResult:
    """Result of AI-powered vulnerability analysis."""
    vulnerability_detected: bool
    confidence: float
    severity: SeverityLevel
    vulnerability_name: str
    description: str
    evidence: List[str]
    remediation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    false_positive_likelihood: float = 0.0
    analysis_reasoning: str = ""


class ReasoningEngine:
    """AI-powered reasoning engine for security analysis using Gemini Flash."""
    
    def __init__(self, api_config: APIConfig):
        self.config = api_config
        self.model = None
        self.request_count = 0
        self.last_request_time = datetime.now()
        
        # Vulnerability pattern knowledge base
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        
        # Analysis prompt templates
        self.prompt_templates = self._initialize_prompt_templates()
    
    async def initialize(self) -> None:
        """Initialize the Gemini Flash model."""
        try:
            genai.configure(api_key=self.config.google_ai_key)
            self.model = genai.GenerativeModel(
                'gemini-1.5-flash',
                generation_config=genai.types.GenerationConfig(
                    temperature=0.1,  # Low temperature for consistent analysis
                    top_p=0.9,
                    top_k=40,
                    max_output_tokens=4096,
                )
            )
            
            # Test the model with a simple query
            test_response = await self.model.generate_content_async(
                "Respond with 'OK' to confirm the model is working."
            )
            
            if "OK" in test_response.text:
                logger.info("Gemini Flash reasoning engine initialized successfully")
            else:
                raise Exception("Model test failed")
                
        except Exception as e:
            logger.error(f"Failed to initialize Gemini Flash model: {e}")
            raise
    
    def _load_vulnerability_patterns(self) -> Dict[OWASPCategory, List[str]]:
        """Load known vulnerability patterns for each OWASP category."""
        return {
            OWASPCategory.A01_BROKEN_ACCESS_CONTROL: [
                "unauthorized access to admin functions",
                "horizontal privilege escalation", 
                "vertical privilege escalation",
                "forced browsing to authenticated pages",
                "missing authorization checks",
                "insecure direct object references"
            ],
            OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES: [
                "weak encryption algorithms",
                "hardcoded cryptographic keys",
                "insufficient entropy",
                "improper certificate validation",
                "weak hashing algorithms",
                "unencrypted sensitive data transmission"
            ],
            OWASPCategory.A03_INJECTION: [
                "SQL injection", "NoSQL injection", "command injection",
                "LDAP injection", "XPath injection", "template injection",
                "code injection", "expression language injection"
            ],
            OWASPCategory.A04_INSECURE_DESIGN: [
                "missing rate limiting", "insecure workflow design",
                "insufficient business logic validation",
                "missing security controls by design"
            ],
            OWASPCategory.A05_SECURITY_MISCONFIGURATION: [
                "default credentials", "unnecessary services enabled",
                "missing security headers", "verbose error messages",
                "directory listing enabled", "outdated software versions"
            ],
            OWASPCategory.A06_VULNERABLE_COMPONENTS: [
                "outdated libraries", "known CVE vulnerabilities",
                "unsupported components", "vulnerable dependencies"
            ],
            OWASPCategory.A07_AUTH_FAILURES: [
                "weak password policies", "brute force vulnerabilities",
                "session fixation", "session hijacking", 
                "credential stuffing", "weak multi-factor authentication"
            ],
            OWASPCategory.A08_DATA_INTEGRITY_FAILURES: [
                "insecure deserialization", "unsigned code execution",
                "lack of integrity validation", "tampered software updates"
            ],
            OWASPCategory.A09_LOGGING_FAILURES: [
                "insufficient logging", "log injection",
                "missing security event monitoring", 
                "inadequate alerting mechanisms"
            ],
            OWASPCategory.A10_SSRF: [
                "server-side request forgery", "internal service access",
                "cloud metadata access", "port scanning via SSRF",
                "file system access through SSRF"
            ]
        }
    
    def _initialize_prompt_templates(self) -> Dict[str, str]:
        """Initialize prompt templates for different analysis scenarios."""
        return {
            "vulnerability_analysis": """
You are an expert cybersecurity analyst specializing in web application security testing. 
Analyze the following HTTP request/response for {category} vulnerabilities.

**Context:**
Target URL: {target_url}
Technology Stack: {tech_stack}
OWASP Category: {category}

**Test Details:**
Payload Used: {payload}
Request Method: {method}
Request Headers: {request_headers}
Request Data: {request_data}

**Response Analysis:**
HTTP Status: {status_code}
Response Headers: {response_headers}
Response Body: {response_body}

**Known {category} Patterns to Look For:**
{vulnerability_patterns}

**Analysis Instructions:**
1. Carefully examine the response for signs of {category} vulnerabilities
2. Look for specific indicators in headers, status codes, response content, and timing
3. Consider false positive scenarios and provide confidence assessment
4. If a vulnerability is detected, provide clear evidence and impact assessment
5. Suggest specific remediation steps

Provide your analysis in the following JSON format:
{{
  "vulnerability_detected": boolean,
  "confidence": float (0.0-1.0),
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "vulnerability_name": "Specific vulnerability name",
  "description": "Detailed technical description",
  "evidence": ["List of specific evidence from the response"],
  "remediation": "Specific remediation recommendations",
  "cwe_id": "CWE-XXX if applicable",
  "cvss_score": float (0.0-10.0) or null,
  "false_positive_likelihood": float (0.0-1.0),
  "analysis_reasoning": "Detailed reasoning for the analysis decision"
}}

Be thorough, accurate, and focus on minimizing false positives while ensuring real vulnerabilities are detected.
""",
            
            "payload_effectiveness": """
As a security testing expert, evaluate the effectiveness of the following test payload for detecting {category} vulnerabilities.

Payload: {payload}
Category: {category}
Target Response: {response_summary}
Detection Result: {detection_result}

Evaluate:
1. How well did this payload perform for {category} testing?
2. What made it effective or ineffective?
3. How can it be improved?
4. Rate its overall effectiveness (0.0-1.0)

Provide a JSON response:
{{
  "effectiveness_score": float (0.0-1.0),
  "strengths": ["List of payload strengths"],
  "weaknesses": ["List of payload weaknesses"],
  "improvement_suggestions": ["Suggestions for improvement"],
  "recommended_variations": ["Suggested payload variations"]
}}
""",
            
            "pattern_learning": """
Analyze the following vulnerability detection patterns to improve future scanning accuracy.

Successful Detections:
{successful_patterns}

False Positives:
{false_positive_patterns}

Provide insights to improve detection accuracy:
{{
  "refined_indicators": ["More accurate vulnerability indicators"],
  "false_positive_filters": ["Patterns to filter out false positives"],
  "new_detection_rules": ["Suggested new detection rules"],
  "confidence_factors": {{"factor": weight}} 
}}
"""
        }
    
    async def analyze_vulnerability(
        self, 
        context: AnalysisContext
    ) -> AIAnalysisResult:
        """Perform AI-powered vulnerability analysis on HTTP response."""
        try:
            await self._rate_limit_check()
            
            # Prepare analysis prompt
            prompt = self._build_analysis_prompt(context)
            
            # Generate AI analysis
            response = await self.model.generate_content_async(prompt)
            
            # Parse and validate response
            analysis_result = self._parse_analysis_response(response.text, context)
            
            logger.debug(f"AI analysis completed for {context.owasp_category.value}")
            return analysis_result
            
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            # Return safe fallback result
            return AIAnalysisResult(
                vulnerability_detected=False,
                confidence=0.0,
                severity=SeverityLevel.INFO,
                vulnerability_name="Analysis Failed",
                description=f"AI analysis failed: {str(e)}",
                evidence=[],
                remediation="Manual review required",
                analysis_reasoning=f"AI analysis error: {str(e)}"
            )
    
    def _build_analysis_prompt(self, context: AnalysisContext) -> str:
        """Build the analysis prompt from context."""
        template = self.prompt_templates["vulnerability_analysis"]
        
        # Get vulnerability patterns for this category
        patterns = self.vulnerability_patterns.get(context.owasp_category, [])
        patterns_text = "\n".join(f"- {pattern}" for pattern in patterns)
        
        # Truncate response body if too long
        response_body = context.response_body[:2000] if len(context.response_body) > 2000 else context.response_body
        
        return template.format(
            category=context.owasp_category.value,
            target_url=context.target_url,
            tech_stack=json.dumps(context.technology_stack, indent=2),
            payload=context.test_payload,
            method=context.request_method,
            request_headers=json.dumps(context.request_headers, indent=2),
            request_data=context.request_data or "None",
            status_code=context.response_status,
            response_headers=json.dumps(context.response_headers, indent=2),
            response_body=response_body,
            vulnerability_patterns=patterns_text
        )
    
    def _parse_analysis_response(self, response_text: str, context: AnalysisContext) -> AIAnalysisResult:
        """Parse AI response into structured analysis result."""
        try:
            # Extract JSON from response
            json_match = re.search(r'\{[^{}]*\{[^}]*\}[^{}]*\}|\{[^{}]*\}', response_text, re.DOTALL)
            if not json_match:
                raise ValueError("No valid JSON found in response")
            
            json_str = json_match.group()
            data = json.loads(json_str)
            
            # Validate and extract fields with defaults
            return AIAnalysisResult(
                vulnerability_detected=bool(data.get("vulnerability_detected", False)),
                confidence=float(data.get("confidence", 0.0)),
                severity=SeverityLevel(data.get("severity", "INFO")),
                vulnerability_name=str(data.get("vulnerability_name", "Unknown")),
                description=str(data.get("description", "No description provided")),
                evidence=list(data.get("evidence", [])),
                remediation=str(data.get("remediation", "No remediation provided")),
                cwe_id=data.get("cwe_id"),
                cvss_score=data.get("cvss_score"),
                false_positive_likelihood=float(data.get("false_positive_likelihood", 0.0)),
                analysis_reasoning=str(data.get("analysis_reasoning", ""))
            )
            
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            logger.error(f"Failed to parse AI response: {e}")
            logger.debug(f"Raw response: {response_text[:500]}...")
            
            # Return conservative fallback
            return AIAnalysisResult(
                vulnerability_detected=False,
                confidence=0.0,
                severity=SeverityLevel.INFO,
                vulnerability_name="Parse Error",
                description="Failed to parse AI analysis response",
                evidence=[],
                remediation="Manual review required",
                analysis_reasoning=f"Response parsing failed: {str(e)}"
            )
    
    async def evaluate_payload_effectiveness(
        self, 
        payload: str, 
        category: OWASPCategory,
        response_summary: str,
        detection_result: bool
    ) -> Dict[str, Any]:
        """Evaluate how effective a payload was for vulnerability detection."""
        try:
            await self._rate_limit_check()
            
            template = self.prompt_templates["payload_effectiveness"]
            prompt = template.format(
                payload=payload,
                category=category.value,
                response_summary=response_summary,
                detection_result=detection_result
            )
            
            response = await self.model.generate_content_async(prompt)
            
            # Parse response
            json_match = re.search(r'\{.*\}', response.text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            
            return {"effectiveness_score": 0.5}  # Fallback
            
        except Exception as e:
            logger.error(f"Payload effectiveness evaluation failed: {e}")
            return {"effectiveness_score": 0.0}
    
    async def learn_from_patterns(
        self, 
        successful_detections: List[Dict[str, Any]], 
        false_positives: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Learn from detection patterns to improve future accuracy."""
        try:
            await self._rate_limit_check()
            
            template = self.prompt_templates["pattern_learning"]
            prompt = template.format(
                successful_patterns=json.dumps(successful_detections[:10], indent=2),
                false_positive_patterns=json.dumps(false_positives[:10], indent=2)
            )
            
            response = await self.model.generate_content_async(prompt)
            
            # Parse response
            json_match = re.search(r'\{.*\}', response.text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            
            return {}  # Fallback
            
        except Exception as e:
            logger.error(f"Pattern learning failed: {e}")
            return {}
    
    async def generate_custom_payload(
        self, 
        category: OWASPCategory, 
        target_context: Dict[str, Any]
    ) -> List[str]:
        """Generate custom payloads based on target context and category."""
        try:
            await self._rate_limit_check()
            
            prompt = f"""
Generate 5 targeted test payloads for {category.value} testing based on the following context:

Target Context:
{json.dumps(target_context, indent=2)}

Requirements:
1. Payloads should be specific to the target technology stack
2. Focus on {category.value} vulnerability patterns
3. Consider the application context and likely input validation
4. Provide payloads that are likely to trigger detectable responses
5. Avoid destructive payloads

Return a JSON array of payload strings:
["payload1", "payload2", "payload3", "payload4", "payload5"]
"""
            
            response = await self.model.generate_content_async(prompt)
            
            # Parse response
            json_match = re.search(r'\[.*\]', response.text, re.DOTALL)
            if json_match:
                payloads = json.loads(json_match.group())
                return [str(payload) for payload in payloads if isinstance(payload, str)]
            
            return []  # Fallback
            
        except Exception as e:
            logger.error(f"Custom payload generation failed: {e}")
            return []
    
    async def _rate_limit_check(self) -> None:
        """Implement rate limiting for API calls."""
        now = datetime.now()
        time_diff = (now - self.last_request_time).total_seconds()
        
        # Rate limiting: max requests per minute
        if time_diff < 60:
            if self.request_count >= self.config.rate_limit:
                sleep_time = 60 - time_diff
                logger.debug(f"Rate limit reached, sleeping for {sleep_time:.2f} seconds")
                await asyncio.sleep(sleep_time)
                self.request_count = 0
                self.last_request_time = datetime.now()
        else:
            # Reset counter if more than a minute has passed
            self.request_count = 0
            self.last_request_time = now
        
        self.request_count += 1
    
    def create_vulnerability_finding(
        self, 
        analysis_result: AIAnalysisResult, 
        context: AnalysisContext
    ) -> Optional[VulnerabilityFinding]:
        """Convert AI analysis result to vulnerability finding."""
        if not analysis_result.vulnerability_detected:
            return None
        
        # Determine status based on confidence and false positive likelihood
        if analysis_result.confidence >= 0.9 and analysis_result.false_positive_likelihood <= 0.1:
            status = VulnerabilityStatus.CONFIRMED
        elif analysis_result.confidence >= 0.7 and analysis_result.false_positive_likelihood <= 0.3:
            status = VulnerabilityStatus.PROBABLE
        else:
            status = VulnerabilityStatus.POSSIBLE
        
        return VulnerabilityFinding(
            id="",  # Will be generated
            category=context.owasp_category,
            name=analysis_result.vulnerability_name,
            description=analysis_result.description,
            severity=analysis_result.severity,
            status=status,
            url=context.target_url,
            method=context.request_method,
            payload=context.test_payload,
            evidence="\n".join(analysis_result.evidence),
            remediation=analysis_result.remediation,
            cwe_id=analysis_result.cwe_id,
            cvss_score=analysis_result.cvss_score,
            confidence=analysis_result.confidence
        )
