"""
Access Control (A01) testing agent implementation.
"""
from typing import List, Dict, Any, Optional
import aiohttp
from loguru import logger

from .base import (
    BaseSecurityAgent,
    TestPayload,
    VulnerabilityFinding,
    SeverityLevel,
    VulnerabilityStatus,
    TestResult,
)
from ..core.config import OWASPCategory, ScannerConfig


class AccessControlAgent(BaseSecurityAgent):
    def _get_category(self) -> OWASPCategory:
        return OWASPCategory.A01_BROKEN_ACCESS_CONTROL

    def _initialize_payloads(self) -> None:
        self._payloads = [
            TestPayload(
                name="Forced browsing",
                payload="",
                description="Attempt access to common restricted paths",
                category=self.category,
                method="GET",
            ),
            TestPayload(
                name="IDOR numeric",
                payload="1337",
                description="Replace numeric identifiers with alternate values",
                category=self.category,
                method="GET",
            ),
            TestPayload(
                name="JWT none alg",
                payload="JWT_NONE_ALG",
                description="Attempt token bypass using alg=none (simulated)",
                category=self.category,
                method="GET",
            ),
        ]

    async def _analyze_response(self, response: aiohttp.ClientResponse, payload: TestPayload) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        try:
            status = response.status
            url = str(response.url)
            headers = dict(response.headers)
            text = (await response.text())[:2000]

            # Simple heuristics before AI triage
            indicators: List[str] = []
            if status == 200 and any(k in url.lower() for k in ["/admin", "/manage", "/internal"]):
                indicators.append("Accessible admin-like path without auth")
            if "role" in text.lower() and "admin" in text.lower() and status == 200:
                indicators.append("Admin content leaked in response")
            if "x-robots-tag" in headers and "noindex" in headers.get("x-robots-tag", "").lower():
                indicators.append("Sensitive page hint via robots tag")

            # AI corroboration
            ctx = (
                f"URL: {url}\nHeaders: {headers}\nStatus: {status}\nSnippet: {text[:800]}\n"
            )
            ai = await self.get_ai_analysis(ctx, text, payload)
            if ai.get("vulnerability_detected"):
                severity = SeverityLevel(ai.get("severity", "MEDIUM")) if ai.get("severity") in SeverityLevel.__members__ else SeverityLevel.MEDIUM
                finding = VulnerabilityFinding(
                    id="",
                    category=self.category,
                    name="Broken Access Control",
                    description=ai.get("description", "Potential unauthorized access"),
                    severity=severity,
                    status=VulnerabilityStatus.PROBABLE,
                    url=url,
                    method=payload.method,
                    payload=payload.payload,
                    evidence="; ".join(indicators + ai.get("evidence", [])),
                    remediation=ai.get("remediation", "Enforce authorization checks and least privilege"),
                    cwe_id=ai.get("cwe_id", "CWE-284"),
                    confidence=float(ai.get("confidence", 0.7)),
                )
                findings.append(finding)

            return findings
        except Exception as e:
            logger.error(f"A01 analysis error: {e}")
            return findings
