"""
Injection (A03) testing agent implementation.
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
from ..core.config import OWASPCategory

SQLI_PROBES = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT NULL--",
]

TIME_PROBES = [
    "'; WAITFOR DELAY '0:0:3'--",
]

class InjectionAgent(BaseSecurityAgent):
    def _get_category(self) -> OWASPCategory:
        return OWASPCategory.A03_INJECTION

    def _initialize_payloads(self) -> None:
        payloads: List[TestPayload] = []
        for s in SQLI_PROBES:
            payloads.append(TestPayload(
                name=f"SQLi probe {s}",
                payload=s,
                description="Basic SQL injection probe",
                category=self.category,
                method="POST",
                content_type="application/x-www-form-urlencoded",
            ))
        for t in TIME_PROBES:
            payloads.append(TestPayload(
                name=f"Time-based {t}",
                payload=t,
                description="Time-based SQLi probe",
                category=self.category,
                method="POST",
            ))
        self._payloads = payloads

    async def _analyze_response(self, response: aiohttp.ClientResponse, payload: TestPayload) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        try:
            status = response.status
            url = str(response.url)
            text = (await response.text())[:4000]

            indicators: List[str] = []
            # Simple reflective error patterns
            error_markers = [
                "you have an error in your sql syntax",
                "warning: mysql",
                "unclosed quotation mark",
                "sqlstate[",
                "pg_query():",
            ]
            lowtext = text.lower()
            for m in error_markers:
                if m in lowtext:
                    indicators.append(f"DB error marker: {m}")

            ctx = f"URL: {url}\nStatus: {status}\nSnippet: {text[:1000]}\nPayload: {payload.payload}"
            ai = await self.get_ai_analysis(ctx, text, payload)
            if ai.get("vulnerability_detected") or indicators:
                severity = SeverityLevel.HIGH
                finding = VulnerabilityFinding(
                    id="",
                    category=self.category,
                    name="Injection",
                    description=ai.get("description", "Possible injection vulnerability"),
                    severity=severity,
                    status=VulnerabilityStatus.PROBABLE,
                    url=url,
                    method=payload.method,
                    payload=payload.payload,
                    evidence="; ".join(indicators + ai.get("evidence", [])),
                    remediation=ai.get("remediation", "Use parameterized queries and input validation"),
                    cwe_id=ai.get("cwe_id", "CWE-89"),
                    confidence=float(ai.get("confidence", 0.7)),
                )
                findings.append(finding)

            return findings
        except Exception as e:
            logger.error(f"A03 analysis error: {e}")
            return findings
