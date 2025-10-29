from typing import List, Dict, Any, Optional
import re
from loguru import logger
from ..core.config import ScannerConfig, OWASPCategory
from ..agents.base import BaseSecurityAgent, TestPayload, VulnerabilityFinding, SeverityLevel, VulnerabilityStatus
import aiohttp

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\") OR (\"1\"=\"1",
    "admin' --",
]

NOSQLI_PAYLOADS = [
    '{"$ne": null}', '{"$gt": ""}', '{"$or": [{}, {"a": {"$gt": ""}}]}'
]

class InjectionAgent(BaseSecurityAgent):
    """A03: Injection testing agent (SQLi/NoSQLi/LDAP basic stubs)."""

    def _get_category(self) -> OWASPCategory:
        return OWASPCategory.A03_INJECTION

    def _initialize_payloads(self) -> None:
        self._payloads = []
        for p in SQLI_PAYLOADS:
            self._payloads.append(TestPayload(
                name=f"sqli:{p}", payload=p, description="SQL injection probe", category=self.category, method="POST"
            ))
        for p in NOSQLI_PAYLOADS:
            self._payloads.append(TestPayload(
                name=f"nosqli:{p}", payload=p, description="NoSQL injection probe", category=self.category, method="POST", content_type="application/json",
                headers={"Content-Type": "application/json"}
            ))

    async def _analyze_response(self, response: aiohttp.ClientResponse, payload: TestPayload) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        url = str(response.url)
        status = response.status
        text = ""
        try:
            text = (await response.text())[:4000]
        except Exception:
            pass

        context = f"URL: {url}\nStatus: {status}\nPayload: {payload.payload}\nType: {payload.name}"
        ai = await self.get_ai_analysis(context=context, response_data=text, payload=payload)
        if ai.get("vulnerability_detected"):
            try:
                sev = SeverityLevel(ai.get("severity", "HIGH"))
            except Exception:
                sev = SeverityLevel.HIGH
            finding = VulnerabilityFinding(
                id="",
                category=self.category,
                name=ai.get("vulnerability_name", "Injection"),
                description=ai.get("description", "Potential injection vulnerability"),
                severity=sev,
                status=VulnerabilityStatus.PROBABLE,
                url=url,
                method=payload.method,
                payload=payload.payload,
                evidence=ai.get("evidence"),
                remediation=ai.get("remediation"),
                cwe_id=ai.get("cwe_id"),
                cvss_score=ai.get("cvss_score"),
                confidence=float(ai.get("confidence", 0.6)),
            )
            findings.append(finding)
        return findings
