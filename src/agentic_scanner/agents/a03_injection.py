from typing import List, Dict, Any, Optional
import aiohttp
from .base import BaseSecurityAgent, TestPayload, VulnerabilityFinding, SeverityLevel, VulnerabilityStatus
from ..core.config import OWASPCategory

class InjectionAgent(BaseSecurityAgent):
    """A03: Injection testing agent (SQLi/NoSQLi/basic)."""

    def _get_category(self) -> OWASPCategory:
        return OWASPCategory.A03_INJECTION

    def _initialize_payloads(self) -> None:
        self._payloads = [
            TestPayload(name="sqli_boolean", payload="' OR '1'='1", description="Boolean-based SQLi", category=self.category),
            TestPayload(name="sqli_time", payload="' OR SLEEP(3)-- ", description="Time-based SQLi", category=self.category),
            TestPayload(name="nosqli_basic", payload="{""$ne"": null}", description="Basic NoSQLi", category=self.category, content_type="application/json"),
        ]

    async def _analyze_response(self, response: aiohttp.ClientResponse, payload: TestPayload) -> List[VulnerabilityFinding]:
        vulns: List[VulnerabilityFinding] = []
        url = str(response.url)
        status = response.status
        body = (await response.text())[:2000]
        context = f"URL: {url} | Status: {status} | Payload: {payload.name}"
        ai = await self.get_ai_analysis(context=context, response_data=body, payload=payload)
        if ai.get("vulnerability_detected"):
            vulns.append(VulnerabilityFinding(
                id="",
                category=self.category,
                name=ai.get("vulnerability_name", "Injection"),
                description=ai.get("description", "Potential injection vulnerability"),
                severity=SeverityLevel(ai.get("severity", "HIGH")),
                status=VulnerabilityStatus.PROBABLE,
                url=url,
                parameter=None,
                payload=payload.payload,
                evidence=ai.get("evidence"),
                remediation=ai.get("remediation"),
                cwe_id=ai.get("cwe_id")
            ))
        return vulns
