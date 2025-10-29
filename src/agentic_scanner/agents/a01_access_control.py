from typing import List, Dict, Any, Optional
import re
import time
from loguru import logger
from ..core.config import ScannerConfig, OWASPCategory
from ..agents.base import BaseSecurityAgent, TestPayload, VulnerabilityFinding, SeverityLevel, VulnerabilityStatus
import aiohttp

class AccessControlAgent(BaseSecurityAgent):
    """A01: Broken Access Control testing agent."""

    def _get_category(self) -> OWASPCategory:
        return OWASPCategory.A01_BROKEN_ACCESS_CONTROL

    def _initialize_payloads(self) -> None:
        # Forced browsing and IDOR probes (non-destructive)
        self._payloads = [
            TestPayload(
                name="idor_numeric",
                payload="1",
                description="Replace identifier with nearby numeric IDs",
                category=self.category,
                method="GET"
            ),
            TestPayload(
                name="idor_uuid_like",
                payload="00000000-0000-0000-0000-000000000000",
                description="Try default/zero UUIDs",
                category=self.category,
                method="GET"
            ),
            TestPayload(
                name="role_downgrade_header",
                payload="",
                description="Suggest lower-privilege via header",
                category=self.category,
                method="GET",
                headers={"X-User-Role": "user"}
            ),
        ]

    async def _analyze_response(self, response: aiohttp.ClientResponse, payload: TestPayload) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        url = str(response.url)
        status = response.status
        body_text = ""
        try:
            body_text = (await response.text())[:4000]
        except Exception:
            pass

        context = f"URL: {url}\nStatus: {status}\nHeaders: {dict(response.headers)}\nPayload: {payload.name}"
        ai = await self.get_ai_analysis(context=context, response_data=body_text, payload=payload)
        if ai.get("vulnerability_detected"):
            try:
                sev = SeverityLevel(ai.get("severity", "MEDIUM"))
            except Exception:
                sev = SeverityLevel.MEDIUM
            finding = VulnerabilityFinding(
                id="",
                category=self.category,
                name=ai.get("vulnerability_name", "Broken Access Control"),
                description=ai.get("description", "Potential access control weakness"),
                severity=sev,
                status=VulnerabilityStatus.PROBABLE,
                url=url,
                method=payload.method,
                payload=payload.payload,
                evidence=ai.get("evidence"),
                remediation=ai.get("remediation"),
                cwe_id=ai.get("cwe_id"),
                cvss_score=ai.get("cvss_score"),
                confidence=float(ai.get("confidence", 0.5)),
            )
            findings.append(finding)
        return findings
