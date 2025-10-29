from typing import List, Dict, Any, Optional
from loguru import logger
from .base import BaseSecurityAgent, TestPayload, VulnerabilityFinding, SeverityLevel, VulnerabilityStatus
from ..core.config import OWASPCategory, ScannerConfig
import aiohttp

class AccessControlAgent(BaseSecurityAgent):
    """A01: Broken Access Control testing agent."""

    def _get_category(self) -> OWASPCategory:
        return OWASPCategory.A01_BROKEN_ACCESS_CONTROL

    def _initialize_payloads(self) -> None:
        # Access control often relies on path manipulation and header/cookie changes rather than body payloads
        self._payloads = [
            TestPayload(
                name="role_downgrade_header",
                payload="",
                description="Attempt role downgrade via X-Original-Role header",
                category=self.category,
                content_type="",
                method="GET",
                headers={"X-Original-Role": "user"}
            ),
            TestPayload(
                name="force_browse_admin",
                payload="",
                description="Try to access common admin routes directly",
                category=self.category,
                content_type="",
                method="GET"
            )
        ]

    async def _analyze_response(self, response: aiohttp.ClientResponse, payload: TestPayload) -> List[VulnerabilityFinding]:
        vulns: List[VulnerabilityFinding] = []
        url = str(response.url)
        status = response.status
        text = (await response.text())[:2000]

        context = f"URL: {url} | Status: {status}"
        ai = await self.get_ai_analysis(context=context, response_data=text, payload=payload)
        if ai.get("vulnerability_detected"):
            finding = VulnerabilityFinding(
                id="",
                category=self.category,
                name=ai.get("vulnerability_name", "Broken Access Control"),
                description=ai.get("description", "Possible access control issue"),
                severity=SeverityLevel(ai.get("severity", "HIGH")),
                status=VulnerabilityStatus.PROBABLE,
                url=url,
                evidence=ai.get("evidence"),
                remediation=ai.get("remediation")
            )
            vulns.append(finding)
        return vulns
