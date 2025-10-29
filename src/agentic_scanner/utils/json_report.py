from typing import List
from ..agents.base import VulnerabilityFinding
from ..core.scanner import ScanSession
from pathlib import Path
import json

class JSONReportGenerator:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    async def generate(self, session: ScanSession, findings: List[VulnerabilityFinding]) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / f"report_{session.id}.json"
        data = {
            "session": {
                "id": session.id,
                "target": session.config.target_url,
                "started_at": session.started_at.isoformat(),
                "completed_at": session.completed_at.isoformat() if session.completed_at else None,
                "status": session.status
            },
            "findings": [
                {
                    "id": f.id,
                    "category": f.category.value,
                    "name": f.name,
                    "severity": f.severity.value,
                    "status": f.status.value,
                    "url": f.url,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "cwe_id": f.cwe_id,
                    "cvss": f.cvss_score,
                    "confidence": f.confidence
                } for f in findings
            ]
        }
        path.write_text(json.dumps(data, indent=2))
        return path
