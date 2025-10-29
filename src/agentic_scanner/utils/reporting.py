from pathlib import Path
from typing import List
from ..agents.base import VulnerabilityFinding
from ..core.scanner import ScanSession

class ReportGenerator:
    def __init__(self, reporting_config):
        self.cfg = reporting_config

    async def generate_report(self, session: ScanSession, findings: List[VulnerabilityFinding]) -> Path:
        out = self.cfg.output_dir / f"report_{session.id}.html"
        self.cfg.output_dir.mkdir(parents=True, exist_ok=True)
        html = ["<html><body>", f"<h1>Scan {session.id}</h1>"]
        html.append(f"<p>Target: {session.config.target_url}</p>")
        html.append(f"<p>Total findings: {len(findings)}</p>")
        html.append("</body></html>")
        out.write_text("\n".join(html))
        return out
