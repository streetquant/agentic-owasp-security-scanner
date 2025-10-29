from typing import List
from pathlib import Path
from ..agents.base import VulnerabilityFinding, SeverityLevel
from ..core.scanner import ScanSession

HTML_HEADER = """
<html><head><meta charset="utf-8"><title>AOSS Report</title>
<style>
body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial}
.badge{padding:2px 6px;border-radius:6px;font-size:12px}
.CRITICAL{background:#b71c1c;color:#fff}
.HIGH{background:#e65100;color:#fff}
.MEDIUM{background:#fbc02d;color:#000}
.LOW{background:#43a047;color:#fff}
</style>
</head><body>
"""

class ReportGenerator:
    def __init__(self, reporting_config):
        self.cfg = reporting_config

    async def generate_report(self, session: ScanSession, findings: List[VulnerabilityFinding]) -> Path:
        out = self.cfg.output_dir / f"report_{session.id}.html"
        self.cfg.output_dir.mkdir(parents=True, exist_ok=True)
        rows = []
        for f in findings:
            rows.append(
                f"<tr><td>{f.category.value}</td><td>{f.name}</td><td><span class='badge {f.severity.value}'>{f.severity.value}</span></td><td>{f.url}</td><td>{(f.evidence or '')[:120]}</td></tr>"
            )
        html = [HTML_HEADER, f"<h1>Scan {session.id}</h1>", f"<p>Target: {session.config.target_url}</p>", "<table border=1 cellspacing=0 cellpadding=6>", "<tr><th>Category</th><th>Name</th><th>Severity</th><th>URL</th><th>Evidence</th></tr>", *rows, "</table>", "</body></html>"]
        out.write_text("\n".join(html))
        return out
