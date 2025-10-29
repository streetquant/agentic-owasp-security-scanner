import asyncio
import os
from pathlib import Path
from typer.testing import CliRunner
from agentic_scanner.cli import app

runner = CliRunner()

def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Agentic OWASP Security Scanner" in result.stdout
