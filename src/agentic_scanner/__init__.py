"""
Agentic OWASP Security Scanner

An autonomous AI-powered web application security testing tool that implements
comprehensive OWASP Top 10 vulnerability assessments using Google's Gemini Flash.
"""

__version__ = "0.1.0"
__author__ = "Shayan Banerjee"
__email__ = "streetquant@example.com"
__description__ = "Autonomous AI-powered OWASP Top 10 security testing system"

from .core.scanner import AgenticScanner
from .core.config import ScannerConfig
from .agents.base import BaseSecurityAgent

__all__ = [
    "AgenticScanner",
    "ScannerConfig", 
    "BaseSecurityAgent",
]