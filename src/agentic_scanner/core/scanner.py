"""
Main scanner orchestrator for the Agentic OWASP Security Scanner.

This module coordinates all security testing agents, manages the scanning workflow,
and provides the primary interface for conducting comprehensive security assessments.
"""

import asyncio
from typing import Dict, List, Optional, Type, Any
from datetime import datetime, timedelta
from pathlib import Path
import uuid

import aiohttp
from loguru import logger
from rich.console import Console
from rich.progress import Progress, TaskID, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel

from .config import ScannerConfig, OWASPCategory
from .memory import MemoryManager
from .planning import ScanPlanner
from .reasoning import ReasoningEngine
from ..agents.base import BaseSecurityAgent, TestResult, VulnerabilityFinding
from ..utils.discovery import WebDiscovery
from ..utils.reporting import ReportGenerator


class ScanSession:
    """Represents a scanning session with metadata and state."""
    
    def __init__(self, config: ScannerConfig):
        self.id = str(uuid.uuid4())
        self.config = config
        self.started_at = datetime.now()
        self.completed_at: Optional[datetime] = None
        self.status = "RUNNING"
        self.findings: List[VulnerabilityFinding] = []
        self.agent_results: Dict[str, TestResult] = {}
        self.discovered_urls: List[str] = []
        self.errors: List[str] = []


class AgenticScanner:
    """Main orchestrator for autonomous OWASP Top 10 security testing."""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.console = Console()
        self.session: Optional[ScanSession] = None
        self.agents: Dict[OWASPCategory, BaseSecurityAgent] = {}
        
        # Core components
        self.memory_manager = MemoryManager(config.memory)
        self.planner = ScanPlanner(config)
        self.reasoning_engine = ReasoningEngine(config.api)
        self.discovery = WebDiscovery(config)
        self.report_generator = ReportGenerator(config.reporting)
        
        # HTTP session for shared use
        self.http_session: Optional[aiohttp.ClientSession] = None
        
        # Initialize logging
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Configure logging based on configuration."""
        logger.remove()  # Remove default handler
        
        log_format = self.config.logging.format
        log_level = self.config.logging.level.value
        
        # Console logging
        logger.add(
            lambda msg: self.console.print(msg, style="dim") if not msg.strip().startswith("[") else None,
            level=log_level,
            format=log_format,
            colorize=True
        )
        
        # File logging if configured
        if self.config.logging.file:
            logger.add(
                self.config.logging.file,
                level=log_level,
                format=log_format,
                rotation=f"{self.config.logging.max_size} MB",
                retention=self.config.logging.backup_count
            )
    
    async def initialize(self) -> None:
        """Initialize all components and agents."""
        self.console.print(Panel.fit(
            "🤖 Agentic OWASP Security Scanner v0.1.0\n"
            "Autonomous AI-powered web application security testing",
            style="bold blue"
        ))
        
        logger.info("Initializing scanner components...")
        
        # Initialize HTTP session
        timeout = aiohttp.ClientTimeout(total=self.config.testing.timeout)
        connector = aiohttp.TCPConnector(
            limit=self.config.testing.concurrent_requests,
            verify_ssl=self.config.testing.verify_ssl
        )
        self.http_session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector
        )
        
        # Initialize core components
        await self.memory_manager.initialize()
        await self.reasoning_engine.initialize()
        
        # Load and initialize agents
        await self._load_agents()
        
        logger.info("Scanner initialization complete")
    
    async def _load_agents(self) -> None:
        """Dynamically load and initialize security testing agents."""
        agent_classes = self._get_agent_classes()
        
        for category in self.config.categories:
            if category in agent_classes:
                agent_class = agent_classes[category]
                agent = agent_class(self.config, self.http_session)
                await agent.initialize()
                self.agents[category] = agent
                logger.info(f"Loaded agent for {category.value}")
    
    def _get_agent_classes(self) -> Dict[OWASPCategory, Type[BaseSecurityAgent]]:
        """Get mapping of OWASP categories to agent classes."""
        from ..agents.a01_access_control import AccessControlAgent
        from ..agents.a02_crypto_failures import CryptographicFailuresAgent
        from ..agents.a03_injection import InjectionAgent
        from ..agents.a04_insecure_design import InsecureDesignAgent
        from ..agents.a05_misconfiguration import MisconfigurationAgent
        from ..agents.a06_vulnerable_components import VulnerableComponentsAgent
        from ..agents.a07_auth_failures import AuthenticationFailuresAgent
        from ..agents.a08_data_integrity import DataIntegrityAgent
        from ..agents.a09_logging_failures import LoggingFailuresAgent
        from ..agents.a10_ssrf import SSRFAgent
        
        return {
            OWASPCategory.A01_BROKEN_ACCESS_CONTROL: AccessControlAgent,
            OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES: CryptographicFailuresAgent,
            OWASPCategory.A03_INJECTION: InjectionAgent,
            OWASPCategory.A04_INSECURE_DESIGN: InsecureDesignAgent,
            OWASPCategory.A05_SECURITY_MISCONFIGURATION: MisconfigurationAgent,
            OWASPCategory.A06_VULNERABLE_COMPONENTS: VulnerableComponentsAgent,
            OWASPCategory.A07_AUTH_FAILURES: AuthenticationFailuresAgent,
            OWASPCategory.A08_DATA_INTEGRITY_FAILURES: DataIntegrityAgent,
            OWASPCategory.A09_LOGGING_FAILURES: LoggingFailuresAgent,
            OWASPCategory.A10_SSRF: SSRFAgent
        }
    
    async def run_full_assessment(self) -> ScanSession:
        """Run comprehensive OWASP Top 10 security assessment."""
        self.session = ScanSession(self.config)
        
        try:
            self.console.print(f"🎯 Target: {self.config.target_url}")
            self.console.print(f"📅 Started: {self.session.started_at.strftime('%Y-%m-%d %H:%M:%S %Z')}")
            self.console.print()
            
            # Phase 1: Discovery and reconnaissance
            await self._discovery_phase()
            
            # Phase 2: AI-powered vulnerability analysis
            await self._analysis_phase()
            
            # Phase 3: Results compilation and reporting
            await self._reporting_phase()
            
            self.session.completed_at = datetime.now()
            self.session.status = "COMPLETED"
            
            # Save session to memory
            await self.memory_manager.save_session(self.session)
            
            return self.session
            
        except Exception as e:
            logger.error(f"Assessment failed: {str(e)}")
            self.session.status = "FAILED"
            self.session.errors.append(str(e))
            raise
    
    async def _discovery_phase(self) -> None:
        """Phase 1: Reconnaissance and discovery."""
        self.console.print("🔍 Phase 1: Reconnaissance and Discovery", style="bold cyan")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True
        ) as progress:
            
            # Technology stack detection
            task1 = progress.add_task("🌐 Technology Stack Detection", total=None)
            tech_info = await self.discovery.detect_technology_stack(self.config.target_url)
            progress.update(task1, description="🌐 Technology Stack Detection: Completed")
            
            # Application mapping
            task2 = progress.add_task("🗺️ Application Mapping", total=None)
            discovered_urls = await self.discovery.discover_endpoints(
                self.config.target_url, 
                max_depth=self.config.testing.max_depth
            )
            self.session.discovered_urls = discovered_urls
            progress.update(task2, description=f"🗺️ Application Mapping: {len(discovered_urls)} endpoints discovered")
            
            # Authentication analysis
            task3 = progress.add_task("🔐 Authentication Analysis", total=None)
            auth_info = await self.discovery.analyze_authentication(self.config.target_url)
            progress.update(task3, description=f"🔐 Authentication Analysis: {len(auth_info.get('mechanisms', []))} auth mechanisms found")
            
            # Input parameter enumeration
            task4 = progress.add_task("📋 Input Parameter Enumeration", total=None)
            parameters = await self.discovery.enumerate_parameters(discovered_urls)
            progress.update(task4, description=f"📋 Input Parameter Enumeration: {len(parameters)} parameters identified")
        
        self.console.print()
    
    async def _analysis_phase(self) -> None:
        """Phase 2: AI-powered vulnerability analysis."""
        self.console.print("🧠 Phase 2: AI-Powered Vulnerability Analysis", style="bold cyan")
        
        # Create progress table
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Category", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Critical", justify="center", style="red")
        table.add_column("High", justify="center", style="orange1")
        table.add_column("Medium", justify="center", style="yellow")
        table.add_column("Low", justify="center", style="green")
        
        # Run agents concurrently with controlled concurrency
        semaphore = asyncio.Semaphore(3)  # Limit concurrent agents
        tasks = []
        
        for category, agent in self.agents.items():
            task = asyncio.create_task(self._run_agent_with_semaphore(semaphore, agent, category))
            tasks.append(task)
        
        # Wait for all agents to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results and update table
        for i, result in enumerate(results):
            category = list(self.agents.keys())[i]
            
            if isinstance(result, Exception):
                table.add_row(
                    f"🚨 {category.value}",
                    "❌ FAILED",
                    "0", "0", "0", "0"
                )
                self.session.errors.append(f"{category.value}: {str(result)}")
            else:
                self.session.agent_results[category.value] = result
                self.session.findings.extend(result.vulnerabilities)
                
                # Count findings by severity
                counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
                for vuln in result.vulnerabilities:
                    if vuln.severity.value in counts:
                        counts[vuln.severity.value] += 1
                
                status = "✅ COMPLETED" if result.success else "⚠️ PARTIAL"
                
                table.add_row(
                    f"🛡️ {category.value}",
                    status,
                    str(counts["CRITICAL"]),
                    str(counts["HIGH"]),
                    str(counts["MEDIUM"]),
                    str(counts["LOW"])
                )
        
        self.console.print(table)
        self.console.print()
    
    async def _run_agent_with_semaphore(
        self, 
        semaphore: asyncio.Semaphore, 
        agent: BaseSecurityAgent,
        category: OWASPCategory
    ) -> TestResult:
        """Run agent with concurrency control."""
        async with semaphore:
            logger.info(f"Starting {category.value} analysis...")
            
            all_vulnerabilities = []
            all_errors = []
            total_time = 0.0
            
            # Test discovered URLs
            async for result in agent.run_comprehensive_test(self.session.discovered_urls):
                all_vulnerabilities.extend(result.vulnerabilities)
                all_errors.extend(result.errors)
                total_time += result.execution_time
            
            return TestResult(
                success=len(all_errors) == 0,
                vulnerabilities=all_vulnerabilities,
                errors=all_errors,
                execution_time=total_time,
                metadata={"category": category.value, "urls_tested": len(self.session.discovered_urls)}
            )
    
    async def _reporting_phase(self) -> None:
        """Phase 3: Results compilation and reporting."""
        self.console.print("📊 Phase 3: Report Generation", style="bold cyan")
        
        # Generate comprehensive report
        report_path = await self.report_generator.generate_report(
            session=self.session,
            findings=self.session.findings
        )
        
        # Display summary
        self._display_summary(report_path)
    
    def _display_summary(self, report_path: Path) -> None:
        """Display scan summary."""
        # Count findings by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        
        for finding in self.session.findings:
            if finding.severity.value in severity_counts:
                severity_counts[finding.severity.value] += 1
        
        total_findings = sum(severity_counts.values())
        
        # Create summary panel
        summary_text = f"""
✅ Assessment Complete!
📊 Total Findings: {severity_counts['CRITICAL']} CRITICAL, {severity_counts['HIGH']} HIGH, {severity_counts['MEDIUM']} MEDIUM, {severity_counts['LOW']} LOW
📄 Report: {report_path}
⏱️  Duration: {self._format_duration()}
🔗 URLs Tested: {len(self.session.discovered_urls)}
        """.strip()
        
        self.console.print(Panel(
            summary_text,
            title="Scan Results",
            style="green" if severity_counts['CRITICAL'] == 0 else "red"
        ))
    
    def _format_duration(self) -> str:
        """Format scan duration."""
        if not self.session.completed_at:
            return "Unknown"
        
        duration = self.session.completed_at - self.session.started_at
        return str(timedelta(seconds=int(duration.total_seconds())))
    
    async def cleanup(self) -> None:
        """Clean up all resources."""
        logger.info("Cleaning up scanner resources...")
        
        # Cleanup agents
        for agent in self.agents.values():
            await agent.cleanup()
        
        # Cleanup HTTP session
        if self.http_session and not self.http_session.closed:
            await self.http_session.close()
        
        # Cleanup core components
        await self.memory_manager.cleanup()
        
        logger.info("Cleanup complete")
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.cleanup()
