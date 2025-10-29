"""
Planning and goal management system for the Agentic OWASP Scanner.

This module implements strategic planning capabilities that break down complex
security testing objectives into manageable, executable tasks with proper
dependency management and resource allocation.
"""

import asyncio
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import uuid

from loguru import logger

from .config import ScannerConfig, OWASPCategory


class TaskStatus(str, Enum):
    """Task execution status."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class TaskPriority(int, Enum):
    """Task priority levels."""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


@dataclass
class ScanTask:
    """Represents a single scanning task."""
    id: str
    name: str
    description: str
    category: OWASPCategory
    priority: TaskPriority
    estimated_duration: timedelta
    dependencies: Set[str] = field(default_factory=set)
    resources_required: Dict[str, Any] = field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Any] = None
    error: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    
    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())[:8]


@dataclass
class ScanPlan:
    """Represents a complete scanning plan with tasks and execution strategy."""
    id: str
    name: str
    target_url: str
    tasks: List[ScanTask] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    estimated_total_duration: timedelta = field(default_factory=lambda: timedelta(0))
    
    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())[:8]


class ScanPlanner:
    """Strategic planner for security testing operations."""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.current_plan: Optional[ScanPlan] = None
        self.task_templates = self._initialize_task_templates()
        
    def _initialize_task_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize templates for different types of scanning tasks."""
        return {
            "discovery": {
                "technology_detection": {
                    "name": "Technology Stack Detection",
                    "description": "Identify web technologies, frameworks, and server information",
                    "priority": TaskPriority.CRITICAL,
                    "estimated_duration": timedelta(minutes=2),
                    "dependencies": set(),
                    "resources": {"network": True, "ai_analysis": True}
                },
                "endpoint_discovery": {
                    "name": "Endpoint Discovery",
                    "description": "Crawl and map application endpoints and resources",
                    "priority": TaskPriority.CRITICAL,
                    "estimated_duration": timedelta(minutes=10),
                    "dependencies": {"technology_detection"},
                    "resources": {"network": True, "high_bandwidth": True}
                },
                "parameter_enumeration": {
                    "name": "Parameter Enumeration",
                    "description": "Identify input parameters and data entry points",
                    "priority": TaskPriority.HIGH,
                    "estimated_duration": timedelta(minutes=5),
                    "dependencies": {"endpoint_discovery"},
                    "resources": {"network": True, "parsing": True}
                },
                "authentication_analysis": {
                    "name": "Authentication Analysis",
                    "description": "Analyze authentication mechanisms and session management",
                    "priority": TaskPriority.HIGH,
                    "estimated_duration": timedelta(minutes=3),
                    "dependencies": {"endpoint_discovery"},
                    "resources": {"network": True, "ai_analysis": True}
                }
            },
            "vulnerability_testing": {
                "A01": {
                    "name": "Access Control Testing",
                    "description": "Test for broken access control vulnerabilities",
                    "priority": TaskPriority.HIGH,
                    "estimated_duration": timedelta(minutes=15),
                    "dependencies": {"parameter_enumeration", "authentication_analysis"},
                    "resources": {"network": True, "ai_analysis": True, "payload_generation": True}
                },
                "A02": {
                    "name": "Cryptographic Testing",
                    "description": "Test for cryptographic failures and weak implementations",
                    "priority": TaskPriority.MEDIUM,
                    "estimated_duration": timedelta(minutes=8),
                    "dependencies": {"technology_detection"},
                    "resources": {"network": True, "crypto_analysis": True, "ai_analysis": True}
                },
                "A03": {
                    "name": "Injection Testing",
                    "description": "Test for SQL, NoSQL, command, and other injection vulnerabilities",
                    "priority": TaskPriority.CRITICAL,
                    "estimated_duration": timedelta(minutes=20),
                    "dependencies": {"parameter_enumeration"},
                    "resources": {"network": True, "ai_analysis": True, "payload_generation": True, "high_cpu": True}
                },
                "A04": {
                    "name": "Design Analysis",
                    "description": "Analyze for insecure design patterns and business logic flaws",
                    "priority": TaskPriority.MEDIUM,
                    "estimated_duration": timedelta(minutes=12),
                    "dependencies": {"endpoint_discovery", "authentication_analysis"},
                    "resources": {"network": True, "ai_analysis": True, "workflow_analysis": True}
                },
                "A05": {
                    "name": "Configuration Testing",
                    "description": "Test for security misconfigurations and default settings",
                    "priority": TaskPriority.HIGH,
                    "estimated_duration": timedelta(minutes=10),
                    "dependencies": {"technology_detection"},
                    "resources": {"network": True, "ai_analysis": True, "config_analysis": True}
                },
                "A06": {
                    "name": "Component Analysis",
                    "description": "Analyze vulnerable and outdated components",
                    "priority": TaskPriority.MEDIUM,
                    "estimated_duration": timedelta(minutes=7),
                    "dependencies": {"technology_detection"},
                    "resources": {"network": True, "vulnerability_db": True, "ai_analysis": True}
                },
                "A07": {
                    "name": "Authentication Testing",
                    "description": "Test identification and authentication failures",
                    "priority": TaskPriority.HIGH,
                    "estimated_duration": timedelta(minutes=12),
                    "dependencies": {"authentication_analysis"},
                    "resources": {"network": True, "ai_analysis": True, "session_management": True}
                },
                "A08": {
                    "name": "Integrity Testing",
                    "description": "Test software and data integrity failures",
                    "priority": TaskPriority.MEDIUM,
                    "estimated_duration": timedelta(minutes=8),
                    "dependencies": {"endpoint_discovery"},
                    "resources": {"network": True, "ai_analysis": True, "integrity_validation": True}
                },
                "A09": {
                    "name": "Logging Analysis",
                    "description": "Evaluate security logging and monitoring failures",
                    "priority": TaskPriority.LOW,
                    "estimated_duration": timedelta(minutes=5),
                    "dependencies": {"endpoint_discovery"},
                    "resources": {"network": True, "ai_analysis": True, "log_analysis": True}
                },
                "A10": {
                    "name": "SSRF Testing",
                    "description": "Test for Server-Side Request Forgery vulnerabilities",
                    "priority": TaskPriority.HIGH,
                    "estimated_duration": timedelta(minutes=10),
                    "dependencies": {"parameter_enumeration"},
                    "resources": {"network": True, "ai_analysis": True, "payload_generation": True}
                }
            }
        }
    
    async def create_scan_plan(self, target_url: str) -> ScanPlan:
        """Create a comprehensive scan plan based on configuration and target analysis."""
        logger.info(f"Creating scan plan for {target_url}")
        
        plan = ScanPlan(
            id=str(uuid.uuid4())[:8],
            name=f"OWASP Top 10 Scan - {target_url}",
            target_url=target_url
        )
        
        # Add discovery tasks
        discovery_tasks = await self._create_discovery_tasks()
        plan.tasks.extend(discovery_tasks)
        
        # Add vulnerability testing tasks based on enabled categories
        vuln_tasks = await self._create_vulnerability_tasks()
        plan.tasks.extend(vuln_tasks)
        
        # Add reporting task
        reporting_task = await self._create_reporting_task()
        plan.tasks.append(reporting_task)
        
        # Calculate total estimated duration
        plan.estimated_total_duration = sum(
            (task.estimated_duration for task in plan.tasks),
            timedelta(0)
        )
        
        # Optimize task order based on dependencies and priorities
        plan.tasks = self._optimize_task_order(plan.tasks)
        
        self.current_plan = plan
        
        logger.info(
            f"Created scan plan with {len(plan.tasks)} tasks, "
            f"estimated duration: {plan.estimated_total_duration}"
        )
        
        return plan
    
    async def _create_discovery_tasks(self) -> List[ScanTask]:
        """Create discovery and reconnaissance tasks."""
        tasks = []
        discovery_templates = self.task_templates["discovery"]
        
        for task_key, template in discovery_templates.items():
            task = ScanTask(
                id=f"discovery_{task_key}",
                name=template["name"],
                description=template["description"],
                category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,  # Discovery is general
                priority=template["priority"],
                estimated_duration=template["estimated_duration"],
                dependencies=template["dependencies"],
                resources_required=template["resources"]
            )
            tasks.append(task)
        
        return tasks
    
    async def _create_vulnerability_tasks(self) -> List[ScanTask]:
        """Create vulnerability testing tasks for enabled OWASP categories."""
        tasks = []
        vuln_templates = self.task_templates["vulnerability_testing"]
        
        for category in self.config.categories:
            category_key = category.value
            if category_key in vuln_templates:
                template = vuln_templates[category_key]
                
                task = ScanTask(
                    id=f"vuln_{category_key.lower()}",
                    name=template["name"],
                    description=template["description"],
                    category=category,
                    priority=template["priority"],
                    estimated_duration=template["estimated_duration"],
                    dependencies=template["dependencies"],
                    resources_required=template["resources"]
                )
                tasks.append(task)
        
        return tasks
    
    async def _create_reporting_task(self) -> ScanTask:
        """Create the final reporting task."""
        # Get all vulnerability task IDs as dependencies
        vuln_task_deps = {f"vuln_{cat.value.lower()}" for cat in self.config.categories}
        
        return ScanTask(
            id="reporting",
            name="Report Generation",
            description="Generate comprehensive security assessment report",
            category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,  # Reporting is general
            priority=TaskPriority.MEDIUM,
            estimated_duration=timedelta(minutes=2),
            dependencies=vuln_task_deps,
            resources_required={"report_generation": True, "file_io": True}
        )
    
    def _optimize_task_order(self, tasks: List[ScanTask]) -> List[ScanTask]:
        """Optimize task execution order based on dependencies and priorities."""
        # Topological sort considering dependencies and priorities
        ordered_tasks = []
        remaining_tasks = tasks.copy()
        completed_task_ids = set()
        
        while remaining_tasks:
            # Find tasks with no unmet dependencies
            ready_tasks = [
                task for task in remaining_tasks
                if all(dep in completed_task_ids for dep in task.dependencies)
            ]
            
            if not ready_tasks:
                # Circular dependency or missing dependency - take first task
                logger.warning("Potential circular dependency detected in task planning")
                ready_tasks = [remaining_tasks[0]]
            
            # Sort ready tasks by priority
            ready_tasks.sort(key=lambda x: (x.priority.value, x.created_at))
            
            # Add highest priority task
            selected_task = ready_tasks[0]
            ordered_tasks.append(selected_task)
            completed_task_ids.add(selected_task.id)
            remaining_tasks.remove(selected_task)
        
        return ordered_tasks
    
    async def execute_plan(self, plan: ScanPlan) -> Dict[str, Any]:
        """Execute the scan plan with proper resource management and error handling."""
        logger.info(f"Executing scan plan: {plan.name}")
        
        execution_results = {
            "plan_id": plan.id,
            "started_at": datetime.now(),
            "task_results": {},
            "completed_tasks": 0,
            "failed_tasks": 0,
            "total_tasks": len(plan.tasks)
        }
        
        # Resource management
        resource_semaphores = self._create_resource_semaphores()
        
        try:
            for task in plan.tasks:
                logger.info(f"Executing task: {task.name}")
                
                # Check if dependencies are satisfied
                if not self._check_dependencies(task, execution_results["task_results"]):
                    logger.error(f"Dependencies not met for task {task.id}")
                    task.status = TaskStatus.SKIPPED
                    execution_results["task_results"][task.id] = {
                        "status": task.status,
                        "error": "Dependencies not met"
                    }
                    continue
                
                # Execute task with resource management
                task_result = await self._execute_task_with_resources(
                    task, resource_semaphores
                )
                
                execution_results["task_results"][task.id] = task_result
                
                if task_result["status"] == TaskStatus.COMPLETED:
                    execution_results["completed_tasks"] += 1
                elif task_result["status"] == TaskStatus.FAILED:
                    execution_results["failed_tasks"] += 1
                    
                    # Decide whether to continue or abort
                    if self._should_abort_on_failure(task):
                        logger.error(f"Critical task {task.id} failed, aborting plan")
                        break
            
            execution_results["completed_at"] = datetime.now()
            execution_results["success"] = execution_results["failed_tasks"] == 0
            
            logger.info(
                f"Plan execution completed. "
                f"Success: {execution_results['success']}, "
                f"Completed: {execution_results['completed_tasks']}/{execution_results['total_tasks']}"
            )
            
            return execution_results
            
        except Exception as e:
            logger.error(f"Plan execution failed: {e}")
            execution_results["completed_at"] = datetime.now()
            execution_results["success"] = False
            execution_results["error"] = str(e)
            return execution_results
    
    def _create_resource_semaphores(self) -> Dict[str, asyncio.Semaphore]:
        """Create semaphores for resource management."""
        return {
            "network": asyncio.Semaphore(self.config.testing.concurrent_requests),
            "ai_analysis": asyncio.Semaphore(3),  # Limit AI calls
            "high_cpu": asyncio.Semaphore(2),
            "high_bandwidth": asyncio.Semaphore(5),
            "file_io": asyncio.Semaphore(10)
        }
    
    def _check_dependencies(self, task: ScanTask, completed_tasks: Dict[str, Any]) -> bool:
        """Check if task dependencies are satisfied."""
        for dep_id in task.dependencies:
            if dep_id not in completed_tasks:
                return False
            if completed_tasks[dep_id]["status"] != TaskStatus.COMPLETED:
                return False
        return True
    
    async def _execute_task_with_resources(
        self, 
        task: ScanTask, 
        semaphores: Dict[str, asyncio.Semaphore]
    ) -> Dict[str, Any]:
        """Execute a task with proper resource acquisition."""
        # Acquire required resources
        acquired_semaphores = []
        
        try:
            for resource in task.resources_required:
                if resource in semaphores:
                    await semaphores[resource].acquire()
                    acquired_semaphores.append(semaphores[resource])
            
            task.started_at = datetime.now()
            task.status = TaskStatus.RUNNING
            
            # Simulate task execution (in real implementation, this would call the actual agent)
            await asyncio.sleep(1)  # Placeholder for actual task execution
            
            task.completed_at = datetime.now()
            task.status = TaskStatus.COMPLETED
            
            return {
                "status": task.status,
                "started_at": task.started_at,
                "completed_at": task.completed_at,
                "duration": (task.completed_at - task.started_at).total_seconds(),
                "result": task.result
            }
            
        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error = str(e)
            
            return {
                "status": task.status,
                "error": str(e),
                "started_at": task.started_at
            }
        
        finally:
            # Release acquired resources
            for sem in acquired_semaphores:
                sem.release()
    
    def _should_abort_on_failure(self, task: ScanTask) -> bool:
        """Determine if plan should abort on task failure."""
        # Abort on critical discovery tasks
        if task.priority == TaskPriority.CRITICAL and task.id.startswith("discovery"):
            return True
        return False
    
    async def replan_on_failure(self, failed_task: ScanTask, remaining_tasks: List[ScanTask]) -> List[ScanTask]:
        """Replan remaining tasks when a task fails."""
        logger.info(f"Replanning due to failed task: {failed_task.id}")
        
        # Remove tasks that depend on the failed task
        filtered_tasks = [
            task for task in remaining_tasks
            if failed_task.id not in task.dependencies
        ]
        
        # Adjust priorities and dependencies
        for task in filtered_tasks:
            if failed_task.category == task.category:
                # Increase priority for related tasks
                if task.priority.value > 1:
                    task.priority = TaskPriority(task.priority.value - 1)
        
        return self._optimize_task_order(filtered_tasks)
    
    def get_plan_status(self) -> Dict[str, Any]:
        """Get current plan execution status."""
        if not self.current_plan:
            return {"status": "No active plan"}
        
        completed = sum(1 for task in self.current_plan.tasks if task.status == TaskStatus.COMPLETED)
        running = sum(1 for task in self.current_plan.tasks if task.status == TaskStatus.RUNNING)
        failed = sum(1 for task in self.current_plan.tasks if task.status == TaskStatus.FAILED)
        
        return {
            "plan_id": self.current_plan.id,
            "total_tasks": len(self.current_plan.tasks),
            "completed": completed,
            "running": running,
            "failed": failed,
            "progress": completed / len(self.current_plan.tasks) * 100
        }
