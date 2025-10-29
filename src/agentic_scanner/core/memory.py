"""
Memory and knowledge management system for the Agentic OWASP Scanner.

This module provides persistent storage, caching, and learning capabilities
to enable the system to improve over time and maintain context across scans.
"""

import asyncio
import json
import pickle
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timedelta
from dataclasses import asdict

import aioredis
from loguru import logger
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import Column, String, DateTime, Text, Float, Integer, Boolean, JSON

from .config import MemoryConfig
from ..agents.base import VulnerabilityFinding, TestResult


Base = declarative_base()


class ScanSessionModel(Base):
    """SQLAlchemy model for scan sessions."""
    __tablename__ = "scan_sessions"
    
    id = Column(String, primary_key=True)
    target_url = Column(String, nullable=False)
    started_at = Column(DateTime, nullable=False)
    completed_at = Column(DateTime)
    status = Column(String, nullable=False)
    findings_count = Column(Integer, default=0)
    config_data = Column(JSON)
    created_at = Column(DateTime, default=datetime.now)


class VulnerabilityModel(Base):
    """SQLAlchemy model for vulnerability findings."""
    __tablename__ = "vulnerabilities"
    
    id = Column(String, primary_key=True)
    session_id = Column(String, nullable=False)
    category = Column(String, nullable=False)
    name = Column(String, nullable=False)
    description = Column(Text)
    severity = Column(String, nullable=False)
    status = Column(String, nullable=False)
    url = Column(String, nullable=False)
    method = Column(String, default="GET")
    parameter = Column(String)
    payload = Column(Text)
    evidence = Column(Text)
    remediation = Column(Text)
    cwe_id = Column(String)
    cvss_score = Column(Float)
    confidence = Column(Float, default=0.0)
    discovered_at = Column(DateTime, default=datetime.now)


class KnowledgeModel(Base):
    """SQLAlchemy model for accumulated knowledge."""
    __tablename__ = "knowledge_base"
    
    id = Column(String, primary_key=True)
    category = Column(String, nullable=False)
    pattern_type = Column(String, nullable=False)  # payload, signature, etc.
    pattern_data = Column(Text, nullable=False)
    effectiveness_score = Column(Float, default=0.0)
    usage_count = Column(Integer, default=0)
    success_rate = Column(Float, default=0.0)
    last_updated = Column(DateTime, default=datetime.now)
    metadata = Column(JSON)


class MemoryManager:
    """Manages persistent memory, caching, and knowledge accumulation."""
    
    def __init__(self, config: MemoryConfig):
        self.config = config
        self.redis: Optional[aioredis.Redis] = None
        self.db_engine = None
        self.async_session = None
        
        # In-memory caches
        self._session_cache: Dict[str, Any] = {}
        self._knowledge_cache: Dict[str, Dict[str, Any]] = {}
        self._payload_effectiveness: Dict[str, float] = {}
    
    async def initialize(self) -> None:
        """Initialize memory management components."""
        logger.info("Initializing memory management system...")
        
        # Initialize Redis connection
        try:
            self.redis = await aioredis.from_url(
                self.config.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
            await self.redis.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}. Using in-memory cache only.")
            self.redis = None
        
        # Initialize SQLite database
        try:
            self.db_engine = create_async_engine(
                "sqlite+aiosqlite:///scanner_memory.db",
                echo=False
            )
            
            async with self.db_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            
            self.async_session = sessionmaker(
                self.db_engine, 
                class_=AsyncSession,
                expire_on_commit=False
            )
            
            logger.info("Database initialized")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise
        
        # Load cached knowledge
        await self._load_knowledge_cache()
    
    async def save_session(self, session) -> None:
        """Save scan session to persistent storage."""
        try:
            session_data = {
                "id": session.id,
                "target_url": session.config.target_url,
                "started_at": session.started_at,
                "completed_at": session.completed_at,
                "status": session.status,
                "findings_count": len(session.findings),
                "config_data": session.config.to_dict()
            }
            
            # Save to database
            async with self.async_session() as db_session:
                db_session.add(ScanSessionModel(**session_data))
                
                # Save findings
                for finding in session.findings:
                    finding_data = {
                        "id": finding.id,
                        "session_id": session.id,
                        "category": finding.category.value,
                        "name": finding.name,
                        "description": finding.description,
                        "severity": finding.severity.value,
                        "status": finding.status.value,
                        "url": finding.url,
                        "method": finding.method,
                        "parameter": finding.parameter,
                        "payload": finding.payload,
                        "evidence": finding.evidence,
                        "remediation": finding.remediation,
                        "cwe_id": finding.cwe_id,
                        "cvss_score": finding.cvss_score,
                        "confidence": finding.confidence,
                        "discovered_at": finding.discovered_at
                    }
                    db_session.add(VulnerabilityModel(**finding_data))
                
                await db_session.commit()
            
            # Cache session data
            self._session_cache[session.id] = session_data
            
            # Cache in Redis if available
            if self.redis:
                await self.redis.setex(
                    f"session:{session.id}",
                    self.config.cache_ttl,
                    json.dumps(session_data, default=str)
                )
            
            logger.info(f"Session {session.id} saved to memory")
            
        except Exception as e:
            logger.error(f"Failed to save session: {e}")
            raise
    
    async def load_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Load scan session from storage."""
        try:
            # Check in-memory cache first
            if session_id in self._session_cache:
                return self._session_cache[session_id]
            
            # Check Redis cache
            if self.redis:
                cached_data = await self.redis.get(f"session:{session_id}")
                if cached_data:
                    return json.loads(cached_data)
            
            # Load from database
            async with self.async_session() as db_session:
                result = await db_session.get(ScanSessionModel, session_id)
                if result:
                    return {
                        "id": result.id,
                        "target_url": result.target_url,
                        "started_at": result.started_at,
                        "completed_at": result.completed_at,
                        "status": result.status,
                        "findings_count": result.findings_count,
                        "config_data": result.config_data
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to load session {session_id}: {e}")
            return None
    
    async def save_knowledge(self, category: str, pattern_type: str, pattern_data: str, 
                           effectiveness_score: float = 0.0, metadata: Optional[Dict] = None) -> None:
        """Save knowledge pattern to the knowledge base."""
        try:
            import hashlib
            
            # Generate unique ID for the pattern
            pattern_id = hashlib.sha256(f"{category}:{pattern_type}:{pattern_data}".encode()).hexdigest()[:16]
            
            knowledge_data = {
                "id": pattern_id,
                "category": category,
                "pattern_type": pattern_type,
                "pattern_data": pattern_data,
                "effectiveness_score": effectiveness_score,
                "usage_count": 1,
                "success_rate": effectiveness_score,
                "last_updated": datetime.now(),
                "metadata": metadata or {}
            }
            
            # Save to database (upsert)
            async with self.async_session() as db_session:
                existing = await db_session.get(KnowledgeModel, pattern_id)
                if existing:
                    # Update existing pattern
                    existing.usage_count += 1
                    existing.effectiveness_score = (existing.effectiveness_score + effectiveness_score) / 2
                    existing.success_rate = existing.effectiveness_score
                    existing.last_updated = datetime.now()
                    if metadata:
                        existing.metadata.update(metadata)
                else:
                    # Create new pattern
                    db_session.add(KnowledgeModel(**knowledge_data))
                
                await db_session.commit()
            
            # Update cache
            if category not in self._knowledge_cache:
                self._knowledge_cache[category] = {}
            self._knowledge_cache[category][pattern_id] = knowledge_data
            
            logger.debug(f"Knowledge pattern saved: {category}/{pattern_type}")
            
        except Exception as e:
            logger.error(f"Failed to save knowledge: {e}")
    
    async def get_effective_payloads(self, category: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get most effective payloads for a category."""
        try:
            # Check cache first
            if category in self._knowledge_cache:
                payloads = [
                    pattern for pattern in self._knowledge_cache[category].values()
                    if pattern["pattern_type"] == "payload"
                ]
                # Sort by effectiveness
                payloads.sort(key=lambda x: x["effectiveness_score"], reverse=True)
                return payloads[:limit]
            
            # Load from database
            async with self.async_session() as db_session:
                from sqlalchemy import select
                
                stmt = select(KnowledgeModel).where(
                    KnowledgeModel.category == category,
                    KnowledgeModel.pattern_type == "payload"
                ).order_by(KnowledgeModel.effectiveness_score.desc()).limit(limit)
                
                result = await db_session.execute(stmt)
                patterns = result.scalars().all()
                
                return [
                    {
                        "id": p.id,
                        "pattern_data": p.pattern_data,
                        "effectiveness_score": p.effectiveness_score,
                        "usage_count": p.usage_count,
                        "success_rate": p.success_rate,
                        "metadata": p.metadata
                    }
                    for p in patterns
                ]
            
        except Exception as e:
            logger.error(f"Failed to get effective payloads for {category}: {e}")
            return []
    
    async def update_payload_effectiveness(self, payload: str, category: str, 
                                         success: bool, confidence: float = 0.0) -> None:
        """Update payload effectiveness based on test results."""
        try:
            effectiveness_score = confidence if success else -0.1
            
            await self.save_knowledge(
                category=category,
                pattern_type="payload",
                pattern_data=payload,
                effectiveness_score=effectiveness_score,
                metadata={
                    "success": success,
                    "confidence": confidence,
                    "updated_at": datetime.now().isoformat()
                }
            )
            
            # Update in-memory tracking
            payload_key = f"{category}:{payload}"
            if payload_key not in self._payload_effectiveness:
                self._payload_effectiveness[payload_key] = effectiveness_score
            else:
                # Moving average
                current = self._payload_effectiveness[payload_key]
                self._payload_effectiveness[payload_key] = (current + effectiveness_score) / 2
            
        except Exception as e:
            logger.error(f"Failed to update payload effectiveness: {e}")
    
    async def get_similar_targets(self, target_url: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get similar targets that have been scanned before."""
        try:
            from urllib.parse import urlparse
            
            target_domain = urlparse(target_url).netloc
            
            async with self.async_session() as db_session:
                from sqlalchemy import select, func
                
                # Find sessions with similar domains or technology stacks
                stmt = select(ScanSessionModel).where(
                    func.lower(ScanSessionModel.target_url).contains(target_domain.lower())
                ).order_by(ScanSessionModel.started_at.desc()).limit(limit)
                
                result = await db_session.execute(stmt)
                sessions = result.scalars().all()
                
                return [
                    {
                        "id": s.id,
                        "target_url": s.target_url,
                        "started_at": s.started_at,
                        "findings_count": s.findings_count,
                        "status": s.status
                    }
                    for s in sessions
                ]
            
        except Exception as e:
            logger.error(f"Failed to get similar targets: {e}")
            return []
    
    async def _load_knowledge_cache(self) -> None:
        """Load frequently used knowledge into memory cache."""
        try:
            async with self.async_session() as db_session:
                from sqlalchemy import select
                
                # Load top patterns by effectiveness
                stmt = select(KnowledgeModel).where(
                    KnowledgeModel.effectiveness_score > 0.5
                ).order_by(KnowledgeModel.usage_count.desc()).limit(1000)
                
                result = await db_session.execute(stmt)
                patterns = result.scalars().all()
                
                for pattern in patterns:
                    category = pattern.category
                    if category not in self._knowledge_cache:
                        self._knowledge_cache[category] = {}
                    
                    self._knowledge_cache[category][pattern.id] = {
                        "id": pattern.id,
                        "pattern_type": pattern.pattern_type,
                        "pattern_data": pattern.pattern_data,
                        "effectiveness_score": pattern.effectiveness_score,
                        "usage_count": pattern.usage_count,
                        "success_rate": pattern.success_rate,
                        "metadata": pattern.metadata
                    }
            
            logger.info(f"Loaded {len(patterns)} knowledge patterns into cache")
            
        except Exception as e:
            logger.error(f"Failed to load knowledge cache: {e}")
    
    async def get_scan_statistics(self) -> Dict[str, Any]:
        """Get overall scan statistics."""
        try:
            async with self.async_session() as db_session:
                from sqlalchemy import select, func
                
                # Get session stats
                session_count = await db_session.scalar(
                    select(func.count(ScanSessionModel.id))
                )
                
                # Get vulnerability stats
                vuln_stats = await db_session.execute(
                    select(
                        VulnerabilityModel.severity,
                        func.count(VulnerabilityModel.id)
                    ).group_by(VulnerabilityModel.severity)
                )
                
                severity_breakdown = {row[0]: row[1] for row in vuln_stats}
                
                return {
                    "total_scans": session_count or 0,
                    "total_vulnerabilities": sum(severity_breakdown.values()),
                    "severity_breakdown": severity_breakdown,
                    "knowledge_patterns": len(self._knowledge_cache),
                    "cache_hit_rate": self._calculate_cache_hit_rate()
                }
                
        except Exception as e:
            logger.error(f"Failed to get scan statistics: {e}")
            return {}
    
    def _calculate_cache_hit_rate(self) -> float:
        """Calculate cache hit rate (placeholder implementation)."""
        # This would be implemented with proper metrics tracking
        return 0.85  # Placeholder
    
    async def cleanup(self) -> None:
        """Clean up memory management resources."""
        logger.info("Cleaning up memory management system...")
        
        if self.redis:
            await self.redis.close()
        
        if self.db_engine:
            await self.db_engine.dispose()
        
        # Clear caches
        self._session_cache.clear()
        self._knowledge_cache.clear()
        self._payload_effectiveness.clear()
        
        logger.info("Memory management cleanup complete")
