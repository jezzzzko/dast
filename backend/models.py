from sqlalchemy import Column, Integer, String, DateTime, Text, Float, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from typing import Dict, List, Any

Base = declarative_base()


class Scan(Base):
    """Main scan result table"""
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String, nullable=False)
    status = Column(String, default="pending")  # pending, running, completed, failed
    scan_mode = Column(String, default="full")  # full, xss, sqli, bola, recon, etc.
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    findings = Column(Text, default="[]")  # JSON stored as text
    findings_summary = Column(JSON, nullable=True)  # Structured summary
    scan_metadata = Column(JSON, nullable=True)  # Additional scan metadata


class ScanSession(Base):
    """Session data for multi-user testing (BOLA/IDOR)"""
    __tablename__ = "scan_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, nullable=False)  # Reference to Scan.id
    session_type = Column(String, nullable=False)  # user_a, user_b, admin
    email = Column(String, nullable=True)
    jwt_token = Column(Text, nullable=True)
    cookies = Column(Text, default="{}")  # JSON stored as text
    headers = Column(Text, default="{}")  # JSON stored as text
    user_info = Column(JSON, nullable=True)  # Extracted user info
    created_at = Column(DateTime, default=datetime.utcnow)


class ScanLog(Base):
    """Detailed scan execution logs"""
    __tablename__ = "scan_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, nullable=False)  # Reference to Scan.id
    timestamp = Column(DateTime, default=datetime.utcnow)
    level = Column(String, default="INFO")  # INFO, WARNING, ERROR, DEBUG
    module = Column(String, nullable=True)  # Module that generated the log
    message = Column(Text, nullable=False)
    details = Column(JSON, nullable=True)  # Additional structured data


class DiscoveredEndpoint(Base):
    """Discovered API endpoints during crawling"""
    __tablename__ = "discovered_endpoints"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, nullable=False)  # Reference to Scan.id
    url = Column(String, nullable=False)
    method = Column(String, default="GET")
    parameters = Column(JSON, nullable=True)  # List of parameters
    auth_required = Column(Boolean, default=False)
    source = Column(String, nullable=True)  # xhr, fetch, link, etc.
    response_sample = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ScanStatistic(Base):
    """Scan statistics and metrics"""
    __tablename__ = "scan_statistics"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, nullable=False, unique=True)  # Reference to Scan.id
    total_requests = Column(Integer, default=0)
    total_endpoints = Column(Integer, default=0)
    endpoints_discovered = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)
    false_positives_eliminated = Column(Integer, default=0)
    scan_duration_ms = Column(Float, default=0.0)
    pages_crawled = Column(Integer, default=0)
    jwt_tokens_found = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
