"""
DAST Scanner Backend - Professional Red Team Edition
FastAPI-based backend with Playwright engine, advanced vulnerability detection,
session management, and context-aware payload generation
"""
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from models import Base, Scan, ScanSession, ScanLog, DiscoveredEndpoint, ScanStatistic
from typing import List, Optional, Dict, Any
from datetime import datetime
import json
import time
import asyncio
import logging
from contextlib import asynccontextmanager

# Import existing scanners for backward compatibility
from juice_scanner import JuiceShopScanner
from exploiter import JuiceShopExploiter
from rce_exploiter import RCEExploiter
from real_sqli_detector import RealSQLiDetector
from recon_scanner import ReconScanner
from post_recon_exploiter import PostReconExploiter

# Import new professional modules
from playwright_engine import PlaywrightEngine, DiscoveredEndpoint as PWEndpoint
from session_manager import SessionManager, UserCredentials
from xss_validator import XSSValidator, XSSScanner
from advanced_sqli import AdvancedSQLiDetector
from bola_tester import BOLATester, BOLAEndpointScanner, EndpointInfo
from payload_generator import get_payload_generator, VulnerabilityClass, PayloadContext
from juice_login_sqli import JuiceShopLoginSQLiDetector

# Import ApexScanner modules
from apex_scanner import ApexScanner, run_apex_scan

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./dast.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler"""
    # Startup
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized")
    yield
    # Shutdown
    logger.info("Application shutting down")


app = FastAPI(
    title="DAST Scanner API",
    description="Professional Red Team DAST Scanner with Playwright engine",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================== Request/Response Models ====================

class ScanRequest(BaseModel):
    target: str
    mode: str = "full"  # full, exploit, rce, sqli, auto, recon, xss, ssti, lfi, cors, bola, advanced
    admin_token: Optional[str] = None
    # New options for advanced scanning
    credentials_a: Optional[Dict[str, str]] = None  # For BOLA testing
    credentials_b: Optional[Dict[str, str]] = None
    crawl_enabled: bool = True
    headless_browser: bool = True
    max_depth: int = 3
    timeout: int = 300000  # 5 minutes default


class ScanResponse(BaseModel):
    id: int
    status: str
    mode: str
    target: str
    created_at: datetime


class ScanDetailResponse(BaseModel):
    id: int
    target_url: str
    status: str
    scan_mode: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    findings: List[Dict[str, Any]]
    findings_summary: Optional[Dict[str, Any]] = None
    statistics: Optional[Dict[str, Any]] = None


class SessionCreateRequest(BaseModel):
    scan_id: int
    session_type: str  # user_a, user_b, admin
    email: str
    password: str


class SessionResponse(BaseModel):
    id: int
    scan_id: int
    session_type: str
    email: str
    authenticated: bool
    user_info: Optional[Dict[str, Any]] = None


# ==================== Global State ====================

scan_logs: List[str] = []
active_scans: Dict[int, Dict[str, Any]] = {}  # scan_id -> scan info


# ==================== Helper Functions ====================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def log_to_db(db: Session, scan_id: int, message: str, level: str = "INFO", module: str = None, details: Dict = None):
    """Log message to database"""
    try:
        log_entry = ScanLog(
            scan_id=scan_id,
            level=level,
            module=module,
            message=message,
            details=details
        )
        db.add(log_entry)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to log to DB: {e}")


def log_to_console(msg: str, level: str = "INFO"):
    """Log message to console and global list"""
    timestamp = datetime.now().strftime('%H:%M:%S')
    log_msg = f"[{timestamp}] [{level}] {msg}"
    print(log_msg)
    scan_logs.append(log_msg)
    
    # Keep only last 500 logs
    if len(scan_logs) > 500:
        scan_logs.pop(0)


# ==================== Advanced Scanning Functions ====================

async def run_advanced_scan(scan_id: int, target_url: str, mode: str, options: Dict[str, Any]):
    """
    Run advanced vulnerability scan using Playwright and new detection modules
    """
    db = SessionLocal()
    start_time = time.time()
    
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        log_to_console(f"[{scan_id}] Starting advanced scan: {target_url} | Mode: {mode}")
        log_to_db(db, scan_id, f"Starting advanced scan", "INFO", "main")
        
        scan.status = "running"
        scan.scan_mode = mode
        db.commit()

        findings = []
        endpoints_discovered = []
        statistics = {
            "total_requests": 0,
            "endpoints_discovered": 0,
            "pages_crawled": 0,
            "jwt_tokens_found": 0,
            "vulnerabilities_by_type": {},
            "vulnerabilities_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        }

        # Initialize Playwright engine
        headless = options.get('headless_browser', True)
        crawl_enabled = options.get('crawl_enabled', True)
        max_depth = options.get('max_depth', 3)
        timeout = options.get('timeout', 300000)

        log_to_console(f"[{scan_id}] Initializing Playwright engine (headless={headless})")
        log_to_db(db, scan_id, "Initializing Playwright engine", "INFO", "playwright")

        async with PlaywrightEngine(headless=headless, timeout=timeout) as engine:
            # Navigate to target
            await engine.navigate(target_url)
            statistics["pages_crawled"] = 1

            # Extract JWT tokens
            jwt_tokens = await engine.extract_jwt_tokens()
            statistics["jwt_tokens_found"] = len(jwt_tokens)
            if jwt_tokens:
                log_to_console(f"[{scan_id}] Found {len(jwt_tokens)} JWT tokens")
                log_to_db(db, scan_id, f"Extracted {len(jwt_tokens)} JWT tokens", "INFO", "session")

            # Crawl if enabled
            if crawl_enabled:
                log_to_console(f"[{scan_id}] Starting crawl (max_depth={max_depth})")
                log_to_db(db, scan_id, "Starting application crawl", "INFO", "crawler")
                
                endpoints = await engine.crawl(max_depth=max_depth)
                endpoints_discovered = endpoints
                statistics["endpoints_discovered"] = len(endpoints)
                
                # Save discovered endpoints to DB
                for ep in endpoints[:100]:  # Limit saved endpoints
                    db_ep = DiscoveredEndpoint(
                        scan_id=scan_id,
                        url=ep.url,
                        method=ep.method,
                        parameters=ep.parameters,
                        auth_required=ep.auth_required,
                        source=ep.source
                    )
                    db.add(db_ep)
                db.commit()

                log_to_console(f"[{scan_id}] Crawl complete: {len(endpoints)} endpoints discovered")

            # ==================== XSS Scanning ====================
            if mode in ["full", "xss", "advanced"]:
                log_to_console(f"[{scan_id}] Running XSS validation with execution confirmation")
                log_to_db(db, scan_id, "Starting XSS validation", "INFO", "xss")

                xss_scanner = XSSScanner(page=engine._page)
                
                # Test discovered endpoints
                for endpoint in endpoints_discovered[:20]:  # Limit for performance
                    xss_findings = await xss_scanner.scan_url(endpoint.url)
                    
                    for finding in xss_findings:
                        findings.append(finding)
                        sev = finding.get('info', {}).get('severity', 'info')
                        statistics["vulnerabilities_by_severity"][sev] = statistics["vulnerabilities_by_severity"].get(sev, 0) + 1

                xss_summary = xss_scanner.validator.get_findings_summary()
                log_to_console(f"[{scan_id}] XSS scan complete: {xss_summary.get('confirmed', 0)} confirmed, {xss_summary.get('potential', 0)} potential")

            # ==================== SQLi Scanning ====================
            if mode in ["full", "sqli", "advanced"]:
                log_to_console(f"[{scan_id}] Running advanced SQLi detection")
                log_to_db(db, scan_id, "Starting SQLi detection", "INFO", "sqli")

                sqli_detector = AdvancedSQLiDetector(page=engine._page, timeout=timeout)

                # Test endpoints with parameters
                for endpoint in endpoints_discovered[:30]:
                    if endpoint.parameters or '?' in endpoint.url:
                        sqli_findings = await sqli_detector.detect_sqli(
                            url=endpoint.url,
                            parameter=endpoint.parameters[0] if endpoint.parameters else 'id'
                        )

                        for finding in sqli_findings:
                            findings.append(finding.to_dict())
                            statistics["vulnerabilities_by_severity"]["critical"] += 1

                sqli_summary = sqli_detector.get_findings_summary()
                log_to_console(f"[{scan_id}] SQLi scan complete: {sqli_summary.get('total', 0)} findings")

            # ==================== Juice Shop Login SQLi ====================
            if mode in ["full", "sqli", "advanced", "auth_bypass"]:
                log_to_console(f"[{scan_id}] Running Juice Shop Login SQLi detection (Action-based)")
                log_to_db(db, scan_id, "Starting Juice Shop Login SQLi detection", "INFO", "juice_sqli")

                login_sqli_detector = JuiceShopLoginSQLiDetector(
                    page=engine._page,
                    timeout=timeout,
                    target_url=target_url
                )

                login_findings = await login_sqli_detector.detect_login_sqli()

                for finding in login_findings:
                    findings.append(finding.to_dict())
                    statistics["vulnerabilities_by_severity"]["critical"] += 1

                login_summary = login_sqli_detector.get_findings_summary()
                log_to_console(f"[{scan_id}] Juice Shop Login SQLi complete: {login_summary.get('total', 0)} auth bypass found!")
                
                if login_findings:
                    log_to_console(f"[{scan_id}] 🎉 AUTH BYPASS ACHIEVED! Check findings for JWT tokens", "CRITICAL")

            # ==================== BOLA/IDOR Scanning ====================
            if mode in ["full", "bola", "advanced"] and options.get('credentials_a') and options.get('credentials_b'):
                log_to_console(f"[{scan_id}] Running BOLA/IDOR testing with dual sessions")
                log_to_db(db, scan_id, "Starting BOLA/IDOR testing", "INFO", "bola")

                # Initialize session manager
                session_manager = SessionManager(target_url)

                # Authenticate both users
                credentials_a = UserCredentials(**options['credentials_a'])
                credentials_b = UserCredentials(**options['credentials_b'])

                session_a, session_b = await session_manager.authenticate_user_a_and_b(
                    credentials_a, credentials_b
                )

                if session_a and session_b:
                    # Save sessions to DB
                    for session, session_type in [(session_a, 'user_a'), (session_b, 'user_b')]:
                        db_session = ScanSession(
                            scan_id=scan_id,
                            session_type=session_type,
                            email=session.email,
                            jwt_token=session.jwt_token,
                            cookies=json.dumps(session.cookies),
                            headers=json.dumps(session.headers),
                            user_info={
                                'user_id': session.user_id,
                                'role': session.role
                            }
                        )
                        db.add(db_session)
                    db.commit()

                    # Test endpoints for BOLA
                    bola_tester = BOLATester(
                        session_a_headers=session_manager.get_headers_for_session(session_a.session_id),
                        session_b_headers=session_manager.get_headers_for_session(session_b.session_id),
                        session_a_info=session_manager.get_user_context(session_a.session_id),
                        session_b_info=session_manager.get_user_context(session_b.session_id)
                    )

                    # Convert discovered endpoints to BOLA format
                    for endpoint in endpoints_discovered[:50]:
                        if endpoint.auth_required:
                            bola_endpoint = EndpointInfo(
                                url=endpoint.url,
                                method=endpoint.method,
                                parameters=endpoint.parameters,
                                auth_required=True,
                                id_parameter='id'  # Default, could be smarter
                            )
                            
                            bola_findings = bola_tester.test_endpoint(bola_endpoint)
                            
                            for finding in bola_findings:
                                findings.append(finding.to_dict())
                                statistics["vulnerabilities_by_severity"][finding.severity.value] += 1

                    log_to_console(f"[{scan_id}] BOLA scan complete: {len(bola_tester.get_findings())} findings")
                else:
                    log_to_console(f"[{scan_id}] BOLA testing skipped - authentication failed", "WARNING")

        # ==================== Post-processing ====================
        
        # Remove duplicates
        seen = set()
        unique_findings = []
        for f in findings:
            key = f"{f.get('url', '')}-{f.get('info', {}).get('name', '')}-{f.get('parameter', '')}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        findings = unique_findings
        statistics["vulnerabilities_found"] = len(findings)
        statistics["scan_duration_ms"] = (time.time() - start_time) * 1000

        # Save results
        scan.findings = json.dumps(findings)
        scan.findings_summary = {
            "total": len(findings),
            "by_severity": statistics["vulnerabilities_by_severity"],
            "endpoints_discovered": statistics["endpoints_discovered"],
            "jwt_tokens_found": statistics["jwt_tokens_found"]
        }
        scan.scan_metadata = statistics
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        db.commit()

        log_to_console(f"[{scan_id}] ✓ Advanced scan completed successfully!")
        log_to_console(f"[{scan_id}] Total findings: {len(findings)}")
        log_to_console(f"[{scan_id}] Duration: {statistics['scan_duration_ms'] / 1000:.2f}s")

        # Log severity breakdown
        sev = statistics["vulnerabilities_by_severity"]
        log_to_console(f"[{scan_id}] 📊 Critical: {sev['critical']}, High: {sev['high']}, Medium: {sev['medium']}, Low: {sev['low']}, Info: {sev['info']}")

    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        log_to_console(f"[{scan_id}] Error: {e}", "ERROR")
        log_to_db(db, scan_id, f"Scan error: {e}", "ERROR", "main", {"traceback": error_trace})
        
        scan.status = "failed"
        db.commit()
    finally:
        db.close()


def run_legacy_scan(scan_id: int, target_url: str, mode: str, admin_token: Optional[str] = None):
    """
    Run legacy scan using existing scanners (backward compatibility)
    """
    db = SessionLocal()
    
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        log_to_console(f"[{scan_id}] Starting legacy scan: {target_url} | Mode: {mode}")
        
        scan.status = "running"
        db.commit()

        findings = []

        if mode == "sqli":
            log_to_console(f"[{scan_id}] Running Real SQLi Detector...")
            sqli = RealSQLiDetector(target_url)
            sqli_results = sqli.scan()

            if sqli_results.get("vulnerable"):
                findings.append({
                    "template-id": "real-sqli-detected",
                    "tool": "real-sqli-detector",
                    "info": {
                        "name": "🎯 REAL SQL INJECTION DETECTED!",
                        "description": f"SQL Injection confirmed via: {', '.join(sqli_results['type'])}. Parameter: {sqli_results['parameter']}",
                        "severity": "critical",
                        "solution": "Use parameterized queries. Validate all input.",
                        "cwe-id": ["CWE-89"]
                    },
                    "url": target_url,
                    "matched-at": target_url,
                    "parameter": sqli_results.get("payload", ""),
                    "evidence": f"Types: {', '.join(sqli_results['type'])}"
                })

        elif mode == "rce":
            log_to_console(f"[{scan_id}] Running RCE Exploitation...")
            rce = RCEExploiter(target_url, admin_token)
            rce_results = rce.run_full_rce_exploitation()

            if rce_results.get("rce_achieved"):
                findings.append({
                    "template-id": "rce-achieved",
                    "tool": "autonomous-rce-exploiter",
                    "info": {
                        "name": "🎉 REMOTE CODE EXECUTION ACHIEVED!",
                        "description": f"RCE obtained via: {rce_results['rce_method']}. Shell type: {rce_results['shell_type']}",
                        "severity": "critical",
                        "solution": "Immediately patch the vulnerability.",
                        "cwe-id": ["CWE-94"]
                    },
                    "url": target_url,
                    "matched-at": target_url,
                    "evidence": f"RCE Method: {rce_results['rce_method']}"
                })

        elif mode == "recon":
            log_to_console(f"[{scan_id}] Running Bug Bounty Recon...")
            recon = ReconScanner(target_url)
            recon_results = recon.run_full_recon()
            
            recon_findings = recon.convert_to_findings(recon_results)
            findings.extend(recon_findings)

            # Post-recon exploitation
            exploiter = PostReconExploiter(target_url)
            exploit_findings = exploiter.run_full_post_recon(recon_results)
            findings.extend(exploit_findings)

        elif mode == "exploit" or mode == "auto":
            log_to_console(f"[{scan_id}] Running Autonomous Exploitation...")
            exploiter = JuiceShopExploiter(target_url)
            exploit_results = exploiter.run_full_exploitation()

            for exploit in exploit_results.get("exploits", []):
                severity = "critical" if exploit.get("type") in ["SQL Injection", "Broken Access Control"] else "high"
                findings.append({
                    "template-id": f"exploit-{exploit['type'].lower().replace(' ', '-')}",
                    "tool": "autonomous-exploiter",
                    "info": {
                        "name": f"Auto-Exploit: {exploit['type']}",
                        "description": exploit.get("result", ""),
                        "severity": severity,
                        "solution": f"Fix {exploit['type']} vulnerability",
                        "cwe-id": []
                    },
                    "url": target_url,
                    "matched-at": target_url,
                    "parameter": exploit.get("payload", ""),
                    "evidence": exploit.get("result", "")
                })

        else:
            # Default vulnerability scan
            log_to_console(f"[{scan_id}] Running Juice Shop Scanner...")
            scanner = JuiceShopScanner(target_url)
            findings = scanner.scan()

        # Remove duplicates
        seen = set()
        unique = []
        for f in findings:
            key = f"{f.get('url', '')}-{f.get('info', {}).get('name', '')}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        scan.findings = json.dumps(unique)
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        db.commit()

        log_to_console(f"[{scan_id}] ✓ Legacy scan completed! Found {len(unique)} vulnerabilities")

    except Exception as e:
        import traceback
        log_to_console(f"[{scan_id}] Error: {e}", "ERROR")
        scan.status = "failed"
        db.commit()
    finally:
        db.close()


async def run_apex_scanner_task(scan_id: int, target_url: str, options: Dict[str, Any]):
    """
    Run ApexScanner - High-Performance DAST Framework
    """
    db = SessionLocal()
    
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        
        log_to_console(f"[{scan_id}] 🚀 Starting ApexScanner: {target_url}")
        log_to_db(db, scan_id, "Starting ApexScanner scan", "INFO", "apex")
        
        scan.status = "running"
        scan.scan_mode = "apex"
        db.commit()
        
        # Run ApexScanner
        result = await run_apex_scan(
            target_url=target_url,
            headless=options.get('headless_browser', True),
            max_depth=options.get('max_depth', 3),
            enable_recon=True,
            enable_fuzzing=True,
            enable_verification=True
        )
        
        # Convert results to findings format
        findings = []
        for vuln in result.get('vulnerabilities', []):
            findings.append({
                "template-id": f"apex-{vuln.get('type', 'unknown')}",
                "tool": "apex-scanner",
                "info": {
                    "name": f"ApexScanner: {vuln.get('type', 'Unknown')} ({vuln.get('severity', 'info')})",
                    "description": vuln.get('evidence', ''),
                    "severity": vuln.get('severity', 'info'),
                    "solution": "Review and fix the vulnerability",
                    "cwe-id": vuln.get('cwe_id', [])
                },
                "url": vuln.get('url', target_url),
                "matched-at": vuln.get('url', ''),
                "parameter": vuln.get('parameter', ''),
                "evidence": vuln.get('evidence', ''),
                "confidence": vuln.get('confidence', 0),
                "verification_status": vuln.get('verification_status', 'pending')
            })
        
        # Save results
        scan.findings = json.dumps(findings)
        scan.findings_summary = {
            "total": len(findings),
            "by_severity": result.get('vulnerabilities_by_severity', {}),
            "endpoints_discovered": result.get('endpoints_discovered', 0),
            "secrets_found": result.get('secrets_found', 0)
        }
        scan.metadata = result.get('statistics', {})
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        db.commit()
        
        log_to_console(f"[{scan_id}] ✅ ApexScanner complete: {len(findings)} vulnerabilities found")
        
        # Log severity breakdown
        sev = result.get('vulnerabilities_by_severity', {})
        log_to_console(f"[{scan_id}] 📊 Critical: {sev.get('critical', 0)}, High: {sev.get('high', 0)}, Medium: {sev.get('medium', 0)}, Low: {sev.get('low', 0)}")
        
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        log_to_console(f"[{scan_id}] ApexScanner error: {e}", "ERROR")
        log_to_db(db, scan_id, f"ApexScanner error: {e}", "ERROR", "apex", {"traceback": error_trace})
        
        scan.status = "failed"
        db.commit()
    finally:
        db.close()


# ==================== API Endpoints ====================

@app.post("/api/v1/startdast", response_model=ScanResponse)
async def create_scan(req: ScanRequest):
    """Start a new vulnerability scan"""
    db = SessionLocal()
    try:
        new_scan = Scan(
            target_url=req.target,
            scan_mode=req.mode,
            status="pending"
        )
        db.add(new_scan)
        db.commit()
        db.refresh(new_scan)

        # Store scan options
        options = {
            "crawl_enabled": req.crawl_enabled,
            "headless_browser": req.headless_browser,
            "max_depth": req.max_depth,
            "timeout": req.timeout,
            "credentials_a": req.credentials_a,
            "credentials_b": req.credentials_b,
        }
        active_scans[new_scan.id] = {"options": options}

        # Determine scan type and start appropriate task
        advanced_modes = ["full", "xss", "sqli", "bola", "advanced"]
        
        # ApexScanner mode
        if req.mode == "apex":
            asyncio.create_task(
                asyncio.to_thread(
                    run_apex_scanner_task,
                    new_scan.id,
                    req.target,
                    options
                )
            )
        elif req.mode in advanced_modes:
            # Use new advanced scanning engine
            asyncio.create_task(run_advanced_scan(new_scan.id, req.target, req.mode, options))
        else:
            # Use legacy scanners
            asyncio.create_task(
                asyncio.to_thread(
                    run_legacy_scan, 
                    new_scan.id, 
                    req.target, 
                    req.mode, 
                    req.admin_token
                )
            )

        return ScanResponse(
            id=new_scan.id,
            status="started",
            mode=req.mode,
            target=req.target,
            created_at=new_scan.created_at
        )
    finally:
        db.close()


@app.get("/api/v1/scan/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(scan_id: int):
    """Get scan results"""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Get statistics if available
        stats = db.query(ScanStatistic).filter(ScanStatistic.scan_id == scan_id).first()

        return ScanDetailResponse(
            id=scan.id,
            target_url=scan.target_url,
            status=scan.status,
            scan_mode=scan.scan_mode,
            created_at=scan.created_at,
            completed_at=scan.completed_at,
            findings=json.loads(scan.findings) if scan.findings else [],
            findings_summary=scan.findings_summary,
            statistics={
                "scan_duration_ms": stats.scan_duration_ms if stats else 0,
                "endpoints_discovered": stats.endpoints_discovered if stats else 0,
                "pages_crawled": stats.pages_crawled if stats else 0,
            } if stats else None
        )
    finally:
        db.close()


@app.get("/api/v1/scans")
async def list_scans():
    """List all scans"""
    db = SessionLocal()
    try:
        scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
        return [{
            "id": s.id,
            "target_url": s.target_url,
            "status": s.status,
            "scan_mode": s.scan_mode,
            "created_at": s.created_at,
            "findings_count": len(json.loads(s.findings)) if s.findings else 0
        } for s in scans]
    finally:
        db.close()


@app.delete("/api/v1/scans")
async def delete_all_scans():
    """Delete all scans"""
    db = SessionLocal()
    try:
        db.query(Scan).delete()
        db.query(ScanSession).delete()
        db.query(ScanLog).delete()
        db.query(DiscoveredEndpoint).delete()
        db.query(ScanStatistic).delete()
        db.commit()
        return {"message": "All scans deleted"}
    finally:
        db.close()


@app.delete("/api/v1/scan/{scan_id}")
async def delete_scan(scan_id: int):
    """Delete a specific scan"""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        db.delete(scan)
        db.commit()
        return {"message": "Scan deleted"}
    finally:
        db.close()


@app.get("/api/v1/logs")
async def get_logs(scan_id: Optional[int] = None, limit: int = 200):
    """Get scan logs"""
    db = SessionLocal()
    try:
        if scan_id:
            logs = db.query(ScanLog).filter(ScanLog.scan_id == scan_id).order_by(ScanLog.timestamp.desc()).limit(limit).all()
            return [{
                "timestamp": log.timestamp.isoformat(),
                "level": log.level,
                "module": log.module,
                "message": log.message,
                "details": log.details
            } for log in logs]
        else:
            return {"logs": scan_logs[-limit:], "count": len(scan_logs)}
    finally:
        db.close()


@app.get("/api/v1/scan/{scan_id}/endpoints")
async def get_scan_endpoints(scan_id: int):
    """Get discovered endpoints for a scan"""
    db = SessionLocal()
    try:
        endpoints = db.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == scan_id).all()
        return [{
            "id": ep.id,
            "url": ep.url,
            "method": ep.method,
            "parameters": ep.parameters,
            "auth_required": ep.auth_required,
            "source": ep.source
        } for ep in endpoints]
    finally:
        db.close()


@app.get("/api/v1/scan/{scan_id}/sessions")
async def get_scan_sessions(scan_id: int):
    """Get sessions for a scan (BOLA testing)"""
    db = SessionLocal()
    try:
        sessions = db.query(ScanSession).filter(ScanSession.scan_id == scan_id).all()
        return [{
            "id": s.id,
            "session_type": s.session_type,
            "email": s.email,
            "user_info": s.user_info,
            "created_at": s.created_at
        } for s in sessions]
    finally:
        db.close()


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "version": "2.0.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
