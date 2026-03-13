"""
ApexScanner - Main Orchestrator
Action-Interception-Mutation Architecture
High-Performance Automated DAST Framework
"""
import asyncio
import json
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import logging
import httpx

from playwright.async_api import async_playwright, Page

# Import ApexScanner modules
from apex_interceptor import RequestInterceptor, SensitivityLevel, RequestResponsePair
from apex_recon import DeepReconScanner
from apex_fuzzer import MultiVectorFuzzer, VulnerabilityType, Severity
from apex_engine import VulnerabilityEngine, VerificationStatus
from apex_crawler import AutoCrawler

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Complete scan result"""
    scan_id: str
    target_url: str
    status: str
    start_time: float
    end_time: Optional[float] = None
    endpoints_discovered: List[Dict] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    secrets_found: List[Dict] = field(default_factory=list)
    comments_found: List[str] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'scan_id': self.scan_id,
            'target_url': self.target_url,
            'status': self.status,
            'duration_seconds': (self.end_time - self.start_time) if self.end_time else None,
            'endpoints_discovered': len(self.endpoints_discovered),
            'vulnerabilities_count': len(self.vulnerabilities),
            'vulnerabilities_by_severity': self._count_by_severity(),
            'secrets_found': len(self.secrets_found),
            'statistics': self.statistics
        }
    
    def _count_by_severity(self) -> Dict[str, int]:
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            counts[severity] = counts.get(severity, 0) + 1
        return counts


class ApexScanner:
    """
    Main ApexScanner orchestrator
    Coordinates all scanning modules
    """
    
    def __init__(
        self,
        target_url: str,
        headless: bool = True,
        max_depth: int = 3,
        max_pages: int = 50,
        timeout: int = 300000,
        enable_recon: bool = True,
        enable_fuzzing: bool = True,
        enable_verification: bool = True,
        max_concurrency: int = 5
    ):
        self.target_url = target_url
        self.headless = headless
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.enable_recon = enable_recon
        self.enable_fuzzing = enable_fuzzing
        self.enable_verification = enable_verification
        self.max_concurrency = max_concurrency
        
        # Components
        self._page: Optional[Page] = None
        self._browser = None
        self._playwright = None
        self._http_client: Optional[httpx.AsyncClient] = None
        
        self._interceptor: Optional[RequestInterceptor] = None
        self._recon_scanner: Optional[DeepReconScanner] = None
        self._fuzzer: Optional[MultiVectorFuzzer] = None
        self._vuln_engine: Optional[VulnerabilityEngine] = None
        self._crawler: Optional[AutoCrawler] = None
        
        # State
        self._scan_result: Optional[ScanResult] = None
        self._is_running = False
    
    async def __aenter__(self):
        await self._initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._cleanup()
    
    async def _initialize(self):
        """Initialize all components"""
        logger.info("Initializing ApexScanner...")
        
        # Start Playwright
        self._playwright = await async_playwright().start()
        
        # Launch browser
        browser_args = [
            "--disable-blink-features=AutomationControlled",
            "--disable-dev-shm-usage",
            "--no-sandbox",
            "--disable-setuid-sandbox",
        ]
        
        self._browser = await self._playwright.chromium.launch(
            headless=self.headless,
            args=browser_args
        )
        
        # Create context
        context = await self._browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )
        
        self._page = await context.new_page()
        
        # Initialize HTTP client
        self._http_client = httpx.AsyncClient(
            timeout=30,
            follow_redirects=False,
            verify=False
        )
        
        # Initialize interceptor
        self._interceptor = RequestInterceptor(
            page=self._page,
            max_queue_size=1000,
            enable_body_capture=True,
            filter_static=True
        )
        await self._interceptor.attach(self._page)
        
        # Initialize recon scanner
        self._recon_scanner = DeepReconScanner(
            page=self._page,
            base_url=self.target_url
        )
        
        # Initialize fuzzer
        self._fuzzer = MultiVectorFuzzer(
            page=self._page,
            http_client=self._http_client,
            timeout=self.timeout,
            max_concurrency=self.max_concurrency
        )
        
        # Initialize vulnerability engine
        self._vuln_engine = VulnerabilityEngine(
            page=self._page,
            http_client=self._http_client,
            enable_browser_verification=self.enable_verification
        )
        
        # Initialize crawler
        self._crawler = AutoCrawler(
            page=self._page,
            base_url=self.target_url,
            max_depth=self.max_depth,
            max_pages=self.max_pages,
            timeout=self.timeout
        )
        
        logger.info("ApexScanner initialized successfully")
    
    async def _cleanup(self):
        """Cleanup resources"""
        logger.info("Cleaning up resources...")
        
        if self._http_client:
            await self._http_client.aclose()
        
        if self._browser:
            await self._browser.close()
        
        if self._playwright:
            await self._playwright.stop()
        
        logger.info("Cleanup complete")
    
    async def scan(self) -> ScanResult:
        """
        Run complete ApexScanner scan
        """
        logger.info(f"Starting ApexScanner scan on {self.target_url}")
        
        self._is_running = True
        start_time = time.time()
        
        # Initialize scan result
        self._scan_result = ScanResult(
            scan_id=f"apex_{int(start_time)}",
            target_url=self.target_url,
            status="running",
            start_time=start_time
        )
        
        try:
            # Step 1: Navigate to target
            logger.info("Step 1: Navigating to target...")
            await self._page.goto(self.target_url, wait_until='networkidle', timeout=self.timeout)
            await asyncio.sleep(2)  # Wait for initial render
            
            # Step 2: Deep Reconnaissance
            if self.enable_recon:
                logger.info("Step 2: Running deep reconnaissance...")
                recon_results = await self._recon_scanner.scan(max_depth=self.max_depth)
                
                self._scan_result.endpoints_discovered = recon_results.get('endpoints', [])
                self._scan_result.secrets_found = recon_results.get('secrets', [])
                self._scan_result.comments_found = recon_results.get('comments', [])
                
                logger.info(f"Recon complete: {len(recon_results.get('endpoints', []))} endpoints found")
            
            # Step 3: Auto-crawl to discover more endpoints
            logger.info("Step 3: Running auto-crawler...")
            crawl_results = await self._crawler.crawl()
            
            # Merge discovered endpoints
            crawl_endpoints = crawl_results.get('discovered_endpoints', [])
            for endpoint in crawl_endpoints:
                if endpoint not in [e.get('url') for e in self._scan_result.endpoints_discovered]:
                    self._scan_result.endpoints_discovered.append({
                        'url': endpoint,
                        'method': 'GET',
                        'source': 'crawler'
                    })
            
            logger.info(f"Crawl complete: {len(crawl_endpoints)} additional endpoints")
            
            # Step 4: Fuzz discovered endpoints
            if self.enable_fuzzing:
                logger.info("Step 4: Running multi-vector fuzzing...")
                
                # Get intercepted requests
                intercepted_pairs = self._interceptor.get_all_pairs()
                
                # Fuzz each intercepted request
                fuzz_tasks = []
                for pair in intercepted_pairs[:50]:  # Limit to 50 requests
                    request_data = pair.request.to_fuzzing_input()
                    fuzz_tasks.append(self._fuzzer.fuzz_endpoint(request_data))
                
                # Also fuzz recon endpoints
                for endpoint in self._scan_result.endpoints_discovered[:30]:
                    request_data = {
                        'url': endpoint.get('url'),
                        'method': endpoint.get('method', 'GET'),
                        'headers': {},
                        'body_json': {},
                        'query_params': {}
                    }
                    fuzz_tasks.append(self._fuzzer.fuzz_endpoint(request_data))
                
                # Execute fuzzing
                fuzz_results = await asyncio.gather(*fuzz_tasks, return_exceptions=True)
                
                # Collect vulnerabilities
                for result in fuzz_results:
                    if isinstance(result, list):
                        for vuln in result:
                            self._scan_result.vulnerabilities.append(vuln.to_dict())
                
                logger.info(f"Fuzzing complete: {len(self._scan_result.vulnerabilities)} potential vulnerabilities")
            
            # Step 5: Verify vulnerabilities
            if self.enable_verification and self._scan_result.vulnerabilities:
                logger.info("Step 5: Verifying vulnerabilities...")
                
                verified_vulns = []
                
                for vuln_candidate in self._scan_result.vulnerabilities[:20]:  # Limit verification
                    verified = await self._vuln_engine.verify_vulnerability(vuln_candidate)
                    
                    # Only include verified/likely vulnerabilities
                    if verified.verification_status in [VerificationStatus.VERIFIED, VerificationStatus.LIKELY]:
                        verified_vulns.append(verified.to_dict())
                
                self._scan_result.vulnerabilities = verified_vulns
                logger.info(f"Verification complete: {len(verified_vulns)} confirmed vulnerabilities")
            
            # Update scan result
            self._scan_result.status = "completed"
            self._scan_result.end_time = time.time()
            self._scan_result.statistics = self._collect_statistics()
            
        except Exception as e:
            logger.error(f"Scan error: {e}", exc_info=True)
            self._scan_result.status = "failed"
            self._scan_result.errors.append(str(e))
            self._scan_result.end_time = time.time()
        
        finally:
            self._is_running = False
        
        return self._scan_result
    
    def _collect_statistics(self) -> Dict[str, Any]:
        """Collect statistics from all modules"""
        stats = {
            'interceptor': self._interceptor.get_statistics() if self._interceptor else {},
            'recon': self._recon_scanner.get_statistics() if self._recon_scanner else {},
            'fuzzer': self._fuzzer.get_statistics() if self._fuzzer else {},
            'crawler': self._crawler.get_statistics() if self._crawler else {},
            'verification': self._vuln_engine.get_statistics() if self._vuln_engine else {}
        }
        return stats
    
    def get_result(self) -> Optional[ScanResult]:
        """Get current scan result"""
        return self._scan_result
    
    def is_running(self) -> bool:
        """Check if scan is running"""
        return self._is_running


async def run_apex_scan(
    target_url: str,
    headless: bool = True,
    max_depth: int = 3,
    enable_recon: bool = True,
    enable_fuzzing: bool = True,
    enable_verification: bool = True
) -> Dict[str, Any]:
    """
    Convenience function to run ApexScanner
    """
    async with ApexScanner(
        target_url=target_url,
        headless=headless,
        max_depth=max_depth,
        enable_recon=enable_recon,
        enable_fuzzing=enable_fuzzing,
        enable_verification=enable_verification
    ) as scanner:
        result = await scanner.scan()
        return result.to_dict()


if __name__ == "__main__":
    import sys
    
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
    
    print("="*60)
    print("ApexScanner - High-Performance DAST Framework")
    print("="*60)
    print(f"Target: {target}")
    print()
    
    # Run scan
    result = asyncio.run(run_apex_scan(
        target_url=target,
        headless=True,
        max_depth=3,
        enable_recon=True,
        enable_fuzzing=True,
        enable_verification=True
    ))
    
    # Print results
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    print(f"Status: {result['status']}")
    print(f"Duration: {result.get('duration_seconds', 0):.2f}s")
    print(f"Endpoints Discovered: {result['endpoints_discovered']}")
    print(f"Vulnerabilities: {result['vulnerabilities_count']}")
    print(f"By Severity: {result['vulnerabilities_by_severity']}")
    print(f"Secrets Found: {result['secrets_found']}")
