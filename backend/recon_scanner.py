"""
Recon Scanner - Интеграция bug bounty инструментов
Subfinder, httpx, naabu, gobuster, katana, gau, waybackurls, dnsx, interactsh
"""
import subprocess
import json
import os
import tempfile
from typing import Dict, List, Any, Optional
import time


class ReconScanner:
    """Сканер разведки с использованием внешних инструментов"""
    
    def __init__(self, target: str, tools_dir: str = None):
        self.target = target
        self.domain = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        
        # Пути к инструментам
        if tools_dir is None:
            tools_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools")
        self.tools_dir = tools_dir
        
        # Проверка доступных инструментов
        self.available_tools = self._check_tools()
    
    def _check_tools(self) -> Dict[str, bool]:
        """Проверка доступных инструментов"""
        tools = {
            "subfinder": False,
            "httpx": False,
            "naabu": False,
            "gobuster": False,
            "katana": False,
            "gau": False,
            "waybackurls": False,
            "dnsx": False,
            "interactsh-client": False,
            "nuclei": False,
            "dalfox": False,
            "ffuf": False,
            "sqlmap": False,
        }
        
        for tool in tools:
            # Проверяем в tools_dir
            tool_path = os.path.join(self.tools_dir, tool)
            if os.path.exists(tool_path) and os.access(tool_path, os.X_OK):
                tools[tool] = True
            # Проверяем в PATH
            else:
                try:
                    subprocess.run(["which", tool], capture_output=True, check=True)
                    tools[tool] = True
                except subprocess.CalledProcessError:
                    tools[tool] = False
        
        return tools
    
    def run_subfinder(self) -> Dict[str, Any]:
        """Поиск поддоменов через subfinder"""
        result = {
            "tool": "subfinder",
            "type": "subdomain-enumeration",
            "subdomains": [],
            "error": None
        }
        
        if not self.available_tools.get("subfinder"):
            result["error"] = "subfinder not available"
            return result
        
        try:
            cmd = [
                os.path.join(self.tools_dir, "subfinder"),
                "-d", self.domain,
                "-json",
                "-silent"
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            for line in proc.stdout.strip().split("\n"):
                if line:
                    try:
                        data = json.loads(line)
                        result["subdomains"].append({
                            "domain": data.get("host", ""),
                            "source": data.get("source", ""),
                            "ip": data.get("ip", "")
                        })
                    except json.JSONDecodeError:
                        result["subdomains"].append({"domain": line, "source": "unknown"})
            
            result["count"] = len(result["subdomains"])
        except subprocess.TimeoutExpired:
            result["error"] = "timeout"
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def run_httpx(self, targets: List[str] = None) -> Dict[str, Any]:
        """Проверка живых хостов и технологий через httpx"""
        result = {
            "tool": "httpx",
            "type": "tech-detection",
            "live_hosts": [],
            "technologies": [],
            "error": None
        }
        
        if not self.available_tools.get("httpx"):
            result["error"] = "httpx not available"
            return result
        
        if targets is None:
            targets = [self.target]
        
        try:
            # Создаем временный файл со списком целей
            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
                for t in targets:
                    f.write(f"{t}\n")
                temp_file = f.name
            
            cmd = [
                os.path.join(self.tools_dir, "httpx"),
                "-l", temp_file,
                "-json",
                "-silent",
                "-tech-detect",
                "-title",
                "-status-code"
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            for line in proc.stdout.strip().split("\n"):
                if line:
                    try:
                        data = json.loads(line)
                        host_info = {
                            "url": data.get("url", ""),
                            "title": data.get("title", ""),
                            "status_code": data.get("status_code", 0),
                            "technologies": data.get("tech", []),
                            "content_type": data.get("content_type", ""),
                            "content_length": data.get("content_length", 0)
                        }
                        result["live_hosts"].append(host_info)
                        
                        for tech in data.get("tech", []):
                            if tech not in result["technologies"]:
                                result["technologies"].append(tech)
                    except json.JSONDecodeError:
                        pass
            
            os.unlink(temp_file)
            result["count"] = len(result["live_hosts"])
        except subprocess.TimeoutExpired:
            result["error"] = "timeout"
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def run_naabu(self) -> Dict[str, Any]:
        """Сканирование портов через naabu"""
        result = {
            "tool": "naabu",
            "type": "port-scan",
            "ports": [],
            "error": None
        }
        
        if not self.available_tools.get("naabu"):
            result["error"] = "naabu not available"
            return result
        
        try:
            cmd = [
                os.path.join(self.tools_dir, "naabu"),
                "-host", self.domain,
                "-json",
                "-silent",
                "-top-ports", "1000"
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            for line in proc.stdout.strip().split("\n"):
                if line:
                    try:
                        data = json.loads(line)
                        result["ports"].append({
                            "ip": data.get("ip", ""),
                            "port": data.get("port", 0),
                            "protocol": data.get("protocol", "tcp"),
                            "tls": data.get("tls", False)
                        })
                    except json.JSONDecodeError:
                        pass
            
            result["count"] = len(result["ports"])
        except subprocess.TimeoutExpired:
            result["error"] = "timeout"
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def run_gobuster(self, wordlist: str = None) -> Dict[str, Any]:
        """Поиск директорий через gobuster"""
        result = {
            "tool": "gobuster",
            "type": "directory-bruteforce",
            "directories": [],
            "error": None
        }
        
        if not self.available_tools.get("gobuster"):
            result["error"] = "gobuster not available"
            return result
        
        # Wordlist по умолчанию
        if wordlist is None:
            wordlist = "/usr/share/wordlists/dirb/common.txt"
            if not os.path.exists(wordlist):
                wordlist = "/opt/homebrew/share/wordlists/dirb/common.txt"
            if not os.path.exists(wordlist):
                # Создаем минимальный wordlist
                wordlist = os.path.join(tempfile.gettempdir(), "gobuster_wordlist.txt")
                with open(wordlist, "w") as f:
                    f.write("\n".join([
                        "admin", "api", "app", "auth", "backup", "blog", "config",
                        "dashboard", "data", "db", "dev", "docs", "download", "files",
                        "images", "img", "index", "js", "login", "media", "old",
                        "panel", "php", "private", "public", "search", "secure",
                        "server", "site", "src", "static", "test", "tmp", "upload",
                        "uploads", "user", "users", "v1", "v2", "wp", "wp-admin",
                        "wp-content", "wp-includes", "www", "xmlrpc"
                    ]))
        
        try:
            cmd = [
                os.path.join(self.tools_dir, "gobuster"),
                "dir",
                "-u", self.target,
                "-w", wordlist,
                "-q",
                "-o", "/dev/stdout"
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            for line in proc.stdout.strip().split("\n"):
                if line and ("Found:" in line or "Status:" in line or line.startswith("/")):
                    parts = line.split()
                    if len(parts) >= 2:
                        path = parts[0].replace("Found:", "").replace("Status:", "").strip()
                        status = parts[1] if len(parts) > 1 else ""
                        if path.startswith("/"):
                            result["directories"].append({
                                "path": path,
                                "status": status,
                                "url": f"{self.target}{path}"
                            })
            
            result["count"] = len(result["directories"])
        except subprocess.TimeoutExpired:
            result["error"] = "timeout"
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def run_katana(self) -> Dict[str, Any]:
        """Crawling сайта через katana"""
        result = {
            "tool": "katana",
            "type": "crawler",
            "urls": [],
            "endpoints": [],
            "error": None
        }
        
        if not self.available_tools.get("katana"):
            result["error"] = "katana not available"
            return result
        
        try:
            cmd = [
                os.path.join(self.tools_dir, "katana"),
                "-u", self.target,
                "-json",
                "-silent",
                "-d", "3",  # глубина 3
                "-jc"  # парсить JavaScript
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            for line in proc.stdout.strip().split("\n"):
                if line:
                    try:
                        data = json.loads(line)
                        url_info = {
                            "url": data.get("endpoint", ""),
                            "method": data.get("method", "GET"),
                            "source": data.get("source", "")
                        }
                        result["urls"].append(url_info)
                        
                        # Выделяем API endpoints
                        if "/api/" in url_info["url"] or "?" in url_info["url"]:
                            result["endpoints"].append(url_info)
                    except json.JSONDecodeError:
                        pass
            
            result["count"] = len(result["urls"])
            result["endpoints_count"] = len(result["endpoints"])
        except subprocess.TimeoutExpired:
            result["error"] = "timeout"
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def run_gau(self) -> Dict[str, Any]:
        """Получение URL из архивов через gau"""
        result = {
            "tool": "gau",
            "type": "archive-urls",
            "urls": [],
            "error": None
        }
        
        if not self.available_tools.get("gau"):
            result["error"] = "gau not available"
            return result
        
        try:
            cmd = [
                os.path.join(self.tools_dir, "gau"),
                self.domain,
                "--threads", "5",
                "--max-urls", "100"
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            for line in proc.stdout.strip().split("\n"):
                if line and line.startswith("http"):
                    result["urls"].append(line)
            
            result["count"] = len(result["urls"])
        except subprocess.TimeoutExpired:
            result["error"] = "timeout"
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def run_waybackurls(self) -> Dict[str, Any]:
        """Получение URL из Wayback Machine"""
        result = {
            "tool": "waybackurls",
            "type": "archive-urls",
            "urls": [],
            "error": None
        }
        
        if not self.available_tools.get("waybackurls"):
            result["error"] = "waybackurls not available"
            return result
        
        try:
            cmd = [
                os.path.join(self.tools_dir, "waybackurls"),
                self.domain
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            for line in proc.stdout.strip().split("\n"):
                if line and line.startswith("http"):
                    result["urls"].append(line)
            
            result["count"] = len(result["urls"])
        except subprocess.TimeoutExpired:
            result["error"] = "timeout"
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def run_dnsx(self, subdomains: List[str] = None) -> Dict[str, Any]:
        """DNS разведка через dnsx"""
        result = {
            "tool": "dnsx",
            "type": "dns-enumeration",
            "records": [],
            "error": None
        }
        
        if not self.available_tools.get("dnsx"):
            result["error"] = "dnsx not available"
            return result
        
        targets = subdomains if subdomains else [self.domain]
        
        try:
            # Создаем временный файл со списком доменов
            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
                for t in targets:
                    f.write(f"{t}\n")
                temp_file = f.name
            
            cmd = [
                os.path.join(self.tools_dir, "dnsx"),
                "-l", temp_file,
                "-json",
                "-silent",
                "-a", "-cname", "-mx", "-ns", "-txt"
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            for line in proc.stdout.strip().split("\n"):
                if line:
                    try:
                        data = json.loads(line)
                        record = {
                            "domain": data.get("host", ""),
                            "a_records": data.get("a", []),
                            "cname": data.get("cname", []),
                            "mx": data.get("mx", []),
                            "ns": data.get("ns", []),
                            "txt": data.get("txt", [])
                        }
                        result["records"].append(record)
                    except json.JSONDecodeError:
                        pass
            
            os.unlink(temp_file)
            result["count"] = len(result["records"])
        except subprocess.TimeoutExpired:
            result["error"] = "timeout"
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def run_full_recon(self) -> Dict[str, Any]:
        """Запуск полной разведки"""
        results = {
            "target": self.target,
            "domain": self.domain,
            "timestamp": time.time(),
            "tools_available": self.available_tools,
            "subdomains": None,
            "live_hosts": None,
            "ports": None,
            "directories": None,
            "crawler": None,
            "archive_urls": None,
            "dns": None
        }
        
        # 1. Subdomain enumeration
        print(f"[recon] Запуск subfinder для {self.domain}...")
        results["subdomains"] = self.run_subfinder()
        
        # Собираем все поддомены
        all_subdomains = [self.domain]
        if results["subdomains"]["subdomains"]:
            all_subdomains.extend([s["domain"] for s in results["subdomains"]["subdomains"]])
        
        # 2. DNS enumeration
        print(f"[recon] Запуск dnsx...")
        results["dns"] = self.run_dnsx(all_subdomains)
        
        # 3. HTTPX - проверка живых хостов
        print(f"[recon] Запуск httpx...")
        results["live_hosts"] = self.run_httpx([self.target])
        
        # 4. Port scan
        print(f"[recon] Запуск naabu...")
        results["ports"] = self.run_naabu()
        
        # 5. Directory bruteforce
        print(f"[recon] Запуск gobuster...")
        results["directories"] = self.run_gobuster()
        
        # 6. Crawler
        print(f"[recon] Запуск katana...")
        results["crawler"] = self.run_katana()
        
        # 7. Archive URLs
        print(f"[recon] Запуск gau + waybackurls...")
        gau_result = self.run_gau()
        wayback_result = self.run_waybackurls()
        results["archive_urls"] = {
            "gau": gau_result,
            "waybackurls": wayback_result,
            "unique_urls": list(set(gau_result.get("urls", []) + wayback_result.get("urls", [])))
        }
        
        return results
    
    def convert_to_findings(self, recon_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Конвертация результатов recon в findings формат"""
        findings = []
        
        # Subdomains
        if recon_results.get("subdomains") and recon_results["subdomains"].get("subdomains"):
            for sub in recon_results["subdomains"]["subdomains"]:
                findings.append({
                    "template-id": "subdomain-discovered",
                    "tool": "recon-subfinder",
                    "info": {
                        "name": f"Subdomain Discovered: {sub['domain']}",
                        "description": f"Found via {sub.get('source', 'unknown')}",
                        "severity": "info",
                        "cwe-id": []
                    },
                    "url": f"http://{sub['domain']}",
                    "matched-at": sub['domain'],
                    "evidence": f"Source: {sub.get('source', 'unknown')}"
                })
        
        # Technologies
        if recon_results.get("live_hosts") and recon_results["live_hosts"].get("live_hosts"):
            for host in recon_results["live_hosts"]["live_hosts"]:
                techs = host.get("technologies", [])
                if techs:
                    findings.append({
                        "template-id": "tech-stack-detected",
                        "tool": "recon-httpx",
                        "info": {
                            "name": f"Tech Stack: {', '.join(techs[:5])}",
                            "description": f"Technologies detected on {host['url']}",
                            "severity": "info",
                            "cwe-id": []
                        },
                        "url": host["url"],
                        "matched-at": host["url"],
                        "evidence": f"Technologies: {', '.join(techs)}"
                    })
        
        # Open Ports
        if recon_results.get("ports") and recon_results["ports"].get("ports"):
            for port in recon_results["ports"]["ports"]:
                severity = "medium" if port["port"] in [21, 22, 23, 3389, 5900] else "info"
                findings.append({
                    "template-id": f"open-port-{port['port']}",
                    "tool": "recon-naabu",
                    "info": {
                        "name": f"Open Port: {port['port']}/{port['protocol']}",
                        "description": f"Port {port['port']} is open on {port['ip']}",
                        "severity": severity,
                        "cwe-id": []
                    },
                    "url": f"{port['ip']}:{port['port']}",
                    "matched-at": f"{port['ip']}:{port['port']}",
                    "evidence": f"TLS: {port.get('tls', False)}"
                })
        
        # Directories
        if recon_results.get("directories") and recon_results["directories"].get("directories"):
            for dir_info in recon_results["directories"]["directories"]:
                status = dir_info.get("status", "")
                severity = "info"
                if status.startswith("2"):
                    severity = "info"
                elif status.startswith("3"):
                    severity = "info"
                elif status.startswith("4"):
                    severity = "low"
                elif status.startswith("5"):
                    severity = "medium"
                
                findings.append({
                    "template-id": "directory-discovered",
                    "tool": "recon-gobuster",
                    "info": {
                        "name": f"Directory: {dir_info['path']}",
                        "description": f"Status: {status}",
                        "severity": severity,
                        "cwe-id": []
                    },
                    "url": dir_info["url"],
                    "matched-at": dir_info["url"],
                    "evidence": f"HTTP {status}"
                })
        
        # API Endpoints
        if recon_results.get("crawler") and recon_results["crawler"].get("endpoints"):
            for endpoint in recon_results["crawler"]["endpoints"][:20]:  # лимит 20
                findings.append({
                    "template-id": "api-endpoint-discovered",
                    "tool": "recon-katana",
                    "info": {
                        "name": f"API Endpoint: {endpoint['url']}",
                        "description": f"Method: {endpoint['method']}",
                        "severity": "info",
                        "cwe-id": []
                    },
                    "url": endpoint["url"],
                    "matched-at": endpoint["url"],
                    "evidence": f"Method: {endpoint['method']}"
                })
        
        return findings


if __name__ == "__main__":
    # Тест
    scanner = ReconScanner("https://example.com")
    print(f"Available tools: {scanner.available_tools}")
    result = scanner.run_subfinder()
    print(f"Subdomains: {result}")
