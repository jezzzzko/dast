import subprocess
import os
import time
import json
import requests
from datetime import datetime
from typing import List, Dict


class DASTScanner:
    """DAST Scanner с поддержкой Nuclei, ZAP и Burp"""

    def __init__(self, target_url: str, scan_mode: str = "full"):
        self.target_url = target_url
        self.scan_mode = scan_mode
        self.result_dir = "/tmp/dast_scans"
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = f"{self.result_dir}/scan_{self.timestamp}.log"
        os.makedirs(self.result_dir, exist_ok=True)

        self.burp_api_key = ""
        self.burp_host = "127.0.0.1"
        self.burp_port = 1337

    def log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_msg = f"[{timestamp}] [{level}] {message}"
        print(log_msg)
        try:
            with open(self.log_file, "a") as f:
                f.write(log_msg + "\n")
        except:
            pass

    def run_nuclei_scan(self) -> List[Dict]:
        """Запускает Nuclei сканирование по ВСЕМ шаблонам"""
        self.log("Запуск Nuclei сканирования...", "NUCLEI")
        result_file = f"{self.result_dir}/nuclei_{self.timestamp}.jsonl"

        try:
            self.log("Обновление шаблонов Nuclei...", "NUCLEI")
            subprocess.run(["nuclei", "-ut"], capture_output=True, timeout=120)

            # Сканирование ВСЕМИ шаблонами включая CVE, SQLi, XSS
            cmd = [
                "nuclei",
                "-u", self.target_url,
                "-jle", result_file,
                "-severity", "critical,high,medium,low,info",
                "-timeout", "15",
                "-retries", "2",
                "-rate-limit", "150",
                "-concurrency", "30",
                "-system-resolvers",
                "-follow-redirects",
                "-max-redirects", "10",
                "-silent"
            ]

            self.log(f"Сканирование: {self.target_url}", "NUCLEI")
            subprocess.run(cmd, capture_output=True, text=True, timeout=3600)

            findings = []
            if os.path.exists(result_file):
                with open(result_file, "r") as f:
                    for line in f:
                        if line.strip():
                            try:
                                finding = json.loads(line)
                                finding['tool'] = 'nuclei'
                                findings.append(finding)
                            except:
                                pass

            self.log(f"Найдено уязвимостей: {len(findings)}", "NUCLEI")
            return findings

        except subprocess.TimeoutExpired:
            self.log("Превышен таймаут", "ERROR")
            findings = []
            if os.path.exists(result_file):
                with open(result_file, "r") as f:
                    for line in f:
                        if line.strip():
                            try:
                                findings.append(json.loads(line))
                            except:
                                pass
            return findings
        except Exception as e:
            self.log(f"Ошибка: {str(e)}", "ERROR")
            return []

    def run_zap_scan(self) -> List[Dict]:
        """Запускает OWASP ZAP сканирование с атаками на SQLi, XSS и т.д."""
        self.log("Запуск OWASP ZAP сканирования...", "ZAP")
        zap_port = 8090
        zap_api_key = "dast-scanner-key"
        findings = []
        zap_process = None
        zap_running = False

        try:
            # Проверяем запущен ли ZAP
            try:
                resp = requests.get(f"http://127.0.0.1:{zap_port}", timeout=3)
                zap_running = True
                self.log("ZAP уже запущен", "ZAP")
            except:
                pass

            if not zap_running:
                try:
                    subprocess.run(["pkill", "-f", "zap-.*jar"], capture_output=True, timeout=5)
                    time.sleep(2)
                except:
                    pass

                self.log("Запуск ZAP daemon...", "ZAP")
                zap_process = subprocess.Popen(
                    ["/Applications/ZAP.app/Contents/Java/zap.sh", "-daemon", "-port", str(zap_port),
                     "-api", "key", zap_api_key, "-config", "api.addrs.addr.name=.*",
                     "-config", "api.addrs.addr.regex=true",
                     "-config", "spider.maxDuration=10",
                     "-config", "spider.maxChildren=100",
                     "-config", "ajaxSpider.maxDuration=10"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )

                self.log("Ожидание запуска ZAP (45 сек)...", "ZAP")
                time.sleep(45)

            api_base = f"http://127.0.0.1:{zap_port}"

            # Проверяем API
            try:
                resp = requests.get(f"{api_base}/JSON/core/view/version", params={"apikey": zap_api_key}, timeout=10)
                self.log(f"ZAP версия: {resp.json().get('version', 'unknown')}", "ZAP")
            except Exception as e:
                self.log(f"ZAP API недоступен: {e}", "ERROR")
                if zap_process:
                    zap_process.terminate()
                return []

            # Доступ к URL
            try:
                requests.get(f"{api_base}/JSON/core/action/accessUrl",
                           params={"url": self.target_url, "apikey": zap_api_key}, timeout=10)
            except:
                pass
            time.sleep(3)

            # Spider - обход сайта
            self.log("Запуск Spider...", "ZAP")
            spider_scan_id = ""
            try:
                resp = requests.get(f"{api_base}/JSON/spider/action/scan",
                                  params={"url": self.target_url, "apikey": zap_api_key}, timeout=10)
                spider_scan_id = resp.json().get("scan", "")

                for i in range(120):
                    try:
                        resp = requests.get(f"{api_base}/JSON/spider/view/status",
                                          params={"scanId": spider_scan_id, "apikey": zap_api_key}, timeout=5)
                        status = int(resp.json().get("status", 0))
                        if i % 10 == 0:
                            self.log(f"Spider: {status}%", "ZAP")
                        if status >= 100:
                            break
                        time.sleep(5)
                    except:
                        break
            except Exception as e:
                self.log(f"Spider ошибка: {e}", "WARN")

            self.log("Spider завершён", "ZAP")

            # AJAX Spider
            self.log("Запуск AJAX Spider...", "ZAP")
            try:
                requests.get(f"{api_base}/JSON/ajaxSpider/action/scan",
                           params={"url": self.target_url, "apikey": zap_api_key}, timeout=10)

                for i in range(120):
                    try:
                        resp = requests.get(f"{api_base}/JSON/ajaxSpider/view/status",
                                          params={"apikey": zap_api_key}, timeout=5)
                        status = resp.json().get("status", "running")
                        if i % 10 == 0:
                            self.log(f"AJAX Spider: {status}", "ZAP")
                        if status == "stopped":
                            break
                        time.sleep(5)
                    except:
                        break
            except Exception as e:
                self.log(f"AJAX Spider ошибка: {e}", "WARN")

            self.log("AJAX Spider завершён", "ZAP")

            # Получаем все URL
            self.log("Сканирование URL...", "ZAP")
            try:
                resp = requests.get(f"{api_base}/JSON/core/view/urls",
                                  params={"url": self.target_url, "apikey": zap_api_key}, timeout=30)
                urls_data = resp.json()
                urls = urls_data.get("urls", [])
                self.log(f"Найдено URL: {len(urls)}", "ZAP")
            except:
                urls = [self.target_url]

            # Active Scan - АТАКИ на уязвимости
            self.log("Запуск Active Scan (атаки)...", "ZAP")
            try:
                # Включаем ВСЕ политики сканирования
                # Default + SQLi + XSS + Path Traversal + etc
                resp = requests.get(f"{api_base}/JSON/ascan/action/scan",
                                  params={"url": self.target_url, "apikey": zap_api_key,
                                          "scanpolicyname": "Default", "recurse": "true"}, timeout=10)
                ascan_scan_id = resp.json().get("scan", "")

                for i in range(300):
                    try:
                        resp = requests.get(f"{api_base}/JSON/ascan/view/status",
                                          params={"scanId": ascan_scan_id, "apikey": zap_api_key}, timeout=5)
                        status = int(resp.json().get("status", 0))
                        if i % 30 == 0:
                            self.log(f"Active Scan: {status}%", "ZAP")
                        if status >= 100:
                            break
                        time.sleep(10)
                    except:
                        break
            except Exception as e:
                self.log(f"Active Scan ошибка: {e}", "WARN")

            self.log("Active Scan завершён", "ZAP")

            # Получаем результаты
            self.log("Получение результатов...", "ZAP")
            try:
                resp = requests.get(f"{api_base}/JSON/core/view/alerts",
                                  params={"url": self.target_url, "apikey": zap_api_key}, timeout=30)
                alerts = resp.json().get("alerts", [])
                self.log(f"Найдено alerts: {len(alerts)}", "ZAP")

                severity_map = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}

                for alert in alerts:
                    finding = {
                        "template-id": str(alert.get("pluginid", "unknown")),
                        "tool": "zap",
                        "info": {
                            "name": alert.get("alert", "Unknown"),
                            "description": alert.get("description", "")[:1000],
                            "severity": severity_map.get(alert.get("risk", "Informational"), "info"),
                            "solution": alert.get("solution", "")[:1000],
                            "cwe-id": [f"CWE-{alert.get('cweid', 0)}"] if alert.get('cweid') else [],
                            "reference": alert.get("reference", "").split("\n") if alert.get("reference") else []
                        },
                        "url": alert.get("url", ""),
                        "matched-at": alert.get("url", ""),
                        "param": alert.get("param", ""),
                        "attack": alert.get("attack", ""),
                        "evidence": alert.get("evidence", "")
                    }
                    findings.append(finding)

                self.log(f"ZAP завершён. Найдено: {len(findings)} уязвимостей", "ZAP")
            except Exception as e:
                self.log(f"Ошибка получения результатов: {e}", "ERROR")

            if not zap_running:
                try:
                    requests.get(f"{api_base}/JSON/core/action/shutdown", params={"apikey": zap_api_key}, timeout=5)
                except:
                    pass
                if zap_process:
                    zap_process.terminate()

            return findings

        except Exception as e:
            self.log(f"ZAP ошибка: {str(e)}", "ERROR")
            if zap_process:
                zap_process.terminate()
            return []

    def run_burp_scan(self) -> List[Dict]:
        """Запускает Burp Suite сканирование"""
        self.log("Запуск Burp Suite...", "BURP")
        findings = []

        if not self.burp_api_key:
            self.log("Burp API key не установлен", "ERROR")
            return []

        try:
            api_base = f"http://{self.burp_host}:{self.burp_port}/{self.burp_api_key}/v0.1"
            headers = {"Content-Type": "application/json"}

            try:
                resp = requests.get(api_base, headers=headers, timeout=10)
                self.log("Burp API доступен", "BURP")
            except Exception as e:
                self.log(f"Burp API недоступен: {e}", "ERROR")
                return []

            scan_config = {
                "urls": [self.target_url],
                "scan_configurations": [{"type": "audit_config", "name": "Default"}]
            }

            try:
                resp = requests.post(f"{api_base}/scan", headers=headers, json=scan_config, timeout=30)
                if resp.status_code != 201:
                    self.log(f"Ошибка создания скана: {resp.status_code}", "ERROR")
                    return []
                scan_id = resp.json().get("scan_id", "")
                self.log(f"Scan ID: {scan_id}", "BURP")
            except Exception as e:
                self.log(f"Ошибка создания скана: {e}", "ERROR")
                return []

            self.log("Ожидание завершения...", "BURP")
            for i in range(180):
                try:
                    resp = requests.get(f"{api_base}/scan/{scan_id}", headers=headers, timeout=30)
                    scan_status = resp.json().get("scan_status", {})
                    state = scan_status.get("state", "")
                    progress = scan_status.get("percentage_complete", 0)

                    if i % 30 == 0:
                        self.log(f"Burp прогресс: {progress}% ({state})", "BURP")

                    if state in ["succeeded", "failed", "cancelled"]:
                        break

                    time.sleep(10)
                except:
                    time.sleep(10)

            try:
                resp = requests.get(f"{api_base}/scan/{scan_id}",
                                  headers=headers, params={"issue_events": "true"}, timeout=30)

                if resp.status_code == 200:
                    scan_data = resp.json()
                    issue_events = scan_data.get("issue_events", [])

                    severity_map = {"High": "high", "Medium": "medium", "Low": "low", "Information": "info"}

                    for event in issue_events:
                        issue = event.get("issue", {})
                        finding = {
                            "template-id": str(issue.get("issue_type_id", "unknown")),
                            "tool": "burp",
                            "info": {
                                "name": issue.get("name", "Unknown"),
                                "description": issue.get("description", "")[:500],
                                "severity": severity_map.get(issue.get("severity", "Information"), "info"),
                                "solution": issue.get("remediation", "")[:500],
                                "cwe-id": []
                            },
                            "url": issue.get("location", {}).get("url", ""),
                            "matched-at": issue.get("location", {}).get("url", ""),
                            "evidence": issue.get("evidence", "")
                        }
                        findings.append(finding)

                    self.log(f"Burp завершён. Найдено: {len(findings)} уязвимостей", "BURP")
            except Exception as e:
                self.log(f"Ошибка получения результатов: {e}", "ERROR")

            return findings

        except Exception as e:
            self.log(f"Burp ошибка: {str(e)}", "ERROR")
            return []

    def remove_duplicates(self, findings: List[Dict]) -> List[Dict]:
        seen = set()
        unique = []
        for f in findings:
            key = f"{f.get('url', '')}-{f.get('info', {}).get('name', '')}-{f.get('template-id', '')}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def run(self) -> List[Dict]:
        self.log("="*50)
        self.log(f"DAST Scanner запущен")
        self.log(f"Цель: {self.target_url}")
        self.log(f"Режим: {self.scan_mode}")
        self.log("="*50)

        all_findings = []

        # Nuclei (всегда)
        try:
            nuclei_findings = self.run_nuclei_scan()
            all_findings.extend(nuclei_findings)
        except Exception as e:
            self.log(f"Nuclei ошибка: {e}", "ERROR")

        # ZAP (полный режим)
        if self.scan_mode in ["full", "zap"]:
            try:
                zap_findings = self.run_zap_scan()
                all_findings.extend(zap_findings)
            except Exception as e:
                self.log(f"ZAP ошибка: {e}", "ERROR")

        # Burp (burp режим)
        if self.scan_mode == "burp":
            try:
                burp_findings = self.run_burp_scan()
                all_findings.extend(burp_findings)
            except Exception as e:
                self.log(f"Burp ошибка: {e}", "ERROR")

        unique_findings = self.remove_duplicates(all_findings)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        unique_findings.sort(key=lambda x: severity_order.get(x.get("info", {}).get("severity", "info"), 5))

        self.log("="*50)
        self.log(f"Сканирование завершено!")
        self.log(f"Всего уязвимостей: {len(unique_findings)}")
        self.log("="*50)

        return unique_findings
