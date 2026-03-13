# 🚀 ApexScanner - High-Performance Automated DAST Framework

## Action-Interception-Mutation Architecture

Профессиональный инструмент для автоматизированного обнаружения уязвимостей в современных SPA приложениях.

---

## 📋 Оглавление

- [Архитектура](#архитектура)
- [Модули](#модули)
- [Быстрый старт](#быстрый-старт)
- [API](#api)
- [Примеры использования](#примеры-использования)
- [Результаты сканирования](#результаты-сканирования)

---

## 🏗️ Архитектура

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ApexScanner                                  │
│  Action-Interception-Mutation Architecture                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────────┐ │
│  │  Auto-Crawler    │  │  Interceptor     │  │  Deep Recon       │ │
│  │  - Click buttons │  │  - Capture XHR   │  │  - Parse JS       │ │
│  │  - Fill forms    │  │  - Queue for     │  │  - Find endpoints │ │
│  │  - Trigger APIs  │  │    fuzzing       │  │  - Extract secrets│ │
│  └────────┬─────────┘  └────────┬─────────┘  └─────────┬─────────┘ │
│           │                      │                      │           │
│           └──────────────────────┼──────────────────────┘           │
│                                  │                                   │
│                    ┌─────────────▼──────────────┐                   │
│                    │   Multi-Vector Fuzzer      │                   │
│                    │   - SQLi, NoSQLi, XSS      │                   │
│                    │   - IDOR/BOLA, SSRF        │                   │
│                    │   - Auth Bypass            │                   │
│                    └─────────────┬──────────────┘                   │
│                                  │                                   │
│                    ┌─────────────▼──────────────┐                   │
│                    │  Vulnerability Engine      │                   │
│                    │  - Response Diffing        │                   │
│                    │  - Zero False Positive     │                   │
│                    │  - Multi-payload verify    │                   │
│                    └────────────────────────────┘                   │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📦 Модули

### 1. Core Interceptor (`apex_interceptor.py`)
- Перехват всех XHR/Fetch запросов
- Приоритизация по sensitivity (critical/high/medium/low)
- Извлечение JWT, cookies, параметров
- Очередь для fuzzing

### 2. Deep Recon (`apex_recon.py`)
- Парсинг JS бандлов regex'ами
- Поиск скрытых API endpoints
- Извлечение секретов (API keys, tokens)
- Анализ закомментированного кода
- Построение API map

### 3. Multi-Vector Fuzzer (`apex_fuzzer.py`)
- **SQL Injection**: Auth bypass, error-based, union-based
- **NoSQL Injection**: MongoDB operators, JSON injection
- **XSS**: DOM-based, reflected, Angular/React SSTI
- **IDOR/BOLA**: ID substitution, parameter manipulation
- **SSRF**: Internal IPs, protocol-based, AWS metadata
- **Auth Bypass**: Rate limit checks, polyglot payloads

### 4. Vulnerability Engine (`apex_engine.py`)
- **Response Diffing**: Сравнение baseline vs test
- **Multi-payload Verification**: Подтверждение разными пейлоадами
- **Browser Verification**: Проверка выполнения в браузере
- **False Positive Detection**: WAF/CDN detection, error pages
- **Confidence Scoring**: 0.0 - 1.0

### 5. Auto-Crawler (`apex_crawler.py`)
- Автоматический клик всех кнопок
- Заполнение форм тестовыми данными
- Trigger hover states для скрытых меню
- Переход по внутренним ссылкам
- Мониторинг network activity

### 6. Main Orchestrator (`apex_scanner.py`)
- Координация всех модулей
- Управление браузером
- Агрегация результатов

---

## ⚡ Быстрый старт

### 1. Запуск через API

```python
from apex_scanner import run_apex_scan
import asyncio

result = asyncio.run(run_apex_scan(
    target_url="http://localhost:3000",
    headless=True,
    max_depth=3,
    enable_recon=True,
    enable_fuzzing=True,
    enable_verification=True
))

print(f"Vulnerabilities: {result['vulnerabilities_count']}")
```

### 2. Прямой запуск

```bash
cd /Users/p1ko/dast-tool/backend
source /Users/p1ko/Downloads/tools/venv/bin/activate

python apex_scanner.py http://localhost:3000
```

### 3. Через FastAPI backend

```bash
curl -X POST http://localhost:8000/api/v1/startdast \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://localhost:3000",
    "mode": "apex",
    "headless_browser": true,
    "max_depth": 3
  }'
```

---

## 🔬 API

### ApexScanner Class

```python
scanner = ApexScanner(
    target_url="http://localhost:3000",
    headless=True,          # Headless браузер
    max_depth=3,            # Макс. глубина crawler
    max_pages=50,           # Макс. страниц
    timeout=300000,         # Таймаут сканирования
    enable_recon=True,      # Включить recon
    enable_fuzzing=True,    # Включить fuzzing
    enable_verification=True,  # Включить verification
    max_concurrency=5       # Параллельных запросов
)

async with scanner:
    result = await scanner.scan()
    print(result.vulnerabilities)
```

### Vulnerability Format

```json
{
  "id": "vuln_1677234567890_1234",
  "type": "sql_injection",
  "severity": "critical",
  "url": "http://localhost:3000/rest/user/login",
  "parameter": "email",
  "payload": "' OR 1=1--",
  "evidence": "SQL error pattern detected: MySQL syntax",
  "confidence": 0.95,
  "verification_status": "verified",
  "cwe_id": ["CWE-89"],
  "verification_steps": [
    {"step": "false_positive_check", "passed": true},
    {"step": "response_diff", "score": 0.9},
    {"step": "multi_payload_verification", "success_rate": 0.8},
    {"step": "browser_verification", "result": true}
  ]
}
```

---

## 📊 Примеры использования

### Пример 1: Базовое сканирование

```python
import asyncio
from apex_scanner import ApexScanner

async def basic_scan():
    async with ApexScanner(
        target_url="http://localhost:3000",
        headless=True
    ) as scanner:
        result = await scanner.scan()
        
        print(f"Found {len(result.vulnerabilities)} vulnerabilities")
        
        for vuln in result.vulnerabilities:
            print(f"- {vuln['type']}: {vuln['severity']} at {vuln['url']}")

asyncio.run(basic_scan())
```

### Пример 2: Только Recon

```python
async def recon_only():
    async with ApexScanner(
        target_url="http://example.com",
        enable_fuzzing=False,
        enable_verification=False
    ) as scanner:
        result = await scanner.scan()
        
        print(f"Discovered {len(result.endpoints_discovered)} endpoints")
        print(f"Found {len(result.secrets_found)} secrets")

asyncio.run(recon_only())
```

### Пример 3: Кастомный фаззинг

```python
from apex_fuzzer import MultiVectorFuzzer, VulnerabilityType

async def custom_fuzz():
    fuzzer = MultiVectorFuzzer(page=page, http_client=http_client)
    
    # fuzz конкретный endpoint
    request_data = {
        'url': 'http://example.com/api/users',
        'method': 'POST',
        'headers': {'Authorization': 'Bearer token'},
        'body_json': {'id': 123}
    }
    
    vulns = await fuzzer.fuzz_endpoint(request_data)
    
    for vuln in vulns:
        print(f"Found: {vuln.type} - {vuln.evidence}")

asyncio.run(custom_fuzz())
```

---

## 📈 Результаты сканирования

### Scan Result Object

```python
{
  "scan_id": "apex_1677234567",
  "target_url": "http://localhost:3000",
  "status": "completed",
  "duration_seconds": 145.3,
  "endpoints_discovered": 47,
  "vulnerabilities_count": 12,
  "vulnerabilities_by_severity": {
    "critical": 3,
    "high": 5,
    "medium": 3,
    "low": 1,
    "info": 0
  },
  "secrets_found": 2,
  "statistics": {
    "interceptor": {
      "total_requests": 156,
      "critical_requests": 12,
      "queued_for_fuzzing": 48
    },
    "recon": {
      "js_files_analyzed": 8,
      "endpoints_found": 23,
      "secrets_found": 2
    },
    "fuzzer": {
      "requests_made": 342,
      "vulnerabilities_found": 18
    },
    "verification": {
      "total_candidates": 18,
      "verified": 8,
      "false_positives": 10,
      "verification_rate": 0.44
    }
  }
}
```

---

## 🎯 Поддерживаемые уязвимости

| Тип | Методы обнаружения | Confirmation |
|-----|-------------------|--------------|
| **SQL Injection** | Error patterns, Auth bypass, Time-based | Multi-payload, Browser |
| **NoSQL Injection** | Operator injection, JSON manipulation | Response diff |
| **XSS** | DOM injection, Console monitoring, Reflection | Browser execution |
| **IDOR/BOLA** | ID substitution, Response comparison | Access verification |
| **SSRF** | Internal IP detection, Protocol tests | Timeout analysis |
| **Auth Bypass** | Token manipulation, Polyglot payloads | Session validation |

---

## ⚙️ Конфигурация

### Переменные окружения

```bash
# Browser settings
APEX_HEADLESS=true
APEX_BROWSER_TIMEOUT=30000

# Fuzzing settings
APEX_MAX_CONCURRENCY=5
APEX_FUZZ_TIMEOUT=30000

# OAST server (for SSRF)
APEX_OAST_SERVER=http://interact.sh

# Verification thresholds
APEX_VERIFICATION_THRESHOLD=0.75
```

---

## 🚨 Troubleshooting

### Browser не запускается
```bash
playwright install chromium
playwright install-deps chromium  # Для Linux
```

### Мало endpoints найдено
- Увеличьте `max_depth` до 5
- Включите `enable_recon=True`
- Проверьте что JS загружается

### Много false positives
- Включите `enable_verification=True`
- Увеличьте `CONFIDENCE_THRESHOLDS`
- Проверьте логи verification

---

## 📝 Changelog

### v1.0.0 - Initial Release
- ✅ Action-Interception-Mutation Architecture
- ✅ Deep JS bundle parsing
- ✅ Multi-vector fuzzing (6 types)
- ✅ Zero False Positive verification
- ✅ Auto-crawler for SPA

---

## 📚 Документация

- `apex_interceptor.py` - Request interception
- `apex_recon.py` - Deep reconnaissance
- `apex_fuzzer.py` - Multi-vector fuzzing
- `apex_engine.py` - Vulnerability verification
- `apex_crawler.py` - Auto-crawler
- `apex_scanner.py` - Main orchestrator

---

**ApexScanner** - Professional Red Team Tool  
Built with ❤️ for Bug Bounty Hunters
