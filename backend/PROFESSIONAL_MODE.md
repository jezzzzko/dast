# DAST Scanner - Professional Red Team Edition

## Overview

This is a major upgrade to the DAST scanner backend, transforming it into a **Professional Red Team Tool** with advanced capabilities for modern web application security testing.

## Key Features

### 1. Playwright-Based Dynamic Engine
- **Headless Browser Automation**: Full Chromium browser control for SPA testing
- **JavaScript Rendering**: Waits for Angular/React/Vue apps to fully render
- **Network Interception**: Captures XHR/Fetch requests to discover hidden API endpoints
- **DOM Analysis**: Analyzes DOM structure for vulnerability detection
- **Session Extraction**: Automatically extracts JWT tokens from cookies and localStorage

### 2. Intelligent XSS Validation (Zero False Positives)
- **Execution Confirmation**: Doesn't just look for payload reflection - confirms actual JavaScript execution
- **Window Object Checks**: Sets unique markers in `window` object to verify code ran
- **Angular SSTI Detection**: Specialized tests for Angular template injection
- **Multiple Contexts**: Tests HTML, attribute, JavaScript, and URL contexts
- **False Positive Scoring**: Each finding includes a confidence score

### 3. Advanced SQL Injection Detection
- **Error-Based**: Detects SQL error messages from all major databases
- **Boolean-Based**: Statistical analysis of response differences
- **Time-Based**: Multi-sample timing analysis with z-score calculation
- **UNION-Based**: Automatic column count detection and data extraction tests
- **DOM Structure Analysis**: Compares DOM changes between test requests

### 4. BOLA/IDOR Testing (Multi-Session)
- **Dual Authentication**: Simultaneously maintains User A and User B sessions
- **Token Swapping**: Tests if auth tokens can be exchanged between users
- **ID Substitution**: Automatic testing of resource ID manipulation
- **Parameter Manipulation**: Tests all common IDOR parameter names
- **Mass Assignment**: Detects parameter pollution vulnerabilities
- **Severity Assessment**: Automatic severity based on exposed data type

### 5. Context-Aware Payload Generation
- **Smart Context Detection**: Analyzes Content-Type, parameter types, and semantics
- **Adaptive Payloads**: Selects appropriate payloads based on context:
  - URL parameters → URL-encoded payloads
  - JSON body → JSON-formatted payloads
  - Headers → Header-specific injections
  - Numeric params → Numeric SQLi payloads
- **Semantic Analysis**: Recognizes email, UUID, date, IP parameters for targeted testing

### 6. Session Management
- **Automatic Token Refresh**: Detects expiring JWTs and refreshes before scan interruption
- **Multi-User Sessions**: Maintains multiple authenticated sessions for BOLA testing
- **Cookie Management**: Automatic cookie synchronization across requests
- **Session Recovery**: Handles session termination gracefully

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         FastAPI Backend                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────┐ │
│  │ PlaywrightEngine │  │ SessionManager   │  │ PayloadGen    │ │
│  │ - Browser ctrl   │  │ - JWT refresh    │  │ - Context ana │ │
│  │ - XHR intercept  │  │ - Multi-user     │  │ - Smart select│ │
│  │ - DOM analysis   │  │ - Auto recovery  │  │ - Encoding    │ │
│  └────────┬─────────┘  └────────┬─────────┘  └───────┬───────┘ │
│           │                      │                    │         │
│  ┌────────▼──────────────────────▼────────────────────▼───────┐ │
│  │              Vulnerability Detectors                        │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐    │ │
│  │  │ XSSValidator│  │AdvSQLiDetect│  │ BOLA/IDORTester │    │ │
│  │  │ - Exec check│  │ - Time-based│  │ - Dual session  │    │ │
│  │  │ - FP elimin │  │ - Boolean   │  │ - Token swap    │    │ │
│  │  │ - Angular   │  │ - UNION     │  │ - Mass assign   │    │ │
│  │  └─────────────┘  └─────────────┘  └─────────────────┘    │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                      SQLite Database                             │
│  - Scans | ScanSessions | ScanLogs | Endpoints | Statistics    │
└─────────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites
- Python 3.9+
- Node.js 16+ (for some external tools)

### Setup

1. **Install Python dependencies**:
```bash
cd backend
pip install -r requirements.txt
playwright install chromium
```

2. **Verify installation**:
```bash
python -c "from playwright.async_api import async_playwright; print('Playwright OK')"
```

## Usage

### Starting an Advanced Scan

```bash
curl -X POST http://localhost:8000/api/v1/startdast \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://localhost:3000",
    "mode": "advanced",
    "crawl_enabled": true,
    "headless_browser": true,
    "max_depth": 3,
    "credentials_a": {
      "email": "user@juice-sh.op",
      "password": "user123",
      "role": "user"
    },
    "credentials_b": {
      "email": "admin@juice-sh.op", 
      "password": "admin123",
      "role": "admin"
    }
  }'
```

### Scan Modes

| Mode | Description |
|------|-------------|
| `full` | Complete scan with all detectors |
| `advanced` | Advanced scan (Playwright + all modules) |
| `xss` | XSS validation with execution confirmation |
| `sqli` | Advanced SQL injection detection |
| `bola` | BOLA/IDOR testing (requires credentials) |
| `recon` | Bug bounty reconnaissance (legacy) |
| `exploit` | Autonomous exploitation (legacy) |
| `rce` | RCE exploitation (legacy) |

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/startdast` | POST | Start new scan |
| `/api/v1/scan/{id}` | GET | Get scan results |
| `/api/v1/scans` | GET | List all scans |
| `/api/v1/scan/{id}/endpoints` | GET | Get discovered endpoints |
| `/api/v1/scan/{id}/sessions` | GET | Get BOLA test sessions |
| `/api/v1/logs` | GET | Get scan logs |

## Module Details

### PlaywrightEngine (`playwright_engine.py`)

```python
from playwright_engine import PlaywrightEngine

async with PlaywrightEngine(headless=True) as engine:
    # Navigate and wait for JS rendering
    await engine.navigate("http://target.com")
    
    # Crawl application
    endpoints = await engine.crawl(max_depth=3)
    
    # Extract JWT tokens
    tokens = await engine.extract_jwt_tokens()
    
    # Execute custom JavaScript
    result = await engine.execute_script("document.title")
```

### SessionManager (`session_manager.py`)

```python
from session_manager import SessionManager, UserCredentials

manager = SessionManager("http://target.com")

# Authenticate two users for BOLA testing
session_a, session_b = await manager.authenticate_user_a_and_b(
    UserCredentials(email="user@test.com", password="pass1"),
    UserCredentials(email="admin@test.com", password="pass2")
)

# Test for BOLA vulnerability
result = await manager.test_bola(
    "http://target.com/api/orders/123",
    session_a.session_id,
    session_b.session_id
)

if result['vulnerable']:
    print("BOLA detected!")
```

### XSSValidator (`xss_validator.py`)

```python
from xss_validator import XSSValidator, XSSScanner

validator = XSSValidator(page=playwright_page)

# Test specific parameter
findings = await validator.validate_xss(
    url="http://target.com/search",
    parameter="q",
    method="GET"
)

# Each finding includes execution confirmation
for finding in findings:
    print(f"XSS Type: {finding.vulnerability_type}")
    print(f"Execution Confirmed: {finding.execution_method}")
    print(f"False Positive Score: {finding.false_positive_score}")
```

### AdvancedSQLiDetector (`advanced_sqli.py`)

```python
from advanced_sqli import AdvancedSQLiDetector

detector = AdvancedSQLiDetector(page=playwright_page)

# Comprehensive SQLi detection
findings = await detector.detect_sqli(
    url="http://target.com/products",
    parameter="id",
    method="GET"
)

for finding in findings:
    print(f"SQLi Type: {finding.vulnerability_type}")
    print(f"Database: {finding.database_type}")
    print(f"Confidence: {finding.confidence}")
```

### BOLATester (`bola_tester.py`)

```python
from bola_tester import BOLATester, EndpointInfo

tester = BOLATester(
    session_a_headers=headers_a,
    session_b_headers=headers_b,
    session_a_info=user_a_info,
    session_b_info=user_b_info
)

# Test endpoint for BOLA
endpoint = EndpointInfo(
    url="http://target.com/api/users/123",
    method="GET",
    parameters={},
    auth_required=True,
    id_parameter="id"
)

findings = tester.test_endpoint(endpoint)
```

### PayloadGenerator (`payload_generator.py`)

```python
from payload_generator import get_payload_generator, VulnerabilityClass, PayloadContext

generator = get_payload_generator()

# Get SQLi payloads for JSON context
payloads = generator.get_payloads(
    VulnerabilityClass.SQL_INJECTION,
    PayloadContext.JSON_BODY
)

# Analyze request and generate targeted payloads
injection_points = generator.analyzer.detect_injection_points(
    url="http://target.com/api/users?id=123",
    method="GET",
    headers={"Content-Type": "application/json"},
    body=None
)
```

## Database Schema

### Tables

- **scans**: Main scan results and findings
- **scan_sessions**: Multi-user session data for BOLA testing
- **scan_logs**: Detailed execution logs
- **discovered_endpoints**: API endpoints found during crawling
- **scan_statistics**: Performance and metrics data

## Migration from Legacy Scans

The new backend maintains **full backward compatibility**:

1. All legacy scan modes continue to work
2. Existing API endpoints unchanged
3. Frontend integration requires no modifications
4. Legacy scanners (JuiceShopScanner, RealSQLiDetector, etc.) still available

## Performance Considerations

- **Browser Overhead**: Playwright adds ~2-5s per page load
- **Memory Usage**: Headless browser uses ~200-500MB RAM
- **Concurrent Scans**: Limit to 2-3 concurrent advanced scans
- **Crawl Depth**: max_depth=3 recommended for most apps

## Troubleshooting

### Playwright Installation Issues
```bash
# Reinstall browsers
playwright install chromium --force

# For Linux servers
playwright install-deps chromium
```

### Session Authentication Fails
- Verify credentials are correct
- Check if login endpoint path is correct
- Ensure target accepts automated traffic

### False Negatives in XSS
- Increase timeout for slow apps
- Try different XSS payload sets
- Check if CSP is blocking execution

## Security Notes

⚠️ **This tool is for authorized security testing only**

- Always obtain written permission before scanning
- Do not use on production systems without proper safeguards
- Respect rate limits to avoid DoS
- Store scan results securely (they contain sensitive data)

## License

Same as the original DAST scanner project.

## Authors

Professional Red Team Tool upgrade implemented with:
- Playwright dynamic engine
- Execution-validated XSS detection
- Statistical SQLi analysis
- Multi-session BOLA testing
- Context-aware payload generation
