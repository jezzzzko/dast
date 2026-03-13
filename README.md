# 🚀 DAST Scanner v3.0 - Recon + Auto-Exploitation

## 🔥 Что нового в v3.0

### ✅ Всё в одном режиме - **RECON**

Больше не нужно выбирать между SQLi, XSS, LFI, CORS - **всё в одном сканировании!**

---

## 📥 Установка

### Windows
См. подробную инструкцию: [WINDOWS_INSTALL.md](WINDOWS_INSTALL.md)

**Быстрый запуск (Windows PowerShell):**
```powershell
# Разрешить выполнение скриптов
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Запустить DAST Scanner
.\run.ps1
```

### macOS / Linux
```bash
# Backend
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install
python main.py

# Frontend (в новом терминале)
cd frontend
npm install
npm run dev
```

---

## 📋 3 Режима сканирования

| Режим | Время | Что делает |
|-------|-------|------------|
| **⚡ Быстрый** | 1-2 мин | Nuclei шаблоны (~1000+) |
| **🛡️ Полный** | 10-15 мин | Nuclei + OWASP ZAP (Spider + Active Scan) |
| **🔍 Recon** | 10-15 мин | **Разведка + Авто-эксплуатация** |

---

## 🔍 Recon - Полная разведка + Авто-эксплуатация

### Этап 1: Разведка

```
┌─────────────────────────────────────────────────────────┐
│                    RECON SCANNING                       │
├─────────────────────────────────────────────────────────┤
│  1. subfinder    → Поиск поддоменов (30+ источников)    │
│  2. dnsx         → DNS разведка (A, CNAME, MX, NS, TXT) │
│  3. httpx        → Живые хосты + технологии             │
│  4. naabu        → Сканирование портов (топ-1000)       │
│  5. gobuster     → Поиск директорий и файлов            │
│  6. katana       → Crawler (обход сайта, глубина 3)     │
│  7. gau          → URL из архивов (AlienVault)          │
│  8. waybackurls  → URL из Wayback Machine               │
└─────────────────────────────────────────────────────────┘
```

### Этап 2: Авто-Эксплуатация

```
┌─────────────────────────────────────────────────────────┐
│               POST-RECON AUTO-EXPLOITATION              │
├─────────────────────────────────────────────────────────┤
│  1. nuclei       → Проверка поддоменов на уязвимости    │
│  2. Directory    → Анализ директорий на чувствительные  │
│                    данные (backup, .git, .env, admin)   │
│  3. Ports        → Проверка опасных портов (Redis,      │
│                    MongoDB, SMB, RDP, Telnet)           │
│  4. SQLi         → SQLMap (10 URL с параметрами)        │
│  5. XSS          → Dalfox (проверка параметров)         │
│  6. LFI          → Проверка на Local File Inclusion     │
│  7. CORS         → CORS Misconfiguration                │
└─────────────────────────────────────────────────────────┘
```

---

## 🎯 Что находит Recon

### Subdomains (subfinder)
```
├─ example.com
├─ api.example.com
├─ admin.example.com
├─ dev.example.com
└─ staging.example.com
```

### Dangerous Ports (naabu)
```
├─ 6379  → Redis (CRITICAL - potential RCE)
├─ 27017 → MongoDB (CRITICAL - data leak)
├─ 445   → SMB (CRITICAL - potential exploit)
├─ 23    → Telnet (CRITICAL - unencrypted)
├─ 3389  → RDP (HIGH - brute force)
└─ 3306  → MySQL (HIGH - data leak)
```

### Sensitive Directories (gobuster)
```
├─ /backup      → HIGH   (Backup files)
├─ /.git        → CRITICAL (Source code)
├─ /admin       → MEDIUM (Admin panel)
├─ /config      → HIGH   (Config files)
├─ /.env        → CRITICAL (Environment secrets)
└─ /api         → MEDIUM (API endpoints)
```

### SQL Injection (sqlmap)
```
├─ /search?q='   → UNION-based SQLi
├─ /user?id=1    → Boolean-based SQLi
└─ /product/     → Error-based SQLi
```

### XSS (dalfox)
```
├─ /search?q=<script>  → Reflected XSS
├─ /profile?name=      → Stored XSS
└─ /redirect?url=      → DOM XSS
```

### LFI (Local File Inclusion)
```
├─ /etc/passwd exposure
├─ Proc self environ
└─ Directory traversal
```

### CORS Misconfiguration
```
├─ Access-Control-Allow-Origin: *
└─ Credentials with wildcard origin
```

---

## 🚀 Запуск

### Через UI
1. Открой http://127.0.0.1:5173
2. Введи URL цели
3. Выбери режим **🔍 Recon**
4. Нажми **Сканировать**

### Через API
```bash
# Запустить Recon
curl -X POST http://127.0.0.1:8000/api/v1/startdast \
  -H "Content-Type: application/json" \
  -d '{"target": "http://example.com", "mode": "recon"}'

# Получить результаты
curl http://127.0.0.1:8000/api/v1/scan/{scan_id}
```

---

## 📊 Пример результата

```json
{
  "id": 1,
  "target_url": "http://example.com",
  "status": "completed",
  "findings": [
    {
      "template-id": "recon-summary",
      "info": {
        "name": "📊 RECON SUMMARY",
        "description": "Subdomains: 15 | Live Hosts: 12 | Ports: 8 | Directories: 25 | URLs: 150 | Post-Recon Vulns: 12",
        "severity": "info"
      }
    },
    {
      "template-id": "open-port-6379",
      "info": {
        "name": "Dangerous Port: 6379/tcp",
        "description": "Redis port open - potential RCE",
        "severity": "critical",
        "solution": "Close or protect port 6379"
      }
    },
    {
      "template-id": "sensitive-dir-git",
      "info": {
        "name": "Sensitive Directory: /.git",
        "description": "Git repository exposed",
        "severity": "critical",
        "solution": "Remove .git directory"
      }
    },
    {
      "template-id": "cors-misconfiguration",
      "info": {
        "name": "CORS Misconfiguration",
        "description": "Permissive CORS policy",
        "severity": "medium",
        "solution": "Restrict CORS to trusted origins"
      }
    }
  ]
}
```

---

## 🛠 Инструменты

### Recon Tools
- **subfinder** - поддомены (30+ источников)
- **httpx** - живые хосты + технологии
- **naabu** - сканирование портов
- **gobuster** - директории и файлы
- **katana** - crawler сайта
- **gau** - URL из архивов
- **waybackurls** - Wayback Machine
- **dnsx** - DNS разведка

### Exploitation Tools
- **nuclei** - шаблонное сканирование
- **sqlmap** - SQL Injection
- **dalfox** - XSS Scanner
- **ffuf** - Fuzzing

---

## 💡 Советы

### Для Bug Bounty
1. **Recon** → собери всю информацию о цели
2. **Анализируй** → найди критические уязвимости
3. **Углубись** → используй Full для детальной проверки

### Для Pentest
1. **Recon** → полная разведка инфраструктуры
2. **Full** → глубокое сканирование с ZAP
3. **Отчет** → экспортируй результаты

---

## 📝 Changelog

### v3.0.0 - Recon + Auto-Exploit
- ✅ Всё в одном режиме Recon
- ✅ Убраны отдельные режимы (SQLi, XSS, LFI, CORS, RCE)
- ✅ Авто-эксплуатация после разведки
- ✅ LFI detection
- ✅ CORS misconfiguration detection
- ✅ Улучшенный UI - всё на одном экране
- ✅ 3 режима: Quick, Full, Recon

### v2.0.0
- ✅ OWASP ZAP интеграция
- ✅ Spider + Active Scan

### v1.0.0
- ✅ Nuclei integration
- ✅ Базовый веб-интерфейс

---

*DAST Scanner v3.0 - Bug Bounty & Vulnerability Scanner*
