# 🚀 Recon + Auto-Exploitation Guide

## 🔍 Что такое Recon режим?

**Recon (Разведка)** - это автоматизированный сбор информации о цели с последующей **авто-эксплуатацией** найденных уязвимостей.

---

## 📋 Как работает Recon + Auto-Exploit

### Этап 1: Разведка

```
┌─────────────────────────────────────────────────────────┐
│                    RECON SCANNING                       │
├─────────────────────────────────────────────────────────┤
│  1. subfinder    → Поиск поддоменов                     │
│  2. dnsx         → DNS разведка                         │
│  3. httpx        → Проверка живых хостов + технологии   │
│  4. naabu        → Сканирование портов                  │
│  5. gobuster     → Поиск директорий                     │
│  6. katana       → Crawler (обход сайта)                │
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
│                    данные (backup, admin, config, etc.) │
│  3. Ports        → Проверка опасных портов (Redis,      │
│                    MongoDB, SMB, RDP, etc.)             │
│  4. SQLi         → Быстрая проверка URL на SQL Injection│
│  5. XSS          → Проверка параметров на XSS (dalfox)  │
└─────────────────────────────────────────────────────────┘
```

---

## 🎯 Примеры находок

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

---

## 🚀 Запуск Recon сканирования

### Через UI
1. Открой http://127.0.0.1:5173
2. Введи URL цели (например, `http://example.com`)
3. Выбери режим **🔍 Recon**
4. Нажми **Сканировать**

### Через API
```bash
curl -X POST http://127.0.0.1:8000/api/v1/startdast \
  -H "Content-Type: application/json" \
  -d '{"target": "http://example.com", "mode": "recon"}'
```

### Получить результаты
```bash
curl http://127.0.0.1:8000/api/v1/scan/{scan_id}
```

---

## 📊 Интерпретация результатов

### Severity Levels

| Уровень | Цвет | Что означает | Примеры |
|---------|------|--------------|---------|
| **Critical** | 🔴 Красный | Немедленная угроза | RCE, SQLi, exposed DB |
| **High** | 🟠 Оранжевый | Серьезная уязвимость | XSS, Auth Bypass, LFI |
| **Medium** | 🟡 Жёлтый | Средняя опасность | Admin panel, Info disclosure |
| **Low** | 🔵 Синий | Низкий риск | Open ports, Missing headers |
| **Info** | ⚪ Серый | Информационное | Subdomains, Technologies |

### Пример отчета

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
        "description": "Subdomains: 15 | Live Hosts: 12 | Ports: 8 | Directories: 25 | URLs: 150 | Post-Recon Vulns: 5",
        "severity": "info"
      }
    },
    {
      "template-id": "open-port-6379",
      "info": {
        "name": "Dangerous Port: 6379/tcp",
        "description": "Redis port open - potential RCE on 127.0.0.1",
        "severity": "critical",
        "solution": "Close or protect port 6379"
      }
    },
    {
      "template-id": "sensitive-dir-git",
      "info": {
        "name": "Sensitive Directory: /.git",
        "description": "Git repository exposed - http://example.com/.git",
        "severity": "critical",
        "solution": "Remove or protect .git directory"
      }
    }
  ]
}
```

---

## 🔥 Post-Recon Auto-Exploitation

После завершения разведки, система **автоматически** проверяет:

1. **Поддомены** → через Nuclei на известные уязвимости
2. **Директории** → на чувствительные файлы (backup, .git, .env, admin)
3. **Порты** → на опасные сервисы (Redis, MongoDB, SMB, RDP)
4. **URL с параметрами** → на SQL Injection (sqlmap) и XSS (dalfox)

### Время сканирования

| Режим | Время | Что делает |
|-------|-------|------------|
| **Recon только** | 3-5 мин | Сбор информации |
| **Recon + Auto-Exploit** | 10-15 мин | Разведка + эксплуатация |

---

## 💡 Советы по использованию

### Для Bug Bounty

1. **Начни с Recon** - собери всю информацию о цели
2. **Проанализируй результаты** - найди критические уязвимости
3. **Углубись в находки** - используй другие режимы для детальной проверки

### Для Pentest

1. **Recon** → полная разведка инфраструктуры
2. **Full** → глубокое сканирование с ZAP
3. **SQLi/RCE** → targeted эксплуатация

### Для Audit

1. **Quick** → быстрая проверка на известные уязвимости
2. **Recon** → поиск забытых поддоменов и сервисов
3. **Full** → полное сканирование для отчета

---

## 🛠 Доступные инструменты

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

## 📝 Changelog

### v3.0.0 - Recon + Auto-Exploit
- ✅ Добавлен Recon режим со всеми инструментами
- ✅ Автоматическая пост-эксплуатация после recon
- ✅ Проверка поддоменов через nuclei
- ✅ Анализ директорий на чувствительные данные
- ✅ Проверка портов на опасные сервисы
- ✅ Быстрая проверка на SQLi и XSS
- ✅ Новый удобный дизайн frontend
- ✅ 9 режимов сканирования

### v2.0.0
- ✅ OWASP ZAP интеграция
- ✅ Spider + Active Scan

### v1.0.0
- ✅ Nuclei integration
- ✅ Базовый веб-интерфейс

---

*Документация для DAST Scanner v3.0.0*
