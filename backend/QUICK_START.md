# 🚀 Quick Start - Juice Shop SQLi Detection

## Запуск сканера

### 1. Запустите Juice Shop (цель)

**Docker (рекомендуется):**
```bash
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
```

**Или локально:**
```bash
cd /path/to/juice-shop
npm start
```

Проверка:
```bash
curl http://localhost:3000
# Должен вернуть HTML страницу
```

---

### 2. Запустите DAST Scanner Backend

```bash
cd /Users/p1ko/dast-tool/backend
source /Users/p1ko/Downloads/tools/venv/bin/activate
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Проверка:
```bash
curl http://localhost:8000/health
# {"status":"healthy","version":"2.0.0"}
```

---

### 3. Запустите Frontend (опционально)

```bash
cd /Users/p1ko/dast-tool/frontend
npm run dev
```

Откройте: http://127.0.0.1:5173

---

### 4. Запустите сканирование

**Через API:**
```bash
curl -X POST http://localhost:8000/api/v1/startdast \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://localhost:3000",
    "mode": "full",
    "crawl_enabled": true,
    "headless_browser": true,
    "max_depth": 2
  }'
```

Ответ:
```json
{
  "id": 1,
  "status": "started",
  "mode": "full",
  "target": "http://localhost:3000"
}
```

---

### 5. Проверьте результаты

```bash
# Получить результаты
curl http://localhost:8000/api/v1/scan/1 | python3 -m json.tool

# Получить логи
curl "http://localhost:8000/api/v1/logs?scan_id=1" | python3 -m json.tool
```

---

## Тестовый запуск детектора

**Прямой тест (без API):**
```bash
cd /Users/p1ko/dast-tool/backend
source /Users/p1ko/Downloads/tools/venv/bin/activate
python test_login_sqli.py http://localhost:3000
```

---

## Ожидаемые находки

Для OWASP Juice Shop сканер найдёт:

### 🔴 Critical: Authentication Bypass

```json
{
  "template-id": "auth-bypass-sql_injection",
  "info": {
    "name": "Authentication Bypass via SQL Injection",
    "severity": "critical",
    "cwe-id": ["CWE-287", "CWE-89"]
  },
  "payload": "{\"email\": \"' OR 1=1--\", \"password\": \"anything\"}",
  "jwt_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "evidence": "SQL Injection in login form bypassed authentication"
}
```

---

## Режимы сканирования

| Mode | Описание |
|------|----------|
| `full` | Полное сканирование (все модули) |
| `advanced` | Playwright + все детекторы |
| `sqli` | Только SQL injection |
| `auth_bypass` | Только обход аутентификации |
| `xss` | Только XSS |
| `bola` | BOLA/IDOR тестирование |

---

## Troubleshooting

### ❌ "Cannot connect to target"
```bash
# Проверьте что Juice Shop запущен
curl http://localhost:3000

# Если не работает - запустите
docker start juice-shop
```

### ❌ "Playwright not installed"
```bash
source /Users/p1ko/Downloads/tools/venv/bin/activate
playwright install chromium
```

### ❌ "Module import error"
```bash
# Проверьте синтаксис
cd /Users/p1ko/dast-tool/backend
python -m py_compile juice_login_sqli.py
python -m py_compile main.py
```

### ❌ Сканер не находит уязвимость

Возможные причины:
1. Juice Shop уже patched (обновите версию)
2. Таймаут слишком маленький (увеличьте `timeout`)
3. Браузер заблокирован (попробуйте `headless_browser: false`)

---

## Структура файлов

```
backend/
├── juice_login_sqli.py       # Новый детектор login SQLi
├── advanced_sqli.py          # Обновлён с JSON поддержкой
├── main.py                   # Интеграция детектора
├── playwright_engine.py      # Browser automation
├── test_login_sqli.py        # Тестовый скрипт
├── SQLI_UPDATE.md            # Документация
└── QUICK_START.md            # Этот файл
```

---

## Следующие шаги

1. ✅ Протестируйте на Juice Shop
2. ✅ Проверьте результаты в API
3. ✅ Настройте под свои нужды
4. ✅ Добавьте поддержку других приложений

---

## Поддержка

Документация:
- `SQLI_UPDATE.md` - Подробное описание изменений
- `PROFESSIONAL_MODE.md` - Общая документация бэкенда
- `README.md` - Основной README проекта

Контакты:
- GitHub Issues
- OWASP Slack Channel
