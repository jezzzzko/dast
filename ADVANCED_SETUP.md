# 🔥 DAST Scanner v3.0 - Advanced Setup

## 📋 Новые возможности

### Режимы сканирования:

| Режим | Инструменты | Время | Описание |
|-------|-------------|-------|----------|
| **⚡ Быстрый** | Nuclei | 1-2 мин | Базовые уязвимости по шаблонам |
| **🔍 Полный** | Nuclei + ZAP | 10-15 мин | Обход сайта + активное сканирование |
| **🚀 Advanced** | Nuclei + ZAP + Gobuster + SQLMap | 20-30 мин | Максимальное покрытие всеми инструментами |
| **🦇 Burp Pro** | Burp Suite Professional | 15-30 мин | Полное сканирование Burp Scanner |

---

## 🛠 Установка дополнительных инструментов

### 1. SQLMap (SQL Injection)

```bash
# macOS
brew install sqlmap

# Linux
sudo apt install sqlmap

# Проверка
sqlmap --version
```

### 2. Gobuster (Directory Bruteforce)

```bash
# macOS
brew install gobuster

# Linux
sudo apt install gobuster

# Проверка
gobuster version
```

### 3. Wordlists для Gobuster

```bash
# Kali/Parrot
/usr/share/wordlists/dirb/common.txt

# Или установить отдельно
git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists
```

---

## 🦇 Настройка Burp Suite Professional API

### Шаг 1: Включить REST API в Burp Suite

1. Открой **Burp Suite Professional**
2. Перейди в **Settings** → **Network** → **REST API**
3. Включи **"Listen on interface"**
4. Укажи:
   - **Interface:** `127.0.0.1`
   - **Port:** `1337` (или любой другой)
5. Включи **"Use custom TLS certificate"** (опционально)
6. Скопируй **API Key** (понадобится для сканирования)

### Шаг 2: Настроить CORS (если нужно)

В Burp Suite:
- **Settings** → **Network** → **REST API**
- Добавь `http://127.0.0.1:8000` в разрешённые origins

### Шаг 3: Проверить подключение

```bash
curl -X GET "http://127.0.0.1:1337/v0.1/version" \
  -H "Authorization: Bearer YOUR_API_KEY"
```

Должен вернуть версию Burp Suite.

---

## 🚀 Запуск Advanced сканирования

### Через веб-интерфейс:

1. Открой http://127.0.0.1:5173
2. Введи URL цели (например, http://127.0.0.1:3000)
3. Выбери режим:
   - **🚀 Advanced** - для максимального покрытия
   - **🦇 Burp Pro** - для сканирования Burp Scanner
4. Для Burp Pro вставь API key
5. Нажми **"Сканировать"**

### Через CLI:

```bash
# Быстрое сканирование
python3 advanced_scanner.py -u http://target.com -m quick

# Полное сканирование
python3 advanced_scanner.py -u http://target.com -m full

# Advanced (все инструменты)
python3 advanced_scanner.py -u http://target.com -m advanced

# Burp Suite
python3 advanced_scanner.py -u http://target.com -m burp
```

---

## 📊 Результаты сканирования

### Где искать отчёты:

```bash
# JSON результаты
/tmp/dast_scans/combined_YYYYMMDD_HHMMSS.json

# HTML отчёт
/tmp/dast_scans/report_YYYYMMDD_HHMMSS.html

# Nuclei результаты
/tmp/dast_scans/nuclei_YYYYMMDD_HHMMSS.json

# ZAP результаты
/tmp/dast_scans/zap_YYYYMMDD_HHMMSS.json

# Gobuster результаты
/tmp/dast_scans/gobuster_YYYYMMDD_HHMMSS.txt
```

### HTML отчёт включает:

- 📊 Сводка по severity (Critical/High/Medium/Low/Info)
- 📋 Полный список уязвимостей
- 🔗 Ссылки на CWE/CVSS
- 🛠 Рекомендации по исправлению

---

## 🔧 Настройка производительности

### advanced_scanner.py параметры:

```python
# Nuclei настройки
"-rate-limit", "150",      # Запросов в секунду
"-bulk-size", "25",        # Пакетный размер
"-concurrency", "50"       # Параллельных потоков

# ZAP настройки
"-config", "spider.maxDuration=30",      # Spider таймаут
"-config", "ajaxSpider.maxDuration=30"   # AJAX Spider таймаут

# SQLMap настройки
"--level", "3",           # Глубина тестирования (1-5)
"--risk", "2"             # Риск (1-3)
```

### Для быстрых результатов:

```python
# Уменьшить таймауты
"-timeout", "5"           # Вместо 15
"--risk", "1"             # Вместо 2

# Увеличить скорость
"-rate-limit", "300"      # Вместо 150
"-concurrency", "100"     # Вместо 50
```

### Для тихого сканирования:

```python
# Меньше шума
"-rate-limit", "50"       # Вместо 150
"--delay", "1"            # Задержка между запросами
```

---

## 🎯 Интеграция с Burp Suite

### Автоматизация через REST API:

```python
# Создать сканирование
POST /v0.1/scan
{
  "urls": ["http://target.com"],
  "scan_configurations": [
    {"type": "audit_config", "name": "Hardened"}
  ]
}

# Получить статус
GET /v0.1/scan/{scan_id}

# Получить уязвимости
GET /v0.1/scan/{scan_id}/issues
```

### Burp Scanner конфигурации:

| Название | Описание |
|----------|----------|
| **Default** | Стандартное сканирование |
| **Hardened** | Агрессивное сканирование |
| **Fast** | Быстрое сканирование |
| **Complete** | Полное сканирование |

---

## 📈 Сравнение режимов

### Quick (Nuclei only)

```
✅ Быстро (1-2 мин)
✅ Мало ложных срабатываний
❌ Только шаблонные уязвимости
❌ Нет обхода сайта

Находит: ~5-10 уязвимостей
```

### Full (Nuclei + ZAP)

```
✅ Обход сайта (Spider)
✅ AJAX Spider для JS
✅ Active Scan атаки
✅ Больше уязвимостей

Находит: ~20-30 уязвимостей
```

### Advanced (All Tools)

```
✅ Всё из Full режима
✅ Gobuster (скрытые директории)
✅ SQLMap (SQL инъекции)
✅ Максимальное покрытие

Находит: ~30-50+ уязвимостей
```

### Burp Pro

```
✅ Burp Scanner (профессиональный)
✅ Business logic уязвимости
✅ Минимум ложных срабатываний
✅ Детальные отчёты

Находит: ~25-40 уязвимостей
```

---

## 🎨 Примеры использования

### Тестирование Juice Shop:

```bash
# 1. Быстрое сканирование
python3 advanced_scanner.py -u http://127.0.0.1:3000 -m quick

# 2. Полное сканирование
python3 advanced_scanner.py -u http://127.0.0.1:3000 -m full

# 3. Advanced с SQLMap
python3 advanced_scanner.py -u http://127.0.0.1:3000 -m advanced

# 4. Burp Suite (если есть API key)
python3 advanced_scanner.py -u http://127.0.0.1:3000 -m burp
```

### Тестирование API:

```bash
# Только Nuclei API шаблоны
nuclei -u http://api.target.com -t http/exposures/apis/ -je api_results.json

# + ZAP
python3 advanced_scanner.py -u http://api.target.com -m full
```

### Тестирование с аутентификацией:

```bash
# С cookies
nuclei -u http://target.com -header "Cookie: session=abc123" -je auth_results.json

# С токеном
nuclei -u http://target.com -header "Authorization: Bearer TOKEN" -je auth_results.json
```

---

## 🛠 Troubleshooting

### SQLMap не работает:

```bash
# Проверить установку
which sqlmap

# Обновить
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap
export PATH="/opt/sqlmap:$PATH"
```

### Gobuster не находит ничего:

```bash
# Проверить wordlist
ls -la /usr/share/wordlists/dirb/common.txt

# Использовать другой wordlist
gobuster dir -u http://target.com -w /path/to/your/wordlist.txt
```

### Burp API не подключается:

```bash
# Проверить порт
lsof -i :1337

# Проверить API key
curl -X GET "http://127.0.0.1:1337/v0.1/version" \
  -H "Authorization: Bearer YOUR_KEY"
```

### ZAP не запускается:

```bash
# Проверить установку
ls -la /Applications/ZAP.app

# Запустить вручную
/Applications/ZAP.app/Contents/Java/zap.sh -daemon -port 8090
```

---

## 📚 Дополнительные ресурсы

- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [OWASP ZAP API](https://www.zaproxy.org/docs/api/)
- [Burp Suite REST API](https://portswigger.net/burp/documentation/rest-api)
- [SQLMap Documentation](http://sqlmap.org/)
- [Gobuster Wiki](https://github.com/OJ/gobuster/wiki)

---

*DAST Scanner v3.0 - Maximum Power!* 🚀
