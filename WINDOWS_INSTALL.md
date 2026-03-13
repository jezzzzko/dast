# 🚀 DAST Scanner v3.0 - Установка на Windows

Полное руководство по установке и запуску DAST Scanner на Windows 10/11.

---

## 📋 Системные требования

| Компонент | Минимальные | Рекомендуемые |
|-----------|-------------|---------------|
| **ОС** | Windows 10 | Windows 11 |
| **Процессор** | 2 ядра | 4+ ядра |
| **ОЗУ** | 4 GB | 8+ GB |
| **Место на диске** | 5 GB | 10+ GB |
| **Python** | 3.10+ | 3.11+ |
| **Node.js** | 18+ | 20+ |

---

## 📥 Шаг 1: Установка Python

### 1.1 Скачайте Python
1. Перейдите на https://www.python.org/downloads/
2. Скачайте последнюю версию Python 3.11+
3. **ВАЖНО:** При установке отметьте галочку ✅ **"Add Python to PATH"**

### 1.2 Проверка установки
Откройте PowerShell или Command Prompt и выполните:
```powershell
python --version
pip --version
```

Должно отобразиться:
```
Python 3.11.x
pip 24.x
```

---

## 📥 Шаг 2: Установка Node.js

### 2.1 Скачайте Node.js
1. Перейдите на https://nodejs.org/
2. Скачайте **LTS версию** (Long Term Support)
3. Запустите установщик и следуйте инструкциям

### 2.2 Проверка установки
```powershell
node --version
npm --version
```

Должно отобразиться:
```
v20.x.x
10.x.x
```

---

## 📥 Шаг 3: Установка Playwright

Playwright необходим для браузерной автоматизации:

```powershell
pip install playwright
playwright install
```

Это установит браузеры Chromium, Firefox и WebKit.

---

## 📥 Шаг 4: Установка дополнительных инструментов (опционально)

### 4.1 Nuclei (для шаблонного сканирования)
```powershell
# Через Chocolatey (рекомендуется)
choco install nuclei

# Или вручную:
# 1. Скачайте с https://github.com/projectdiscovery/nuclei/releases
# 2. Распакуйте в C:\nuclei
# 3. Добавьте в PATH
```

### 4.2 SQLMap (для SQL Injection тестирования)
```powershell
# Git clone
git clone https://github.com/sqlmapproject/sqlmap.git C:\sqlmap

# Добавьте в системную переменную PATH:
# C:\sqlmap
```

### 4.3 Gobuster (для поиска директорий)
```powershell
# Через Chocolatey
choco install gobuster

# Или скачайте бинарник с:
# https://github.com/OJ/gobuster/releases
```

### 4.4 OWASP ZAP (для полного сканирования)
1. Скачайте с https://www.zaproxy.org/download/
2. Установите в `C:\Program Files\OWASP\ZAP`
3. Запускайте отдельно перед использованием Full режима

---

## 📥 Шаг 5: Клонирование проекта

```powershell
# Перейдите в удобную директорию
cd C:\Users\%USERNAME%\Desktop

# Клонируйте репозиторий
git clone https://github.com/your-username/dast-tool.git

# Перейдите в папку проекта
cd dast-tool
```

---

## 📥 Шаг 6: Настройка Backend

### 6.1 Создание виртуального окружения
```powershell
cd C:\Users\%USERNAME%\Desktop\dast-tool\backend

# Создание venv
python -m venv venv

# Активация
.\venv\Scripts\Activate.ps1
```

> ⚠️ **Если ошибка выполнения скриптов:**
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

### 6.2 Установка зависимостей
```powershell
# Внутри активированного venv
pip install -r requirements.txt

# Установка Playwright браузеров
playwright install
```

---

## 📥 Шаг 7: Настройка Frontend

### 7.1 Установка зависимостей
```powershell
cd C:\Users\%USERNAME%\Desktop\dast-tool\frontend

# Установка npm пакетов
npm install
```

---

## 🚀 Шаг 8: Запуск DAST Scanner

### Терминал 1: Backend
```powershell
cd C:\Users\%USERNAME%\Desktop\dast-tool\backend

# Активация venv
.\venv\Scripts\Activate.ps1

# Запуск сервера
python main.py
```

Должно отобразиться:
```
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     Application startup complete.
```

### Терминал 2: Frontend
```powershell
cd C:\Users\%USERNAME%\Desktop\dast-tool\frontend

# Запуск dev сервера
npm run dev
```

Должно отобразиться:
```
VITE v5.x.x  ready in xxx ms

➜  Local:   http://127.0.0.1:5173/
➜  Network: use --host to expose
```

---

## 🌐 Шаг 9: Использование

### 9.1 Открытие веб-интерфейса
1. Откройте браузер
2. Перейдите на **http://127.0.0.1:5173**
3. Введите URL цели (например, `http://127.0.0.1:3000`)
4. Выберите режим сканирования
5. Нажмите **"Сканировать"**

### 9.2 Доступные режимы

| Режим | Время | Описание |
|-------|-------|----------|
| **⚡ Быстрый** | 1-2 мин | Nuclei шаблоны (~1000+) |
| **🛡️ Полный** | 10-15 мин | Nuclei + OWASP ZAP |
| **🔍 Recon** | 10-15 мин | Разведка + Авто-эксплуатация |

---

## 📊 Шаг 10: Просмотр результатов

### Через веб-интерфейс
- Результаты отображаются в реальном времени
- Можно экспортировать в JSON/HTML

### Через API
```powershell
# Получить список сканирований
curl http://127.0.0.1:8000/api/v1/scans

# Получить конкретное сканирование
curl http://127.0.0.1:8000/api/v1/scan/{scan_id}

# Получить логи
curl http://127.0.0.1:8000/api/v1/scan/{scan_id}/logs
```

### Файлы результатов
```
C:\Users\%USERNAME%\Desktop\dast-tool\backend\
├── dast.db              # База данных сканирований
└── scans/               # Папка с отчетами (если настроено)
```

---

## 🛠 Troubleshooting

### Ошибка: "python не является внутренней или внешней командой"
**Решение:**
1. Переустановите Python с галочкой "Add to PATH"
2. Или добавьте вручную:
   - Панель управления → Система → Дополнительные параметры
   - Переменные среды → Path → Изменить
   - Добавить: `C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python311\`

### Ошибка: "Выполнение скриптов отключено"
**Решение:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Ошибка: "ModuleNotFoundError: No module named 'fastapi'"
**Решение:**
```powershell
cd backend
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Ошибка: "npm : Имя 'npm' не распознано"
**Решение:**
1. Переустановите Node.js
2. Перезапустите PowerShell

### Ошибка: "Playwright not installed"
**Решение:**
```powershell
pip install playwright
playwright install
```

### Ошибка: "Port 8000 already in use"
**Решение:**
```powershell
# Найти процесс на порту 8000
netstat -ano | findstr :8000

# Убить процесс (замените PID на ваш)
taskkill /PID <PID> /F
```

### Ошибка: "Cannot connect to backend"
**Решение:**
1. Убедитесь, что backend запущен на http://127.0.0.1:8000
2. Проверьте CORS настройки в `backend/main.py`
3. Откройте порт в брандмауэре Windows

---

## 📝 Быстрый запуск (шпаргалка)

### PowerShell скрипт для запуска (run.ps1)
```powershell
# run.ps1 - Запуск DAST Scanner

Write-Host "🚀 Запуск DAST Scanner..." -ForegroundColor Green

# Терминал 1: Backend
Start-Process powershell -ArgumentList @"
cd $PSScriptRoot\backend
.\venv\Scripts\Activate.ps1
python main.py
"@

# Терминал 2: Frontend
Start-Process powershell -ArgumentList @"
cd $PSScriptRoot\frontend
npm run dev
"@

Write-Host "✅ Backend: http://127.0.0.1:8000" -ForegroundColor Cyan
Write-Host "✅ Frontend: http://127.0.0.1:5173" -ForegroundColor Cyan
Write-Host "🎯 Откройте браузер: http://127.0.0.1:5173" -ForegroundColor Green
```

**Использование:**
```powershell
.\run.ps1
```

---

## 🎓 Тестирование установки

### Тест 1: Проверка backend API
```powershell
curl http://127.0.0.1:8000/docs
```
Должна открыться Swagger документация.

### Тест 2: Проверка frontend
Откройте http://127.0.0.1:5173 в браузере.
Должен загрузиться веб-интерфейс.

### Тест 3: Тестовое сканирование
1. Откройте http://127.0.0.1:5173
2. Введите: `http://127.0.0.1:3000` (если есть Juice Shop)
3. Выберите режим "Быстрый"
4. Нажмите "Сканировать"

---

## 📚 Дополнительные ресурсы

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [OWASP ZAP](https://www.zaproxy.org/)
- [SQLMap Documentation](http://sqlmap.org/)
- [Playwright Docs](https://playwright.dev/)

---

## 🆘 Поддержка

Если возникли проблемы:
1. Проверьте логи в консоли backend/frontend
2. Убедитесь, что все зависимости установлены
3. Проверьте, что порты 8000 и 5173 свободны
4. Откройте issue на GitHub

---

*DAST Scanner v3.0 - Windows Installation Guide*
