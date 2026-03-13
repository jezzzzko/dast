# 📦 DAST Scanner - Git Инструкция

## Быстрый старт для GitHub

### 1. Инициализация репозитория

```bash
cd /Users/p1ko/dast-tool

# Инициализация Git
git init

# Проверка статуса
git status
```

### 2. Добавление файлов

```bash
# Добавить все файлы
git add .

# Или выборочно:
git add README.md
git add WINDOWS_INSTALL.md
git add run.ps1
git add backend/
git add frontend/
```

### 3. Первый коммит

```bash
git commit -m "Initial commit: DAST Scanner v3.0

- Backend на FastAPI + Playwright
- Frontend на React + TypeScript
- Поддержка Windows/macOS/Linux
- 3 режима сканирования (Quick, Full, Recon)
- Авто-эксплуатация уязвимостей
- SQLi, XSS, LFI, CORS detection
- OWASP Top 10 совместимость"
```

### 4. Создание репозитория на GitHub

1. Зайдите на https://github.com/new
2. Введите имя: `dast-tool` или `dast-scanner`
3. Выберите **Public** или **Private**
4. **Не нажимайте** "Add README" (у вас уже есть файлы)
5. Нажмите **Create repository**

### 5. Привязка удаленного репозитория

```bash
# Замените YOUR_USERNAME на ваш логин GitHub
git remote add origin https://github.com/YOUR_USERNAME/dast-tool.git

# Проверка
git remote -v
```

### 6. Отправка в GitHub

```bash
# Переименование ветки в main
git branch -M main

# Отправка
git push -u origin main
```

---

## 🔄 Последующие изменения

### После внесения изменений в код:

```bash
# 1. Проверка изменений
git status

# 2. Добавление измененных файлов
git add .

# 3. Коммит
git commit -m "Описание изменений (на английском)"

# 4. Отправка
git push origin main
```

### Примеры коммитов:

```bash
# Добавление новой функции
git commit -m "feat: add LFI detection module"

# Исправление бага
git commit -m "fix: resolve CORS issue in backend"

# Обновление документации
git commit -m "docs: update Windows installation guide"

# Рефакторинг
git commit -m "refactor: optimize Playwright engine"
```

---

## 📝 .gitignore

Проект уже включает `.gitignore` который исключает:

- ✅ `node_modules/` - зависимости frontend
- ✅ `venv/` - виртуальное окружение Python
- ✅ `*.db` - базы данных
- ✅ `.env` - файлы с секретами
- ✅ `__pycache__/` - кэш Python
- ✅ `dist/` - билды frontend
- ✅ `.DS_Store` - системные файлы macOS

---

## 🏷️ Версионирование (Tags)

### Создание тега для релиза:

```bash
# Создать тег
git tag -a v3.0.0 -m "DAST Scanner v3.0.0 - Recon + Auto-Exploit"

# Отправить теги на GitHub
git push origin --tags
```

### Список тегов:

```bash
git tag -l
```

---

## 🌿 Ветвление (Branches)

### Создание новой ветки:

```bash
# Создать и переключиться
git checkout -b feature/new-scanner

# Или отдельно:
git branch feature/new-scanner
git checkout feature/new-scanner
```

### Слияние веток:

```bash
# Вернуться в main
git checkout main

# Влить изменения из feature ветки
git merge feature/new-scanner

# Отправить
git push origin main
```

### Удаление ветки:

```bash
# Локально
git branch -d feature/new-scanner

# На GitHub
git push origin --delete feature/new-scanner
```

---

## 👥 Совместная работа (Pull Requests)

### 1. Fork репозитория
- Зайдите на страницу репозитория
- Нажмите **Fork** в правом верхнем углу

### 2. Клонирование fork'а
```bash
git clone https://github.com/YOUR_USERNAME/dast-tool.git
cd dast-tool
```

### 3. Создание ветки для изменений
```bash
git checkout -b fix/sql-injection-detection
```

### 4. Внесение изменений и коммит
```bash
# ... редактирование файлов ...
git add .
git commit -m "fix: improve SQL injection detection accuracy"
git push origin fix/sql-injection-detection
```

### 5. Создание Pull Request
- Зайдите на GitHub в ваш fork
- Нажмите **Pull requests** → **New pull request**
- Выберите вашу ветку
- Добавьте описание изменений
- Нажмите **Create pull request**

---

## 📊 GitHub Actions (CI/CD)

### Создание workflow для автотестов:

Создайте файл `.github/workflows/test.yml`:

```yaml
name: Tests

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test-backend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          cd backend
          python -m venv venv
          source venv/bin/activate
          pip install -r requirements.txt
      
      - name: Run tests
        run: |
          cd backend
          source venv/bin/activate
          python -m pytest

  test-frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '20'
      
      - name: Install dependencies
        run: |
          cd frontend
          npm install
      
      - name: Run tests
        run: |
          cd frontend
          npm test
```

---

## 🛡️ Безопасность

### Что НЕЛЬЗЯ коммитить:

❌ Файлы `.env` с API ключами  
❌ Файлы баз данных с чувствительной информацией  
❌ Логи с токенами и паролями  
❌ Личные данные и секреты  

### Проверка перед коммитом:

```bash
# Проверить, что будет закоммичено
git status
git diff --cached

# Поиск секретов в истории
git log --all --full-history -- "**/*.env"
git log --all --full-history -- "**/config.py"
```

---

## 📈 Статистика репозитория

### Просмотр статистики:

```bash
# История коммитов
git log --oneline

# Статистика по авторам
git shortlog -sn

# Изменения по файлам
git log --stat
```

### GitHub Insights:
- Зайдите в репозиторий → **Insights** → **Contributors**
- Просматривайте графики активности

---

## 🔗 Полезные ссылки

- [Git Documentation](https://git-scm.com/doc)
- [GitHub Docs](https://docs.github.com/)
- [Git Cheat Sheet](https://education.github.com/git-cheat-sheet-education.pdf)
- [Conventional Commits](https://www.conventionalcommits.org/)

---

*DAST Scanner - Git & GitHub Guide*
