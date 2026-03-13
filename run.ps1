# DAST Scanner - Быстрый запуск на Windows
# Использование: .\run.ps1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   🚀 DAST Scanner v3.0 - Запуск       " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Проверка Python
Write-Host "[1/4] Проверка Python..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✅ $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Python не найден! Установите Python 3.10+" -ForegroundColor Red
    Write-Host "Скачайте с: https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

# Проверка Node.js
Write-Host "[2/4] Проверка Node.js..." -ForegroundColor Yellow
try {
    $nodeVersion = node --version 2>&1
    Write-Host "✅ Node.js $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Node.js не найден! Установите Node.js 18+" -ForegroundColor Red
    Write-Host "Скачайте с: https://nodejs.org/" -ForegroundColor Yellow
    exit 1
}

# Получение пути к скрипту
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendPath = Join-Path $scriptPath "backend"
$frontendPath = Join-Path $scriptPath "frontend"

# Запуск Backend
Write-Host "[3/4] Запуск Backend..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList @"
Set-Location '$backendPath'
.\venv\Scripts\Activate.ps1
Write-Host '========================================' -ForegroundColor Cyan
Write-Host '   DAST Scanner Backend                ' -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan
python main.py
"@ -WindowStyle Normal

Start-Sleep -Seconds 2

# Запуск Frontend
Write-Host "[4/4] Запуск Frontend..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList @"
Set-Location '$frontendPath'
Write-Host '========================================' -ForegroundColor Cyan
Write-Host '   DAST Scanner Frontend               ' -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan
npm run dev
"@ -WindowStyle Normal

# Задержка для отображения сообщения
Start-Sleep -Seconds 3

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "   ✅ DAST Scanner запущен!            " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "📍 Backend API:   http://127.0.0.1:8000" -ForegroundColor Cyan
Write-Host "📍 Frontend UI:   http://127.0.0.1:5173" -ForegroundColor Cyan
Write-Host "📍 Swagger Docs:  http://127.0.0.1:8000/docs" -ForegroundColor Cyan
Write-Host ""
Write-Host "🎯 Откройте браузер: http://127.0.0.1:5173" -ForegroundColor Green
Write-Host ""
Write-Host "Для остановки нажмите Ctrl+C в каждом окне" -ForegroundColor Yellow
Write-Host ""
