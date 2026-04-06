param(
    [string]$ApiCommand = "",
    [switch]$SkipApi,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

$pythonExe = Join-Path $projectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $pythonExe)) {
    Write-Host "[오류] 가상환경 Python을 찾을 수 없습니다: $pythonExe" -ForegroundColor Red
    Write-Host "먼저 .venv를 만들고 requirements를 설치하세요." -ForegroundColor Yellow
    exit 1
}

if (-not $SkipApi) {
    if ([string]::IsNullOrWhiteSpace($ApiCommand)) {
        if ($env:CONTROL_API_COMMAND) {
            $ApiCommand = $env:CONTROL_API_COMMAND
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ApiCommand)) {
        Write-Host "[정보] 제어 API 시작: $ApiCommand" -ForegroundColor Cyan
        Start-Process powershell -ArgumentList @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-Command", "Set-Location '$projectRoot'; $ApiCommand"
        ) | Out-Null
    }
    else {
        Write-Host "[경고] CONTROL_API_COMMAND 또는 -ApiCommand가 없어 외부 제어 API는 시작하지 않습니다." -ForegroundColor Yellow
        Write-Host "       웹 GUI는 실행되지만 실제 네트워크 제어는 동작하지 않을 수 있습니다." -ForegroundColor Yellow
    }
}

if (-not $NoBrowser) {
    Start-Process "http://localhost:5000" | Out-Null
}

Write-Host "[정보] 웹 GUI 시작 중..." -ForegroundColor Green
& $pythonExe app.py
