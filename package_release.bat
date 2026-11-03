@echo off
setlocal
cd /d "%~dp0"

echo ======================================================================
echo   Cyber Guardian (Network Sentry) -- Windows Desktop Release Builder
echo ======================================================================

echo [1/5] Compiling Native C Packet Engine (packet_parser.dll)...
pushd src\native
call build.bat
if %ERRORLEVEL% NEQ 0 (
    popd
    echo [Error] Native C compilation failed.
    exit /b 1
)
popd

echo [2/5] Running Pytest Verification Suite...
.\.venv\Scripts\python.exe -m pytest -q
if %ERRORLEVEL% NEQ 0 (
    echo [Error] Unit test suite failed. Aborting release build.
    exit /b 1
)

echo [3/5] Packaging Standalone Windows Desktop App with PyInstaller...
if exist "dist\NetworkSentry\networksentry.db*" del /f /q "dist\NetworkSentry\networksentry.db*" 2>nul
if exist "dist\NetworkSentry\*.log" del /f /q "dist\NetworkSentry\*.log" 2>nul
.\.venv\Scripts\pyinstaller.exe ^
    --noconfirm ^
    --clean ^
    --windowed ^
    --icon "assets\cyber_guardian.ico" ^
    --name NetworkSentry ^
    --onedir ^
    --add-data "assets\oui_database.json;assets" ^
    --add-data "assets\cyber_guardian.ico;assets" ^
    --add-binary "src\native\packet_parser.dll;src\native" ^
    --exclude-module PySide6.QtWebEngineCore ^
    --exclude-module PySide6.QtWebEngineWidgets ^
    --exclude-module PySide6.QtQml ^
    --exclude-module PySide6.QtQuick ^
    --exclude-module PySide6.QtPdf ^
    --exclude-module PySide6.Qt3DCore ^
    main.py

if %ERRORLEVEL% NEQ 0 (
    echo [Error] PyInstaller packaging failed.
    exit /b 1
)

echo [4/5] Generating SHA-256 Checksums and Release Archive...
.\.venv\Scripts\python.exe scripts\package_release.py %*
if %ERRORLEVEL% NEQ 0 (
    echo [Error] Release checksum generation failed.
    exit /b 1
)

echo [5/5] Creating Windows Desktop Shortcut (Cyber Guardian - Network Sentry.lnk)...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$desktop = [Environment]::GetFolderPath('Desktop'); " ^
    "$lnkPath = Join-Path $desktop 'Cyber Guardian - Network Sentry.lnk'; " ^
    "$ws = New-Object -ComObject WScript.Shell; " ^
    "$s = $ws.CreateShortcut($lnkPath); " ^
    "$s.TargetPath = '%~dp0dist\NetworkSentry\NetworkSentry.exe'; " ^
    "$s.WorkingDirectory = '%~dp0'; " ^
    "$s.IconLocation = '%~dp0assets\cyber_guardian.ico,0'; " ^
    "$s.Description = 'Cyber Guardian | Network Port Scanner & Packet Analyzer'; " ^
    "$s.Save();"

echo ======================================================================
echo   Release Build Successful: dist\NetworkSentry\NetworkSentry.exe
echo   Desktop Shortcut Created: Cyber Guardian - Network Sentry.lnk
echo ======================================================================
exit /b 0
