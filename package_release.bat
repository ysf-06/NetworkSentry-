@echo off
setlocal
cd /d "%~dp0"

echo ======================================================================
echo   Network Sentry v1.0.0 -- Release Build and Packaging Script
echo ======================================================================

echo [1/3] Compiling Native C Packet Engine (packet_parser.dll)...
pushd src\native
call build.bat
if %ERRORLEVEL% NEQ 0 (
    popd
    echo [Error] Native C compilation failed.
    exit /b 1
)
popd

echo [2/3] Running Pytest Verification Suite...
.\.venv\Scripts\python.exe -m pytest -q
if %ERRORLEVEL% NEQ 0 (
    echo [Error] Unit test suite failed. Aborting release build.
    exit /b 1
)

echo [3/3] Packaging Standalone Executable with PyInstaller...
.\.venv\Scripts\pyinstaller.exe ^
    --noconfirm ^
    --clean ^
    --name NetworkSentry ^
    --onedir ^
    --add-data "assets\oui_database.json;assets" ^
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

echo ======================================================================
echo   Release Build Successful: dist\NetworkSentry\NetworkSentry.exe
echo ======================================================================
exit /b 0
