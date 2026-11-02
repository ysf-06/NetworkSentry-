@echo off
setlocal
cd /d "%~dp0"

where gcc >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    if exist "C:\msys64\ucrt64\bin\gcc.exe" (
        set "PATH=C:\msys64\ucrt64\bin;%PATH%"
    ) else if exist "C:\msys64\mingw64\bin\gcc.exe" (
        set "PATH=C:\msys64\mingw64\bin;%PATH%"
    )
)

echo [Build] Compiling packet_parser.dll...
gcc -O3 -Wall -Wextra -shared -DBUILDING_PACKET_PARSER src/packet_parser.c -Iinclude -o packet_parser.dll
if %ERRORLEVEL% NEQ 0 (
    echo [Error] Failed to compile packet_parser.dll
    exit /b 1
)

echo [Build] Compiling C unit test runner test_packet_parser.exe...
gcc -O3 -Wall -Wextra -DBUILDING_PACKET_PARSER src/packet_parser.c src/test_packet_parser.c -Iinclude -o test_packet_parser.exe
if %ERRORLEVEL% NEQ 0 (
    echo [Error] Failed to compile test_packet_parser.exe
    exit /b 1
)

echo [Build] Running C unit tests...
.\test_packet_parser.exe
exit /b %ERRORLEVEL%
