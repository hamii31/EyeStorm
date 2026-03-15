@echo off
REM ═══════════════════════════════════════════════════════════════════════════
REM  build.bat  —  Build SysMon with MSVC (cl.exe) or MinGW (gcc)
REM
REM  Prerequisites (MSVC):
REM    - Visual Studio 2019/2022  OR  Build Tools for Visual Studio
REM    - Run from a "Developer Command Prompt for VS"
REM      OR run this bat from a plain prompt after calling vcvars64.bat
REM
REM  Prerequisites (MinGW):
REM    - MinGW-w64  (https://www.mingw-w64.org/)
REM    - gcc.exe must be on PATH
REM ═══════════════════════════════════════════════════════════════════════════

setlocal

set SRCS=main.c snapshot.c compare.c legitimacy.c sha256.c util.c
set OUTDIR=build
set TARGET=eyestorm.exe

if not exist %OUTDIR% mkdir %OUTDIR%

REM ── Try MSVC first ─────────────────────────────────────────────────────────
where cl >nul 2>&1
if %ERRORLEVEL% EQU 0 goto :use_msvc

REM ── Fallback: MinGW / gcc ──────────────────────────────────────────────────
where gcc >nul 2>&1
if %ERRORLEVEL% EQU 0 goto :use_gcc

echo [!] Neither cl.exe (MSVC) nor gcc (MinGW) found on PATH.
echo     Install Visual Studio Build Tools or MinGW-w64 and retry.
exit /b 1

REM ════════════════════════════════════════════════════════════════════════════
:use_msvc
echo [*] Building with MSVC (cl.exe)...

cl.exe /nologo /W3 /O2 /MT ^
    /DWIN32 /D_WIN32_WINNT=0x0A00 /DUNICODE /D_UNICODE ^
    /D_CRT_SECURE_NO_WARNINGS /D_CRT_NONSTDC_NO_WARNINGS ^
    %SRCS% ^
    /Fe:%OUTDIR%\%TARGET% ^
    /link ^
    advapi32.lib ^
    bcrypt.lib ^
    crypt32.lib ^
    iphlpapi.lib ^
    ole32.lib ^
    oleaut32.lib ^
    psapi.lib ^
    shlwapi.lib ^
    taskschd.lib ^
    wbemuuid.lib ^
    wintrust.lib ^
    ws2_32.lib ^
    ntdll.lib

if %ERRORLEVEL% NEQ 0 (
    echo [!] MSVC build failed.
    exit /b %ERRORLEVEL%
)
goto :build_ok

REM ════════════════════════════════════════════════════════════════════════════
:use_gcc
echo [*] Building with MinGW gcc...

gcc -O2 -Wall -Wno-unused-function ^
    -D WIN32 -D _WIN32_WINNT=0x0A00 -D UNICODE -D _UNICODE ^
    %SRCS% ^
    -o %OUTDIR%\%TARGET% ^
    -l advapi32 ^
    -l bcrypt ^
    -l crypt32 ^
    -l iphlpapi ^
    -l ole32 ^
    -l oleaut32 ^
    -l psapi ^
    -l shlwapi ^
    -l taskschd ^
    -l wbemuuid ^
    -l wintrust ^
    -l ws2_32

if %ERRORLEVEL% NEQ 0 (
    echo [!] MinGW build failed.
    exit /b %ERRORLEVEL%
)
goto :build_ok

REM ════════════════════════════════════════════════════════════════════════════
:build_ok
echo.
echo [+] Build successful:  %OUTDIR%\%TARGET%
echo.
echo Usage (run as Administrator):
echo   %OUTDIR%\%TARGET% snapshot  snap1.bin
echo   %OUTDIR%\%TARGET% snapshot  snap2.bin
echo   %OUTDIR%\%TARGET% compare   snap1.bin snap2.bin
echo   %OUTDIR%\%TARGET% watch     30 snapshots\
echo   %OUTDIR%\%TARGET% audit     snap1.bin
echo   %OUTDIR%\%TARGET% tasks     snap1.bin
echo   %OUTDIR%\%TARGET% procs     snap1.bin
echo   %OUTDIR%\%TARGET% net       snap1.bin
echo   %OUTDIR%\%TARGET% verify    snap1.bin
echo.
endlocal
