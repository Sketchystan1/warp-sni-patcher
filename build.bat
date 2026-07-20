@echo off
setlocal EnableExtensions

for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do set "ESC=%%b"
set "RED=%ESC%[91m"
set "GREEN=%ESC%[92m"
set "YELLOW=%ESC%[93m"
set "RESET=%ESC%[0m"

set VCVARS="C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat"
:: This script lives next to the source files; everything is built in place.
set "PATCHER_DIR=%~dp0"
set "PATCHER_EXE=%PATCHER_DIR%warp-sni-patcher.exe"
set "SOURCES=patcher.c ui.c"

if not exist %VCVARS% (
    echo %RED%[!] Visual Studio 2026 not found at %VCVARS%%RESET%
    goto :error
)

echo %YELLOW%Building patcher...%RESET%
call %VCVARS% amd64 >nul 2>&1
pushd "%PATCHER_DIR%"

:: Extract the shell32.dll icon (index 314) into gear.ico, then compile the
:: resource script that embeds it into the executable.
if not exist "%PATCHER_DIR%gear.ico" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%PATCHER_DIR%make-icon.ps1"
    if errorlevel 1 goto :error
)
rc.exe /nologo /fo "%PATCHER_DIR%app.res" "%PATCHER_DIR%app.rc"
if errorlevel 1 goto :error

:: /SUBSYSTEM:WINDOWS for a GUI app; the linker embeds the requireAdministrator
:: manifest so the patcher always launches elevated. Objects land next to the
:: sources and are cleaned up below.
cl.exe /nologo /W3 /O2 /DNDEBUG /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS /MT ^
    /Fe"%PATCHER_EXE%" %SOURCES% ^
    /link /INCREMENTAL:NO /RELEASE /SUBSYSTEM:WINDOWS app.res ^
    /MANIFEST:EMBED /MANIFESTUAC:"level='requireAdministrator' uiAccess='false'" ^
    kernel32.lib user32.lib gdi32.lib comdlg32.lib advapi32.lib comctl32.lib dwmapi.lib uxtheme.lib
if errorlevel 1 goto :error

del /Q "%PATCHER_DIR%*.obj" "%PATCHER_DIR%*.exp" "%PATCHER_DIR%*.lib" "%PATCHER_DIR%*.res" 2>nul

echo %GREEN%[+] Patcher built: %PATCHER_EXE%%RESET%
popd
endlocal
exit /b 0

:error
echo %RED%[!] Patcher build failed%RESET%
del /Q "%PATCHER_DIR%*.obj" "%PATCHER_DIR%*.exp" "%PATCHER_DIR%*.lib" "%PATCHER_DIR%*.res" 2>nul
popd
echo.
echo Press any key to close . . .
pause >nul
endlocal
exit /b 1
