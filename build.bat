@echo off
setlocal
cd /d "%~dp0"

where cmake >nul 2>&1
if not errorlevel 1 goto :build
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto :missing
for /f "usebackq delims=" %%V in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do call "%%V\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul
where cmake >nul 2>&1
if errorlevel 1 goto :missing

:build
python scripts\build_all.py %*
exit /b %errorlevel%

:missing
echo Install Visual Studio C++ build tools with CMake, or add CMake to PATH.
exit /b 1
