@echo off
setlocal EnableExtensions
chcp 65001 >nul 2>&1
title Intelligent Windows Cleanup and Dependency Scanner
set "APPDIR=%~dp0"

set "MAINPS=%APPDIR%src\Main.ps1"
if not exist "%MAINPS%" set "MAINPS=%APPDIR%Main.ps1"
if not exist "%MAINPS%" (
    echo ERROR: Main.ps1 was not found next to this launcher or in a src subfolder.
    echo Put WinCleanup.bat, Main.ps1 and all Lib.*.ps1 files together, or use the src folder.
    pause
    exit /b 1
)

where powershell.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: Windows PowerShell 5.1 was not found on this system.
    pause
    exit /b 1
)

rem --- Detect administrator rights -------------------------------------
net session >nul 2>&1
if %errorlevel%==0 (set "ISADMIN=1") else (set "ISADMIN=0")

if /i "%~1"=="/elevated" goto run
if "%ISADMIN%"=="1" goto run

echo.
echo ============================================================
echo  Not running as Administrator.
echo ============================================================
echo  Without elevation the tool still works, but it cannot read
echo  C:\Windows\Temp, other user profiles, or some registry keys.
echo  Items that depend on unreadable data are classified as
echo  NEEDS REVIEW, never SAFE.
echo.
choice /c AC /n /m "[A] Relaunch as Administrator   [C] Continue without elevation: "
if errorlevel 2 goto run

set "SELF=%~f0"
powershell.exe -NoProfile -Command "Start-Process -FilePath $env:SELF -ArgumentList '/elevated' -Verb RunAs"
exit /b 0

:run
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%MAINPS%"
set "RC=%errorlevel%"
if not "%RC%"=="0" (
    echo.
    echo The tool exited with code %RC%.
    pause
)
endlocal
exit /b %RC%
