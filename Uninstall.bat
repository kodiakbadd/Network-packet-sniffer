@echo off
title Network Packet Sniffer Uninstaller

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo ERROR: Administrator privileges required
    echo Right-click this file and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

cls
echo.
echo ==========================================
echo   Uninstalling Network Packet Sniffer
echo ==========================================
echo.

set "INSTALL_DIR=C:\Program Files\NetworkPacketSniffer"

echo Removing shortcuts...
del "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Network Packet Sniffer.lnk" 2>nul
del "C:\Users\Public\Desktop\Network Packet Sniffer.lnk" 2>nul

echo Removing program files...
if exist "%INSTALL_DIR%" (
    rmdir /s /q "%INSTALL_DIR%" 2>nul
    echo Program files removed
) else (
    echo Program files already removed
)

echo Removing registry entries...
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NetworkPacketSniffer" /f >nul 2>&1

cls
echo.
echo ==========================================
echo    UNINSTALLATION COMPLETED
echo ==========================================
echo.
echo Network Packet Sniffer has been completely removed
echo.
pause