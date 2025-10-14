@echo off
title Manual Cleanup - Network Packet Sniffer

echo ==========================================
echo   Manual Cleanup for Network Packet Sniffer
echo ==========================================
echo.
echo This will remove the current broken installation
echo so you can install the updated version.
echo.
pause

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo ERROR: Administrator privileges required
    echo Right-click this file and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo Stopping any running instances...
taskkill /F /IM NetworkPacketSniffer.exe /T 2>nul

echo Removing shortcuts...
del "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Network Packet Sniffer.lnk" 2>nul
del "C:\Users\Public\Desktop\Network Packet Sniffer.lnk" 2>nul

echo Removing program files...
rmdir /s /q "C:\Program Files\NetworkPacketSniffer" 2>nul

echo Removing registry entries...
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NetworkPacketSniffer" /f >nul 2>&1

echo.
echo ==========================================
echo   CLEANUP COMPLETED
echo ==========================================
echo.
echo The old installation has been removed.
echo You can now run Install.bat to install the updated version.
echo.
pause