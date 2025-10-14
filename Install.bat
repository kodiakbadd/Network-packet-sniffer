@echo off
title Network Packet Sniffer Installer

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
echo   Installing Network Packet Sniffer
echo ==========================================
echo.

if not exist "%~dp0dist\NetworkPacketSniffer.exe" (
    echo ERROR: NetworkPacketSniffer.exe not found in dist folder
    echo.
    pause
    exit /b 1
)

set "INSTALL_DIR=C:\Program Files\NetworkPacketSniffer"

echo Installing to: %INSTALL_DIR%
echo.

if exist "%INSTALL_DIR%" (
    echo Removing previous installation...
    rmdir /s /q "%INSTALL_DIR%" 2>nul
)

mkdir "%INSTALL_DIR%" 2>nul

echo Copying executable...
copy "%~dp0dist\NetworkPacketSniffer.exe" "%INSTALL_DIR%\NetworkPacketSniffer.exe" >nul

if not exist "%INSTALL_DIR%\NetworkPacketSniffer.exe" (
    echo ERROR: Failed to copy executable
    pause
    exit /b 1
)

echo Copying uninstaller...
copy "%~dp0Uninstall.bat" "%INSTALL_DIR%\Uninstall.bat" >nul

if not exist "%INSTALL_DIR%\Uninstall.bat" (
    echo ERROR: Failed to copy uninstaller
    pause
    exit /b 1
)

echo SUCCESS: Executable and uninstaller installed

echo Creating Start Menu shortcut...
powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Network Packet Sniffer.lnk'); $s.TargetPath = '%INSTALL_DIR%\NetworkPacketSniffer.exe'; $s.IconLocation = '%INSTALL_DIR%\NetworkPacketSniffer.exe'; $s.Save()"

echo Creating Desktop shortcut...  
powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('C:\Users\Public\Desktop\Network Packet Sniffer.lnk'); $s.TargetPath = '%INSTALL_DIR%\NetworkPacketSniffer.exe'; $s.IconLocation = '%INSTALL_DIR%\NetworkPacketSniffer.exe'; $s.Save()"

echo Registering with Windows...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NetworkPacketSniffer" /v "DisplayName" /t REG_SZ /d "Network Packet Sniffer" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NetworkPacketSniffer" /v "UninstallString" /t REG_SZ /d "\"%INSTALL_DIR%\Uninstall.bat\"" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NetworkPacketSniffer" /v "InstallLocation" /t REG_SZ /d "%INSTALL_DIR%" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NetworkPacketSniffer" /v "Publisher" /t REG_SZ /d "Network Monitor Tools" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NetworkPacketSniffer" /v "DisplayVersion" /t REG_SZ /d "1.0.0" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NetworkPacketSniffer" /v "EstimatedSize" /t REG_DWORD /d 12000 /f >nul

cls
echo.
echo ==========================================
echo    INSTALLATION COMPLETED
echo ==========================================
echo.
echo Network Packet Sniffer installed to:
echo %INSTALL_DIR%
echo.
echo Find it in Start Menu: Network Packet Sniffer
echo Desktop shortcut also created
echo.
echo IMPORTANT: Run as Administrator for packet capture
echo.
pause