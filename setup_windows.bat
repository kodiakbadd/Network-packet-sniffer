@echo off
echo Network Packet Sniffer - Windows Setup
echo ======================================

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges...
) else (
    echo ERROR: This script must be run as Administrator
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

REM Install Python packages
echo Installing Python packages...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

if %errorLevel% neq 0 (
    echo ERROR: Failed to install Python packages
    echo Make sure Python is installed and added to PATH
    pause
    exit /b 1
)

REM Create directories
if not exist logs mkdir logs
if not exist exports mkdir exports
if not exist data mkdir data

echo.
echo Setup completed successfully!
echo.
echo IMPORTANT: You may need to install Npcap for packet capture:
echo https://nmap.org/npcap/
echo.
echo Usage:
echo   python network_monitor.py
echo   python network_monitor.py --help
echo.
pause