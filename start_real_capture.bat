@echo off
echo 🚀 Starting Network Monitor with Real Packet Capture...
echo.
cd /d "C:\Users\James\networkPacketSniffer"
"C:\Users\James\networkPacketSniffer\.venv\Scripts\python.exe" network_gui.py
echo.
echo 🛑 Network Monitor closed
pause