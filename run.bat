@echo off
cd /d "%~dp0"
call .venv\Scripts\activate.bat
python network_gui.py
pause