# Network Packet Sniffer - Windows Installation Package

## 🎯 COMPLETE INSTALLATION PACKAGE

This package contains everything needed to install Network Packet Sniffer on Windows.

### 📦 Package Contents:
- `NetworkPacketSniffer.exe` (in dist/ folder) - Main application (11.5 MB)
- `installer_windows.bat` - Windows installer script
- `favicon.png` - Application icon
- `saved_configs.json` - Sample configurations (optional)

## 🚀 INSTALLATION INSTRUCTIONS

### For End Users (Simple):
1. **Download** the entire package
2. **Right-click** `installer_windows.bat`
3. **Select** "Run as administrator" 
4. **Follow** the installation prompts
5. **Done!** Use desktop shortcut or Start Menu

### What the Installer Does:
✅ **Installs** NetworkPacketSniffer.exe to `C:\Program Files\NetworkPacketSniffer\`
✅ **Creates** desktop shortcut
✅ **Creates** Start Menu entry  
✅ **Registers** with Windows (Add/Remove Programs)
✅ **Creates** uninstaller
✅ **Sets up** proper permissions

## 📁 After Installation:

### Installed Files:
- **Program:** `C:\Program Files\NetworkPacketSniffer\NetworkPacketSniffer.exe`
- **Desktop:** `Network Packet Sniffer.lnk`
- **Start Menu:** `Network Packet Sniffer.lnk`
- **Uninstaller:** `C:\Program Files\NetworkPacketSniffer\uninstall.bat`

### How to Run:
- **Desktop shortcut** → Right-click → "Run as administrator"
- **Start Menu** → Right-click → "Run as administrator"  
- **Direct:** `C:\Program Files\NetworkPacketSniffer\NetworkPacketSniffer.exe`

## 🗑️ UNINSTALLATION

### Method 1: Windows Settings
1. **Settings** → **Apps** → **Network Packet Sniffer** → **Uninstall**

### Method 2: Control Panel  
1. **Control Panel** → **Programs** → **Uninstall a program** → **Network Packet Sniffer**

### Method 3: Direct
1. **Run** `C:\Program Files\NetworkPacketSniffer\uninstall.bat` as Administrator

## ⚠️ IMPORTANT NOTES

### Administrator Rights Required:
- **Installation** requires Administrator
- **Running** requires Administrator (for packet capture)
- **Always** right-click shortcuts → "Run as administrator"

### Windows Security:
- **Windows Defender** may flag the .exe (normal for network tools)
- **SmartScreen** may show warning → Click "More info" → "Run anyway"
- **Add exception** to antivirus if needed

### System Requirements:
- **Windows 10/11** (64-bit recommended)
- **4GB RAM** minimum
- **50MB disk space**
- **Administrator privileges**

## 📋 DISTRIBUTION PACKAGE

### For Distribution:
Create a folder containing:
```
NetworkPacketSniffer_Installer/
├── installer_windows.bat
├── favicon.png
├── dist/
│   └── NetworkPacketSniffer.exe
└── README_INSTALL.md (this file)
```

### Instructions for Recipients:
1. **Extract** the folder
2. **Right-click** `installer_windows.bat` 
3. **Select** "Run as administrator"
4. **Follow** prompts
5. **Use** desktop shortcut (as Administrator)

## 🎉 FEATURES INCLUDED

✅ **Multi-session monitoring**
✅ **Real packet capture** 
✅ **Device scanning**
✅ **Save/load sessions**
✅ **Packet analysis with statistics**
✅ **Split screen view**
✅ **Dark theme interface**
✅ **No Python installation required**

---

**Network Packet Sniffer v1.0 - Professional Network Monitoring Tool**