# 🌐 Network Monitor GUI - Dark Edition

A sophisticated network monitoring tool with a dark-themed GUI interface for capturing and analyzing network traffic, identifying devices, and detecting application traffic.

## ✨ Features

- **🎨 Dark Theme Interface** - Professional dark theme with intuitive button controls
- **📦 Live Packet Monitoring** - Real-time packet capture and display
- **🖥️ Device Discovery** - Automatic detection and tracking of network devices
- **📱 Application Identification** - Identify specific applications generating traffic
- **📊 Statistics Dashboard** - Comprehensive monitoring statistics
- **💻 Console Output** - PowerShell-style console for system messages
- **🔍 Advanced Filtering** - Filter by MAC address, IP, port, and protocol
- **🎯 Pre-configured for Target Device** - Ready to monitor 10.0.0.151 (MAC: 2e:80:02:62:18:46)

## 🚀 Quick Start

### Method 1: Batch File (Recommended)
1. Right-click `start_gui.bat` 
2. Select "Run as administrator"
3. Press any key to launch the GUI

### Method 2: PowerShell
1. Open PowerShell as Administrator
2. Navigate to the project folder:
   ```powershell
   cd "C:\Users\James\networkPacketSniffer"
   ```
3. Activate the virtual environment:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
4. Launch the GUI:
   ```powershell
   python launch_gui.py
   ```

## 🎮 Demo Mode

If network modules aren't available, the GUI runs in demo mode with:
- Sample packet data
- Mock device information  
- Simulated application traffic
- All GUI features functional

## 🖥️ GUI Overview

### 📋 Tabs

1. **📦 Live Packets** - Real-time packet capture display
2. **🖥️ Devices** - Network device discovery and tracking
3. **📱 Applications** - Application traffic identification
4. **📊 Statistics** - System statistics and monitoring info
5. **💻 Console** - System messages and logs (PowerShell-style)

### 🎛️ Control Panel

- **🚀 Start/Stop Monitoring** - Toggle packet capture
- **🗑️ Clear Data** - Reset all displays
- **📝 Filters** - MAC and IP address filtering (pre-filled for your device)

### 🔍 Pre-configured Filters

The GUI comes pre-configured to monitor your target device:
- **MAC Address**: `2e:80:02:62:18:46`
- **IP Address**: `10.0.0.151`

## ⚙️ Requirements

- **Administrator Privileges** - Required for packet capture
- **Python 3.12+** - With virtual environment
- **Npcap** - Windows packet capture driver (already installed)
- **Network Modules** - Scapy, psutil, etc. (in requirements.txt)

## 🔧 Technical Details

### Network Components
- **NetworkCapture** - Scapy-based packet capture
- **DeviceTracker** - MAC/IP device identification
- **TrafficFilter** - Advanced packet filtering
- **ApplicationIdentifier** - Deep packet inspection for apps

### GUI Architecture
- **Tkinter** - Cross-platform GUI framework
- **Threading** - Non-blocking real-time updates
- **Dark Theme** - Custom ttk styles for professional appearance

## 🐛 Troubleshooting

### "Administrator privileges required"
- Right-click PowerShell and select "Run as administrator"
- Or right-click `start_gui.bat` and select "Run as administrator"

### "Module import error"
- Activate the virtual environment first:
  ```powershell
  .\.venv\Scripts\Activate.ps1
  ```
- Install dependencies:
  ```powershell
  pip install -r requirements.txt
  ```

### GUI not responding
- GUI runs in background threads for real-time updates
- Use the 🛑 Stop button to halt monitoring
- Use 🗑️ Clear Data to reset displays

## 📁 File Structure

```
networkPacketSniffer/
├── launch_gui.py          # GUI launcher with admin check
├── network_gui.py         # Main dark-themed GUI application
├── start_gui.bat          # Windows batch launcher
├── network_monitor.py     # Original CLI version
├── requirements.txt       # Python dependencies
├── src/                   # Network monitoring modules
│   ├── packet_capture.py  # Packet capture engine
│   ├── device_tracker.py  # Device identification
│   ├── traffic_filter.py  # Traffic filtering
│   ├── app_identifier.py  # Application detection
│   ├── network_ui.py      # Original CLI interface
│   └── network_logger.py  # Logging system
└── .venv/                 # Python virtual environment
```

## 🎯 Usage Tips

1. **Start with Demo Mode** - Test GUI functionality without admin privileges
2. **Apply Filters First** - Set MAC/IP filters before starting monitoring
3. **Monitor Console Tab** - Check console for system messages and errors
4. **Use Statistics Tab** - View comprehensive monitoring information
5. **Clear Data Regularly** - Reset displays to improve performance

## 🔐 Security Notes

- Requires Administrator privileges for packet capture
- Only monitors local network traffic
- Respects network privacy and security policies
- No data is transmitted outside the local system

---

**🌐 Network Monitor GUI** - Professional network analysis with style! 🎨