# Network Packet Sniffer

A Windows-native network monitoring tool with a dark-themed GUI for real-time packet capture and device filtering.

![Network Packet Sniffer](https://img.shields.io/badge/Platform-Windows-blue) ![License](https://img.shields.io/badge/License-MIT-green) ![Python](https://img.shields.io/badge/Python-3.12+-orange)

## 🚀 Features

### 🔥 Real Network Packet Capture
- Windows-native packet capture (no scapy dependencies)
- Real-time monitoring of established connections
- Filters by MAC address, IP address, and port
- Live connection tracking with protocol detection

### 🎨 Dark Theme GUI
- Modern dark-themed interface
- Multi-session monitoring with tabbed interface
- Pop-out windows for detailed analysis
- Device discovery and application detection

### 📊 Advanced Monitoring

- **Device Identification**: Automatically discover and track devices by MAC address, IP, and hostname
- **Traffic Filtering**: Filter by MAC address, IP address, port, protocol, and more
- **Application Detection**: Identify specific application traffic through port analysis and packet inspection
- **Real-time Monitoring**: Live traffic display with customizable filters
- **Data Export**: Save captured data to JSON/CSV formats for analysis

- Session-specific filters and displays
- Device tracking with MAC/IP correlation
- Application protocol detection (HTTP, HTTPS, SSH, FTP, etc.)
- Real-time statistics and connection logging

### 💾 Configuration Management
- Save and load monitoring configurations
- Persistent session settings
- Export monitoring data

### 🚀 Standalone Deployment
- Single .exe file for easy distribution
- Windows installer with Start Menu integration
- No Python installation required on target machines

## 📦 Installation

### Option 1: Standalone Installer (Recommended)
1. Download the latest release from [Releases](https://github.com/kodiakbadd/network-packet-sniffer/releases)
2. Right-click `Install.bat` and select "Run as administrator"
3. Launch from Start Menu or Desktop shortcut

### Option 2: From Source
```bash
git clone https://github.com/kodiakbadd/network-packet-sniffer.git
cd network-packet-sniffer
pip install -r requirements.txt
python network_gui.py
```

## 🎯 Usage

1. **Launch the application** (requires Administrator privileges for packet capture)
2. **Set filters** - Enter MAC address, IP address, or port number
3. **Click "Start Monitoring"** to begin real-time packet capture
4. **Add sessions** - Use "➕ Add Session" for multi-monitoring
5. **View data** - Check Packets, Devices, Applications, and Statistics tabs

### Multi-Session Monitoring
- Click "➕ Add Session" to create additional monitoring sessions
- Each session has independent filters and displays
- Use pop-out windows for side-by-side comparison

## 📋 Requirements

- Windows 10/11
- Administrator privileges (for packet capture)
- Network interface with active connections

## 🛠️ Building from Source

1. **Clone the repository**
```bash
git clone https://github.com/kodiakbadd/network-packet-sniffer.git
cd network-packet-sniffer
```

2. **Set up virtual environment**
```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1  # Windows PowerShell
pip install -r requirements.txt
```

3. **Run the application**
```bash
python network_gui.py
```

4. **Build standalone executable**
```bash
pyinstaller --onefile --windowed --icon=favicon.ico --add-data "favicon.ico;." --name=NetworkPacketSniffer network_gui.py
```

## 📂 File Structure

```
network-packet-sniffer/
├── network_gui.py          # Main application
├── favicon.ico            # Application icon
├── Install.bat           # Windows installer
├── Uninstall.bat         # Uninstaller
├── ManualCleanup.bat     # Manual cleanup utility
├── requirements.txt      # Python dependencies
├── saved_configs.json    # Saved configurations
├── dist/                 # Built executables
└── src/                  # Source modules
    ├── packet_capture.py # Packet capture logic
    ├── device_tracker.py # Device tracking
    └── ...              # Other modules
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🔧 Troubleshooting

### "Access Denied" or No Packets Captured
- Ensure you're running as Administrator
- Check Windows Firewall settings
- Verify network interface is active

### Icon Not Displaying
- Run `ManualCleanup.bat` as Administrator
- Reinstall using `Install.bat` as Administrator

### Application Won't Start
- Check antivirus software (may quarantine the .exe)
- Verify Windows Defender exclusions
- Try running the Python source version

## 📞 Support

- 🐛 **Bug Reports**: [Create an issue](https://github.com/kodiakbadd/network-packet-sniffer/issues)
- 💡 **Feature Requests**: [Start a discussion](https://github.com/kodiakbadd/network-packet-sniffer/discussions)
- 📧 **Contact**: crashedmobile@gmail.com

## 🙏 Acknowledgments

- Built with Python and tkinter
- Inspired by the need for lightweight Windows network monitoring
- Thanks to the open-source community for tools and libraries

## ⚠️ Disclaimer

This tool is for educational and legitimate network monitoring purposes only. Always ensure you have proper authorization before monitoring network traffic.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Filter by IP address:
```
python network_monitor.py --ip 192.168.1.100
```

### Monitor specific application traffic:
```
python network_monitor.py --app web --port 80,443
```

## Important Notes

- This tool requires administrator/root privileges to capture network packets
- On Windows, you may need to install Npcap or WinPcap
- Use responsibly and only on networks you own or have permission to monitor

## Legal Disclaimer

This tool is for educational and authorized network monitoring purposes only. Users are responsible for complying with all applicable laws and regulations.