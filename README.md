# Network Packet Sniffer

A Windows-native network monitoring tool with a dark-themed GUI for real-time packet capture and device filtering.

## Features

🔥 **Real Network Packet Capture**
- Windows-native packet capture (no scapy dependencies)
- Real-time monitoring of established connections
- Filters by MAC address, IP address, and port

🎨 **Dark Theme GUI**
- Modern dark-themed interface
- Multi-session monitoring with tabbed interface
- Pop-out windows for detailed analysis
- Device discovery and application detection

📊 **Advanced Monitoring**

- **Device Identification**: Automatically discover and track devices by MAC address, IP, and hostname
- **Traffic Filtering**: Filter by MAC address, IP address, port, protocol, and more
- **Application Detection**: Identify specific application traffic through port analysis and packet inspection
- **Real-time Monitoring**: Live traffic display with customizable filters
- **Data Export**: Save captured data to JSON/CSV formats for analysis

## Requirements

- Python 3.7+
- Administrator/root privileges (required for packet capture)
- Windows/Linux/macOS support

## Installation

1. Clone this repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Basic monitoring:
```
python network_monitor.py
```

### Filter by MAC address:
```
python network_monitor.py --mac 00:11:22:33:44:55
```

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