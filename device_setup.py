#!/usr/bin/env python3
"""
Device Discovery and Configuration Script
"""

import sys
import json
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from src.device_tracker import DeviceTracker

def discover_devices():
    """Discover devices on the local network."""
    print("🔍 Discovering devices on your network...")
    
    tracker = DeviceTracker()
    
    # Scan the local network
    tracker.scan_local_network()
    
    # Get discovered devices
    devices = tracker.get_all_devices()
    
    print(f"\n✅ Found {len(devices)} devices:")
    print("=" * 80)
    
    if not devices:
        print("No devices found. This might be because:")
        print("- You're not connected to a network")
        print("- Network scanning is blocked by firewall")
        print("- Devices are not responding to ARP requests")
        return devices
    
    # Display devices in a nice format
    for i, (device_id, device_info) in enumerate(devices.items(), 1):
        print(f"\n📱 Device #{i}")
        print(f"   MAC Address: {device_info['mac_address']}")
        print(f"   IP Address:  {', '.join(device_info['ip_addresses'])}")
        print(f"   Hostname:    {device_info.get('hostname', 'Unknown')}")
        print(f"   Vendor:      {device_info.get('vendor', 'Unknown')}")
        print(f"   Device Type: {device_info.get('device_type', 'Unknown')}")
        print(f"   First Seen:  {device_info['first_seen']}")
    
    return devices

def create_device_config(devices):
    """Create a device configuration file."""
    config = {
        "devices": {},
        "filters": {
            "mac_addresses": [],
            "ip_addresses": [],
            "device_types": []
        },
        "monitoring": {
            "track_bandwidth": True,
            "log_connections": True,
            "detect_new_devices": True
        }
    }
    
    # Add discovered devices to config
    for device_id, device_info in devices.items():
        config["devices"][device_id] = {
            "mac_address": device_info["mac_address"],
            "ip_addresses": device_info["ip_addresses"],
            "hostname": device_info.get("hostname"),
            "vendor": device_info.get("vendor"),
            "device_type": device_info.get("device_type"),
            "custom_name": "",  # User can set a custom name
            "monitor": True,    # Whether to monitor this device
            "alert_on_activity": False,  # Alert when device is active
            "bandwidth_limit": None,     # Bandwidth limit in MB/s
            "allowed_connections": [],   # Allowed destination IPs
            "blocked_connections": []    # Blocked destination IPs
        }
    
    # Save configuration
    config_file = Path("device_config.json")
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2, default=str)
    
    print(f"\n💾 Device configuration saved to: {config_file}")
    return config_file

def interactive_device_config(devices):
    """Interactive device configuration."""
    if not devices:
        print("No devices to configure.")
        return
    
    print("\n🔧 Interactive Device Configuration")
    print("=" * 50)
    
    configured_devices = {}
    
    for device_id, device_info in devices.items():
        print(f"\n📱 Configuring Device: {device_info['mac_address']}")
        print(f"   Current hostname: {device_info.get('hostname', 'Unknown')}")
        print(f"   IP addresses: {', '.join(device_info['ip_addresses'])}")
        
        # Ask for custom name
        custom_name = input("   Enter custom name (or press Enter to skip): ").strip()
        
        # Ask if should monitor
        monitor = input("   Monitor this device? (y/N): ").lower().startswith('y')
        
        # Ask for alerts
        alert = False
        if monitor:
            alert = input("   Alert on activity? (y/N): ").lower().startswith('y')
        
        configured_devices[device_id] = {
            "mac_address": device_info["mac_address"],
            "ip_addresses": device_info["ip_addresses"],
            "hostname": device_info.get("hostname"),
            "vendor": device_info.get("vendor"),
            "device_type": device_info.get("device_type"),
            "custom_name": custom_name or device_info.get('hostname', 'Unknown'),
            "monitor": monitor,
            "alert_on_activity": alert
        }
        
        print(f"   ✅ Configured: {configured_devices[device_id]['custom_name']}")
    
    # Save configured devices
    config_file = Path("my_devices.json")
    with open(config_file, 'w') as f:
        json.dump(configured_devices, f, indent=2, default=str)
    
    print(f"\n💾 Your device configuration saved to: {config_file}")
    return configured_devices

def show_monitoring_examples(devices):
    """Show examples of how to monitor specific devices."""
    if not devices:
        return
    
    print("\n🎯 Device Monitoring Examples")
    print("=" * 50)
    
    # Get first few devices for examples
    device_list = list(devices.items())[:3]
    
    for device_id, device_info in device_list:
        mac = device_info['mac_address']
        ip = device_info['ip_addresses'][0] if device_info['ip_addresses'] else 'N/A'
        name = device_info.get('hostname', 'Unknown')
        
        print(f"\n📱 Monitor '{name}':")
        print(f"   By MAC: python network_monitor.py --mac {mac}")
        print(f"   By IP:  python network_monitor.py --ip {ip}")
        
    print(f"\n🌐 Monitor multiple devices:")
    all_ips = []
    for device_info in devices.values():
        all_ips.extend(device_info['ip_addresses'])
    
    if all_ips:
        # Determine network range
        import ipaddress
        try:
            first_ip = ipaddress.IPv4Address(all_ips[0])
            network = ipaddress.IPv4Network(f"{first_ip}/24", strict=False)
            print(f"   Monitor all local devices: python network_monitor.py --ip {network}")
        except:
            print(f"   Monitor specific IPs: python network_monitor.py --ip {','.join(all_ips[:3])}")
    
    print(f"\n🔍 Advanced monitoring:")
    print(f"   Scan & monitor: python network_monitor.py --scan-network --mode devices")
    print(f"   Monitor apps:   python network_monitor.py --scan-network --mode apps")
    print(f"   Export data:    python network_monitor.py --export-devices --export-apps")

def main():
    """Main function."""
    print("🔧 Network Device Discovery & Configuration Tool")
    print("=" * 60)
    
    # Discover devices
    devices = discover_devices()
    
    if not devices:
        print("\n❌ No devices found. Make sure you're connected to a network.")
        return
    
    # Show menu
    while True:
        print("\n📋 What would you like to do?")
        print("1. 🔧 Configure devices interactively")
        print("2. 💾 Save device list to file")
        print("3. 🎯 Show monitoring examples")
        print("4. 🚀 Start monitoring now")
        print("5. ❌ Exit")
        
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == '1':
            configured = interactive_device_config(devices)
            
        elif choice == '2':
            create_device_config(devices)
            
        elif choice == '3':
            show_monitoring_examples(devices)
            
        elif choice == '4':
            print("\n🚀 To start monitoring, run:")
            print("   python network_monitor.py --scan-network")
            print("\n⚠️  Remember to run as Administrator for packet capture!")
            break
            
        elif choice == '5':
            print("👋 Goodbye!")
            break
            
        else:
            print("❌ Invalid choice. Please enter 1-5.")

if __name__ == "__main__":
    main()