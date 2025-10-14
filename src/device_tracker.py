"""
Device identification and tracking module.
"""

import socket
import subprocess
import platform
import ipaddress
import json
import time
from datetime import datetime, timedelta
from collections import defaultdict
import threading
import re


class DeviceTracker:
    def __init__(self):
        self.devices = {}
        self.mac_to_ip = {}
        self.ip_to_mac = {}
        self.device_activity = defaultdict(list)
        self.vendor_db = {}
        self.last_scan = None
        self._load_mac_vendors()
        
    def _load_mac_vendors(self):
        """Load MAC address vendor database (simplified version)."""
        # This is a simplified vendor database. In practice, you'd load from
        # a comprehensive OUI database file
        self.vendor_db = {
            '00:50:56': 'VMware',
            '08:00:27': 'Oracle VirtualBox',
            '52:54:00': 'QEMU',
            '00:1B:21': 'Intel',
            '00:15:5D': 'Microsoft Hyper-V',
            '00:0C:29': 'VMware',
            'DC:A6:32': 'Raspberry Pi',
            'B8:27:EB': 'Raspberry Pi',
            '00:16:3E': 'Xen',
            '00:1C:42': 'Parallels',
            '08:00:20': 'Sun Microsystems',
            '00:A0:C9': 'Intel',
            '00:E0:4C': 'Realtek',
            '94:DE:80': 'Apple',
            'AC:DE:48': 'Apple',
            '00:1F:F3': 'Apple',
            '28:CD:C4': 'Apple'
        }
        
    def get_vendor_from_mac(self, mac_address):
        """Get vendor name from MAC address."""
        if not mac_address:
            return "Unknown"
            
        # Extract OUI (first 3 octets)
        oui = ':'.join(mac_address.split(':')[:3]).upper()
        return self.vendor_db.get(oui, "Unknown")
        
    def resolve_hostname(self, ip_address):
        """Resolve hostname from IP address."""
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except (socket.herror, socket.gaierror):
            return None
            
    def get_device_type_from_hostname(self, hostname):
        """Guess device type from hostname patterns."""
        if not hostname:
            return "Unknown"
            
        hostname_lower = hostname.lower()
        
        # Common device type patterns
        if any(pattern in hostname_lower for pattern in ['android', 'samsung', 'iphone', 'pixel']):
            return "Mobile Device"
        elif any(pattern in hostname_lower for pattern in ['laptop', 'desktop', 'pc', 'workstation']):
            return "Computer"
        elif any(pattern in hostname_lower for pattern in ['router', 'gateway', 'modem']):
            return "Network Device"
        elif any(pattern in hostname_lower for pattern in ['printer', 'canon', 'hp', 'epson']):
            return "Printer"
        elif any(pattern in hostname_lower for pattern in ['tv', 'roku', 'chromecast', 'appletv']):
            return "Media Device"
        elif any(pattern in hostname_lower for pattern in ['raspberry', 'pi', 'arduino']):
            return "IoT Device"
        elif any(pattern in hostname_lower for pattern in ['nas', 'server']):
            return "Server"
        else:
            return "Unknown"
            
    def add_device_observation(self, mac_address, ip_address, packet_info=None):
        """Add a device observation from network traffic."""
        if not mac_address or not ip_address:
            return
            
        mac_address = mac_address.lower()
        device_id = mac_address
        
        # Update MAC to IP mappings
        self.mac_to_ip[mac_address] = ip_address
        self.ip_to_mac[ip_address] = mac_address
        
        # Create or update device entry
        if device_id not in self.devices:
            hostname = self.resolve_hostname(ip_address)
            vendor = self.get_vendor_from_mac(mac_address)
            device_type = self.get_device_type_from_hostname(hostname)
            
            self.devices[device_id] = {
                'mac_address': mac_address,
                'ip_addresses': [ip_address],
                'hostname': hostname,
                'vendor': vendor,
                'device_type': device_type,
                'first_seen': datetime.now(),
                'last_seen': datetime.now(),
                'packet_count': 0,
                'bytes_sent': 0,
                'bytes_received': 0,
                'active_connections': set(),
                'ports_used': set()
            }
        else:
            # Update existing device
            device = self.devices[device_id]
            if ip_address not in device['ip_addresses']:
                device['ip_addresses'].append(ip_address)
            device['last_seen'] = datetime.now()
            
        # Update packet statistics if packet info provided
        if packet_info:
            device = self.devices[device_id]
            device['packet_count'] += 1
            
            # Track bytes sent/received
            if packet_info.get('src_mac') == mac_address:
                device['bytes_sent'] += packet_info.get('size', 0)
            else:
                device['bytes_received'] += packet_info.get('size', 0)
                
            # Track ports and connections
            if packet_info.get('src_port'):
                device['ports_used'].add(packet_info['src_port'])
            if packet_info.get('dst_port'):
                device['ports_used'].add(packet_info['dst_port'])
                
            # Track connections
            src_ip = packet_info.get('src_ip')
            dst_ip = packet_info.get('dst_ip')
            if src_ip and dst_ip:
                if src_ip == ip_address:
                    device['active_connections'].add(dst_ip)
                else:
                    device['active_connections'].add(src_ip)
                    
        # Record activity
        self.device_activity[device_id].append({
            'timestamp': datetime.now(),
            'ip_address': ip_address,
            'packet_info': packet_info
        })
        
    def get_device_by_mac(self, mac_address):
        """Get device information by MAC address."""
        mac_address = mac_address.lower()
        return self.devices.get(mac_address)
        
    def get_device_by_ip(self, ip_address):
        """Get device information by IP address."""
        mac_address = self.ip_to_mac.get(ip_address)
        if mac_address:
            return self.devices.get(mac_address)
        return None
        
    def get_all_devices(self):
        """Get all tracked devices."""
        return self.devices
        
    def get_active_devices(self, minutes=10):
        """Get devices active within the specified time period."""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        active_devices = {}
        
        for device_id, device in self.devices.items():
            if device['last_seen'] >= cutoff_time:
                active_devices[device_id] = device
                
        return active_devices
        
    def scan_local_network(self, network_range=None):
        """Scan local network for devices using ARP."""
        if not network_range:
            # Try to determine local network range
            network_range = self._get_local_network_range()
            
        if not network_range:
            print("Could not determine network range")
            return
            
        print(f"Scanning network range: {network_range}")
        
        try:
            # Use ARP scan to discover devices
            if platform.system() == "Windows":
                self._arp_scan_windows(network_range)
            else:
                self._arp_scan_unix(network_range)
                
            self.last_scan = datetime.now()
            
        except Exception as e:
            print(f"Error during network scan: {e}")
            
    def _get_local_network_range(self):
        """Determine the local network range."""
        try:
            # Get local IP address
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # Assume /24 subnet (common for home networks)
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            return str(network)
            
        except Exception as e:
            print(f"Error determining network range: {e}")
            return None
            
    def _arp_scan_windows(self, network_range):
        """Perform ARP scan on Windows."""
        try:
            # Use arp -a command
            result = subprocess.run(['arp', '-a'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self._parse_arp_output_windows(result.stdout)
            else:
                print(f"ARP command failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print("ARP scan timed out")
        except Exception as e:
            print(f"Error running ARP scan: {e}")
            
    def _parse_arp_output_windows(self, arp_output):
        """Parse Windows ARP output."""
        lines = arp_output.split('\n')
        
        for line in lines:
            # Look for lines with IP and MAC addresses
            parts = line.strip().split()
            if len(parts) >= 2:
                try:
                    ip_addr = parts[0]
                    mac_addr = parts[1]
                    
                    # Validate IP address format
                    ipaddress.IPv4Address(ip_addr)
                    
                    # Validate MAC address format (basic check)
                    if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac_addr):
                        # Normalize MAC address format
                        mac_addr = mac_addr.replace('-', ':').lower()
                        self.add_device_observation(mac_addr, ip_addr)
                        
                except (ipaddress.AddressValueError, ValueError):
                    continue
                    
    def _arp_scan_unix(self, network_range):
        """Perform ARP scan on Unix-like systems."""
        try:
            # Use arp command or arping if available
            result = subprocess.run(['arp', '-a'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self._parse_arp_output_unix(result.stdout)
            else:
                print(f"ARP command failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print("ARP scan timed out")
        except Exception as e:
            print(f"Error running ARP scan: {e}")
            
    def _parse_arp_output_unix(self, arp_output):
        """Parse Unix ARP output."""
        lines = arp_output.split('\n')
        
        for line in lines:
            # Look for pattern like: hostname (ip) at mac [ether] on interface
            match = re.search(r'\(([\d.]+)\) at ([a-fA-F0-9:]+)', line)
            if match:
                ip_addr = match.group(1)
                mac_addr = match.group(2).lower()
                self.add_device_observation(mac_addr, ip_addr)
                
    def get_device_summary(self):
        """Get a summary of all devices."""
        summary = {
            'total_devices': len(self.devices),
            'active_devices': len(self.get_active_devices()),
            'device_types': defaultdict(int),
            'vendors': defaultdict(int)
        }
        
        for device in self.devices.values():
            summary['device_types'][device['device_type']] += 1
            summary['vendors'][device['vendor']] += 1
            
        return summary
        
    def export_devices(self, filename):
        """Export device information to JSON file."""
        export_data = {}
        
        for device_id, device in self.devices.items():
            device_copy = device.copy()
            # Convert datetime objects and sets to JSON-serializable types
            device_copy['first_seen'] = device_copy['first_seen'].isoformat()
            device_copy['last_seen'] = device_copy['last_seen'].isoformat()
            device_copy['active_connections'] = list(device_copy['active_connections'])
            device_copy['ports_used'] = list(device_copy['ports_used'])
            export_data[device_id] = device_copy
            
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
            
        print(f"Exported {len(export_data)} devices to {filename}")


if __name__ == "__main__":
    # Example usage
    tracker = DeviceTracker()
    
    # Scan network for devices
    tracker.scan_local_network()
    
    # Display discovered devices
    devices = tracker.get_all_devices()
    for device_id, device in devices.items():
        print(f"Device: {device['mac_address']}")
        print(f"  IP: {', '.join(device['ip_addresses'])}")
        print(f"  Hostname: {device['hostname']}")
        print(f"  Vendor: {device['vendor']}")
        print(f"  Type: {device['device_type']}")
        print(f"  Last seen: {device['last_seen']}")
        print()
        
    # Display summary
    summary = tracker.get_device_summary()
    print(f"Device Summary: {summary}")