"""
Core packet capture module using Scapy for network monitoring.
"""

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet6 import IPv6
import threading
import time
from datetime import datetime
from collections import defaultdict
import json


class PacketCapture:
    def __init__(self, interface=None):
        self.interface = interface
        self.is_capturing = False
        self.capture_thread = None
        self.packets = []
        self.packet_count = 0
        self.callbacks = []
        self.filters = {}
        
    def add_callback(self, callback):
        """Add a callback function to be called for each captured packet."""
        self.callbacks.append(callback)
        
    def set_filter(self, filter_dict):
        """Set packet filtering criteria."""
        self.filters = filter_dict
        
    def _apply_filters(self, packet):
        """Apply filters to determine if packet should be processed."""
        if not self.filters:
            return True
            
        # MAC address filter
        if 'mac' in self.filters:
            if packet.haslayer(Ether):
                src_mac = packet[Ether].src.lower()
                dst_mac = packet[Ether].dst.lower()
                filter_mac = self.filters['mac'].lower()
                if filter_mac not in [src_mac, dst_mac]:
                    return False
                    
        # IP address filter
        if 'ip' in self.filters:
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                filter_ip = self.filters['ip']
                if filter_ip not in [src_ip, dst_ip]:
                    return False
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
                filter_ip = self.filters['ip']
                if filter_ip not in [src_ip, dst_ip]:
                    return False
            else:
                return False
                
        # Port filter
        if 'port' in self.filters:
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            else:
                return False
                
            filter_ports = self.filters['port']
            if isinstance(filter_ports, int):
                filter_ports = [filter_ports]
            if not any(port in [src_port, dst_port] for port in filter_ports):
                return False
                
        # Protocol filter
        if 'protocol' in self.filters:
            protocol = self.filters['protocol'].lower()
            if protocol == 'tcp' and not packet.haslayer(TCP):
                return False
            elif protocol == 'udp' and not packet.haslayer(UDP):
                return False
            elif protocol == 'icmp' and not packet.haslayer(ICMP):
                return False
            elif protocol == 'arp' and not packet.haslayer(ARP):
                return False
                
        return True
        
    def _packet_handler(self, packet):
        """Handle captured packets."""
        if not self._apply_filters(packet):
            return
            
        self.packet_count += 1
        
        # Extract packet information
        packet_info = self._extract_packet_info(packet)
        self.packets.append(packet_info)
        
        # Call registered callbacks
        for callback in self.callbacks:
            try:
                callback(packet_info, packet)
            except Exception as e:
                print(f"Error in callback: {e}")
                
    def _extract_packet_info(self, packet):
        """Extract relevant information from a packet."""
        info = {
            'timestamp': datetime.now(),
            'size': len(packet),
            'protocol': 'Unknown',
            'src_mac': None,
            'dst_mac': None,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'flags': None,
            'payload_size': 0
        }
        
        # Ethernet layer
        if packet.haslayer(Ether):
            info['src_mac'] = packet[Ether].src
            info['dst_mac'] = packet[Ether].dst
            
        # IP layer
        if packet.haslayer(IP):
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            info['protocol'] = 'IPv4'
            
            # TCP layer
            if packet.haslayer(TCP):
                info['protocol'] = 'TCP'
                info['src_port'] = packet[TCP].sport
                info['dst_port'] = packet[TCP].dport
                info['flags'] = packet[TCP].flags
                info['payload_size'] = len(packet[TCP].payload)
                
            # UDP layer
            elif packet.haslayer(UDP):
                info['protocol'] = 'UDP'
                info['src_port'] = packet[UDP].sport
                info['dst_port'] = packet[UDP].dport
                info['payload_size'] = len(packet[UDP].payload)
                
            # ICMP layer
            elif packet.haslayer(ICMP):
                info['protocol'] = 'ICMP'
                
        # IPv6 layer
        elif packet.haslayer(IPv6):
            info['src_ip'] = packet[IPv6].src
            info['dst_ip'] = packet[IPv6].dst
            info['protocol'] = 'IPv6'
            
        # ARP layer
        elif packet.haslayer(ARP):
            info['protocol'] = 'ARP'
            info['src_ip'] = packet[ARP].psrc
            info['dst_ip'] = packet[ARP].pdst
            
        return info
        
    def start_capture(self, count=0, timeout=None):
        """Start packet capture."""
        if self.is_capturing:
            print("Capture is already running")
            return
            
        self.is_capturing = True
        self.packets = []
        self.packet_count = 0
        
        print(f"Starting packet capture on interface: {self.interface or 'default'}")
        
        try:
            # Start sniffing in a separate thread
            self.capture_thread = threading.Thread(
                target=self._capture_worker,
                args=(count, timeout)
            )
            self.capture_thread.daemon = True
            self.capture_thread.start()
            
        except Exception as e:
            print(f"Error starting capture: {e}")
            self.is_capturing = False
            
    def _capture_worker(self, count, timeout):
        """Worker thread for packet capture."""
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                count=count,
                timeout=timeout,
                store=False,
                stop_filter=lambda x: not self.is_capturing
            )
        except Exception as e:
            print(f"Capture error: {e}")
        finally:
            self.is_capturing = False
            
    def stop_capture(self):
        """Stop packet capture."""
        if not self.is_capturing:
            print("Capture is not running")
            return
            
        print("Stopping packet capture...")
        self.is_capturing = False
        
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)
            
        print(f"Capture stopped. Total packets captured: {self.packet_count}")
        
    def get_capture_stats(self):
        """Get capture statistics."""
        protocol_stats = defaultdict(int)
        port_stats = defaultdict(int)
        
        for packet in self.packets:
            protocol_stats[packet['protocol']] += 1
            if packet['src_port']:
                port_stats[packet['src_port']] += 1
            if packet['dst_port']:
                port_stats[packet['dst_port']] += 1
                
        return {
            'total_packets': self.packet_count,
            'protocols': dict(protocol_stats),
            'top_ports': dict(sorted(port_stats.items(), key=lambda x: x[1], reverse=True)[:10])
        }
        
    def export_packets(self, filename, format='json'):
        """Export captured packets to file."""
        if not self.packets:
            print("No packets to export")
            return
            
        if format.lower() == 'json':
            # Convert datetime objects to strings for JSON serialization
            export_data = []
            for packet in self.packets:
                packet_copy = packet.copy()
                packet_copy['timestamp'] = packet_copy['timestamp'].isoformat()
                export_data.append(packet_copy)
                
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
                
        print(f"Exported {len(self.packets)} packets to {filename}")
        
    def get_available_interfaces(self):
        """Get list of available network interfaces."""
        try:
            interfaces = get_if_list()
            return interfaces
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            return []


if __name__ == "__main__":
    # Example usage
    capture = PacketCapture()
    
    def packet_callback(packet_info, raw_packet):
        print(f"[{packet_info['timestamp']}] {packet_info['protocol']} "
              f"{packet_info['src_ip']}:{packet_info['src_port']} -> "
              f"{packet_info['dst_ip']}:{packet_info['dst_port']} "
              f"({packet_info['size']} bytes)")
    
    capture.add_callback(packet_callback)
    
    try:
        capture.start_capture(count=10)
        time.sleep(10)
    except KeyboardInterrupt:
        pass
    finally:
        capture.stop_capture()
        stats = capture.get_capture_stats()
        print(f"\nCapture Statistics: {stats}")