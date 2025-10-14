"""
Advanced traffic filtering and analysis engine.
"""

import re
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict, deque
import threading
import time


class TrafficFilter:
    def __init__(self):
        self.filters = {}
        self.active_filters = []
        self.filter_stats = defaultdict(int)
        
    def add_mac_filter(self, mac_addresses):
        """Add MAC address filter."""
        if isinstance(mac_addresses, str):
            mac_addresses = [mac_addresses]
        
        normalized_macs = [mac.lower().replace('-', ':') for mac in mac_addresses]
        self.filters['mac'] = normalized_macs
        
    def add_ip_filter(self, ip_addresses):
        """Add IP address filter (supports individual IPs and CIDR ranges)."""
        if isinstance(ip_addresses, str):
            ip_addresses = [ip_addresses]
            
        parsed_ips = []
        for ip in ip_addresses:
            try:
                if '/' in ip:
                    # CIDR range
                    network = ipaddress.ip_network(ip, strict=False)
                    parsed_ips.append(network)
                else:
                    # Individual IP
                    parsed_ips.append(ipaddress.ip_address(ip))
            except ValueError as e:
                print(f"Invalid IP address/range: {ip} - {e}")
                
        self.filters['ip'] = parsed_ips
        
    def add_port_filter(self, ports):
        """Add port filter."""
        if isinstance(ports, (int, str)):
            ports = [int(ports)]
        elif isinstance(ports, str):
            # Support port ranges like "80-85"
            if '-' in ports:
                start, end = map(int, ports.split('-'))
                ports = list(range(start, end + 1))
            else:
                ports = [int(ports)]
                
        self.filters['port'] = ports
        
    def add_protocol_filter(self, protocols):
        """Add protocol filter."""
        if isinstance(protocols, str):
            protocols = [protocols]
            
        self.filters['protocol'] = [p.lower() for p in protocols]
        
    def add_size_filter(self, min_size=None, max_size=None):
        """Add packet size filter."""
        self.filters['size'] = {
            'min': min_size,
            'max': max_size
        }
        
    def add_payload_filter(self, patterns, case_sensitive=False):
        """Add payload content filter using regex patterns."""
        if isinstance(patterns, str):
            patterns = [patterns]
            
        compiled_patterns = []
        for pattern in patterns:
            flags = 0 if case_sensitive else re.IGNORECASE
            try:
                compiled_patterns.append(re.compile(pattern, flags))
            except re.error as e:
                print(f"Invalid regex pattern: {pattern} - {e}")
                
        self.filters['payload'] = compiled_patterns
        
    def clear_filters(self):
        """Clear all filters."""
        self.filters = {}
        
    def get_active_filters(self):
        """Get list of active filters."""
        return list(self.filters.keys())
        
    def matches_filter(self, packet_info, raw_packet=None):
        """Check if packet matches current filters."""
        if not self.filters:
            return True
            
        # MAC address filter
        if 'mac' in self.filters:
            src_mac = packet_info.get('src_mac', '').lower()
            dst_mac = packet_info.get('dst_mac', '').lower()
            
            if not any(mac in [src_mac, dst_mac] for mac in self.filters['mac']):
                self.filter_stats['mac_filtered'] += 1
                return False
                
        # IP address filter
        if 'ip' in self.filters:
            src_ip = packet_info.get('src_ip')
            dst_ip = packet_info.get('dst_ip')
            
            matched = False
            for filter_ip in self.filters['ip']:
                if isinstance(filter_ip, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                    # CIDR range
                    try:
                        if (src_ip and ipaddress.ip_address(src_ip) in filter_ip) or \
                           (dst_ip and ipaddress.ip_address(dst_ip) in filter_ip):
                            matched = True
                            break
                    except ValueError:
                        continue
                else:
                    # Individual IP
                    if str(filter_ip) in [src_ip, dst_ip]:
                        matched = True
                        break
                        
            if not matched:
                self.filter_stats['ip_filtered'] += 1
                return False
                
        # Port filter
        if 'port' in self.filters:
            src_port = packet_info.get('src_port')
            dst_port = packet_info.get('dst_port')
            
            if not any(port in [src_port, dst_port] for port in self.filters['port']):
                self.filter_stats['port_filtered'] += 1
                return False
                
        # Protocol filter
        if 'protocol' in self.filters:
            protocol = packet_info.get('protocol', '').lower()
            if protocol not in self.filters['protocol']:
                self.filter_stats['protocol_filtered'] += 1
                return False
                
        # Size filter
        if 'size' in self.filters:
            size = packet_info.get('size', 0)
            size_filter = self.filters['size']
            
            if size_filter['min'] is not None and size < size_filter['min']:
                self.filter_stats['size_filtered'] += 1
                return False
            if size_filter['max'] is not None and size > size_filter['max']:
                self.filter_stats['size_filtered'] += 1
                return False
                
        # Payload filter
        if 'payload' in self.filters and raw_packet:
            payload = bytes(raw_packet.payload) if hasattr(raw_packet, 'payload') else b''
            payload_str = payload.decode('utf-8', errors='ignore')
            
            matched = False
            for pattern in self.filters['payload']:
                if pattern.search(payload_str):
                    matched = True
                    break
                    
            if not matched:
                self.filter_stats['payload_filtered'] += 1
                return False
                
        self.filter_stats['passed'] += 1
        return True
        
    def get_filter_stats(self):
        """Get filtering statistics."""
        return dict(self.filter_stats)


class TrafficAnalyzer:
    def __init__(self, window_size=60):
        self.window_size = window_size  # seconds
        self.traffic_data = deque()
        self.connection_tracker = defaultdict(lambda: defaultdict(int))
        self.bandwidth_tracker = defaultdict(list)
        self.protocol_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.geo_stats = defaultdict(int)
        self.lock = threading.Lock()
        
    def add_packet(self, packet_info):
        """Add packet for analysis."""
        with self.lock:
            current_time = datetime.now()
            
            # Add to traffic data with timestamp
            packet_info['analysis_timestamp'] = current_time
            self.traffic_data.append(packet_info)
            
            # Clean old data outside window
            cutoff_time = current_time - timedelta(seconds=self.window_size)
            while self.traffic_data and self.traffic_data[0]['analysis_timestamp'] < cutoff_time:
                self.traffic_data.popleft()
                
            # Update statistics
            self._update_stats(packet_info)
            
    def _update_stats(self, packet_info):
        """Update various traffic statistics."""
        # Protocol statistics
        protocol = packet_info.get('protocol', 'Unknown')
        self.protocol_stats[protocol] += 1
        
        # Port statistics
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        if src_port:
            self.port_stats[src_port] += 1
        if dst_port:
            self.port_stats[dst_port] += 1
            
        # Connection tracking
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        if src_ip and dst_ip:
            connection_key = f"{src_ip}:{dst_ip}"
            self.connection_tracker[connection_key]['packets'] += 1
            self.connection_tracker[connection_key]['bytes'] += packet_info.get('size', 0)
            
        # Bandwidth tracking per IP
        packet_size = packet_info.get('size', 0)
        if src_ip:
            self.bandwidth_tracker[src_ip].append({
                'timestamp': packet_info['analysis_timestamp'],
                'bytes': packet_size,
                'direction': 'sent'
            })
        if dst_ip:
            self.bandwidth_tracker[dst_ip].append({
                'timestamp': packet_info['analysis_timestamp'],
                'bytes': packet_size,
                'direction': 'received'
            })
            
    def get_traffic_rate(self):
        """Get current traffic rate (packets per second)."""
        with self.lock:
            if not self.traffic_data:
                return 0
                
            current_time = datetime.now()
            one_second_ago = current_time - timedelta(seconds=1)
            
            recent_packets = sum(1 for packet in self.traffic_data 
                               if packet['analysis_timestamp'] >= one_second_ago)
            
            return recent_packets
            
    def get_bandwidth_usage(self, ip_address=None):
        """Get bandwidth usage statistics."""
        with self.lock:
            if ip_address:
                # Get bandwidth for specific IP
                ip_data = self.bandwidth_tracker.get(ip_address, [])
                total_sent = sum(data['bytes'] for data in ip_data if data['direction'] == 'sent')
                total_received = sum(data['bytes'] for data in ip_data if data['direction'] == 'received')
                
                return {
                    'ip': ip_address,
                    'bytes_sent': total_sent,
                    'bytes_received': total_received,
                    'total_bytes': total_sent + total_received
                }
            else:
                # Get overall bandwidth statistics
                total_bytes = sum(packet.get('size', 0) for packet in self.traffic_data)
                return {
                    'total_bytes': total_bytes,
                    'average_packet_size': total_bytes / len(self.traffic_data) if self.traffic_data else 0,
                    'packets_count': len(self.traffic_data)
                }
                
    def get_top_connections(self, limit=10):
        """Get top connections by packet count or bytes."""
        with self.lock:
            # Sort connections by packet count
            sorted_connections = sorted(
                self.connection_tracker.items(),
                key=lambda x: x[1]['packets'],
                reverse=True
            )
            
            return sorted_connections[:limit]
            
    def get_protocol_distribution(self):
        """Get protocol distribution statistics."""
        with self.lock:
            total_packets = sum(self.protocol_stats.values())
            if total_packets == 0:
                return {}
                
            distribution = {}
            for protocol, count in self.protocol_stats.items():
                distribution[protocol] = {
                    'count': count,
                    'percentage': (count / total_packets) * 100
                }
                
            return distribution
            
    def get_port_activity(self, limit=20):
        """Get most active ports."""
        with self.lock:
            sorted_ports = sorted(
                self.port_stats.items(),
                key=lambda x: x[1],
                reverse=True
            )
            
            return sorted_ports[:limit]
            
    def detect_anomalies(self):
        """Detect potential network anomalies."""
        anomalies = []
        
        with self.lock:
            # High traffic rate
            current_rate = self.get_traffic_rate()
            if current_rate > 1000:  # More than 1000 packets per second
                anomalies.append({
                    'type': 'high_traffic_rate',
                    'description': f'High traffic rate detected: {current_rate} packets/sec',
                    'severity': 'medium'
                })
                
            # Unusual port activity
            for port, count in self.port_stats.items():
                if port in [22, 23, 3389] and count > 100:  # SSH, Telnet, RDP
                    anomalies.append({
                        'type': 'unusual_port_activity',
                        'description': f'High activity on port {port}: {count} packets',
                        'severity': 'high'
                    })
                    
            # Large number of connections from single IP
            ip_connections = defaultdict(int)
            for connection_key in self.connection_tracker.keys():
                src_ip = connection_key.split(':')[0]
                ip_connections[src_ip] += 1
                
            for ip, conn_count in ip_connections.items():
                if conn_count > 50:
                    anomalies.append({
                        'type': 'high_connection_count',
                        'description': f'IP {ip} has {conn_count} active connections',
                        'severity': 'medium'
                    })
                    
        return anomalies
        
    def reset_stats(self):
        """Reset all statistics."""
        with self.lock:
            self.traffic_data.clear()
            self.connection_tracker.clear()
            self.bandwidth_tracker.clear()
            self.protocol_stats.clear()
            self.port_stats.clear()
            self.geo_stats.clear()


if __name__ == "__main__":
    # Example usage
    traffic_filter = TrafficFilter()
    analyzer = TrafficAnalyzer()
    
    # Set up some filters
    traffic_filter.add_mac_filter("00:11:22:33:44:55")
    traffic_filter.add_ip_filter("192.168.1.0/24")
    traffic_filter.add_port_filter([80, 443, 8080])
    traffic_filter.add_protocol_filter(["TCP", "UDP"])
    
    # Example packet
    packet_info = {
        'src_mac': '00:11:22:33:44:55',
        'dst_mac': '66:77:88:99:aa:bb',
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'src_port': 80,
        'dst_port': 443,
        'protocol': 'TCP',
        'size': 1500
    }
    
    # Test filtering
    if traffic_filter.matches_filter(packet_info):
        print("Packet matches filters")
        analyzer.add_packet(packet_info)
    else:
        print("Packet filtered out")
        
    # Show filter stats
    print("Filter stats:", traffic_filter.get_filter_stats())
    
    # Show analysis results
    print("Traffic rate:", analyzer.get_traffic_rate())
    print("Protocol distribution:", analyzer.get_protocol_distribution())