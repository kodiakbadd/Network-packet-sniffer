"""
Application traffic identification and deep packet inspection.
"""

import re
import struct
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import json


class ApplicationIdentifier:
    def __init__(self):
        self.port_mappings = self._load_port_mappings()
        self.signature_patterns = self._load_signature_patterns()
        self.application_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'connections': set(),
            'first_seen': None,
            'last_seen': None
        })
        self.deep_inspection_enabled = True
        
    def _load_port_mappings(self):
        """Load common port to application mappings."""
        return {
            # Web and HTTP
            80: 'HTTP',
            443: 'HTTPS',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            8000: 'HTTP-Dev',
            3000: 'HTTP-Dev',
            
            # Email
            25: 'SMTP',
            110: 'POP3',
            143: 'IMAP',
            993: 'IMAPS',
            995: 'POP3S',
            587: 'SMTP-Sub',
            
            # File Transfer
            21: 'FTP',
            22: 'SSH/SFTP',
            990: 'FTPS',
            
            # Remote Access
            23: 'Telnet',
            3389: 'RDP',
            5900: 'VNC',
            
            # DNS
            53: 'DNS',
            
            # Network Services
            67: 'DHCP-Server',
            68: 'DHCP-Client',
            69: 'TFTP',
            161: 'SNMP',
            162: 'SNMP-Trap',
            
            # Database
            1433: 'SQL Server',
            1521: 'Oracle DB',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB',
            
            # Messaging
            1863: 'MSN Messenger',
            5222: 'XMPP',
            6667: 'IRC',
            
            # Gaming
            27015: 'Steam',
            7777: 'Games',
            
            # Media Streaming
            554: 'RTSP',
            1935: 'RTMP',
            
            # VPN
            1194: 'OpenVPN',
            500: 'IPSec',
            4500: 'IPSec-NAT',
            
            # P2P
            6881: 'BitTorrent',
            6969: 'BitTorrent-Tracker',
            4662: 'eMule',
            
            # Cloud Services
            5938: 'TeamViewer',
            
            # Development
            9200: 'Elasticsearch',
            8086: 'InfluxDB',
            2375: 'Docker',
            6443: 'Kubernetes',
            
            # Social Media / Messaging Apps
            5242: 'Viber',
            50318: 'WhatsApp Voice',
            
            # Video Conferencing
            19302: 'WebRTC',
            3478: 'STUN/TURN',
        }
        
    def _load_signature_patterns(self):
        """Load application signature patterns for deep packet inspection."""
        return {
            'HTTP': [
                re.compile(rb'GET\s+/.+\s+HTTP/1\.[01]', re.IGNORECASE),
                re.compile(rb'POST\s+/.+\s+HTTP/1\.[01]', re.IGNORECASE),
                re.compile(rb'HTTP/1\.[01]\s+\d{3}', re.IGNORECASE),
                re.compile(rb'User-Agent:', re.IGNORECASE),
                re.compile(rb'Content-Type:', re.IGNORECASE),
            ],
            'HTTPS': [
                re.compile(rb'\x16\x03[\x01-\x04]'),  # TLS handshake
                re.compile(rb'\x14\x03[\x01-\x04]'),  # TLS change cipher spec
                re.compile(rb'\x15\x03[\x01-\x04]'),  # TLS alert
                re.compile(rb'\x17\x03[\x01-\x04]'),  # TLS application data
            ],
            'SSH': [
                re.compile(rb'^SSH-2\.0-', re.IGNORECASE),
                re.compile(rb'^SSH-1\.', re.IGNORECASE),
            ],
            'FTP': [
                re.compile(rb'^220\s+.*FTP', re.IGNORECASE),
                re.compile(rb'^USER\s+', re.IGNORECASE),
                re.compile(rb'^PASS\s+', re.IGNORECASE),
                re.compile(rb'^RETR\s+', re.IGNORECASE),
                re.compile(rb'^STOR\s+', re.IGNORECASE),
            ],
            'SMTP': [
                re.compile(rb'^220\s+.*SMTP', re.IGNORECASE),
                re.compile(rb'^HELO\s+', re.IGNORECASE),
                re.compile(rb'^EHLO\s+', re.IGNORECASE),
                re.compile(rb'^MAIL\s+FROM:', re.IGNORECASE),
                re.compile(rb'^RCPT\s+TO:', re.IGNORECASE),
            ],
            'DNS': [
                # DNS query/response patterns
                re.compile(rb'.{2}\x01\x00'),  # Standard query
                re.compile(rb'.{2}\x81\x80'),  # Standard response
            ],
            'BitTorrent': [
                re.compile(rb'\x13BitTorrent protocol'),
                re.compile(rb'd\d+:announce\d+:'),
                re.compile(rb'announce'),
            ],
            'Skype': [
                re.compile(rb'\x17\x03[\x01-\x03].{2}\x16\x03[\x01-\x03]'),
            ],
            'WhatsApp': [
                re.compile(rb'WA', re.IGNORECASE),
                re.compile(rb'WhatsApp', re.IGNORECASE),
            ],
            'Telegram': [
                re.compile(rb'MTProto', re.IGNORECASE),
            ],
            'Discord': [
                re.compile(rb'discord', re.IGNORECASE),
                re.compile(rb'cdn\.discordapp\.com', re.IGNORECASE),
            ],
            'YouTube': [
                re.compile(rb'youtube\.com', re.IGNORECASE),
                re.compile(rb'googlevideo\.com', re.IGNORECASE),
                re.compile(rb'ytimg\.com', re.IGNORECASE),
            ],
            'Netflix': [
                re.compile(rb'netflix\.com', re.IGNORECASE),
                re.compile(rb'nflxvideo\.net', re.IGNORECASE),
            ],
            'Spotify': [
                re.compile(rb'spotify\.com', re.IGNORECASE),
                re.compile(rb'scdn\.co', re.IGNORECASE),
            ],
            'Steam': [
                re.compile(rb'steampowered\.com', re.IGNORECASE),
                re.compile(rb'steamcontent\.com', re.IGNORECASE),
            ],
            'Zoom': [
                re.compile(rb'zoom\.us', re.IGNORECASE),
                re.compile(rb'zoom\.com', re.IGNORECASE),
            ],
            'Teams': [
                re.compile(rb'teams\.microsoft\.com', re.IGNORECASE),
                re.compile(rb'skype\.com', re.IGNORECASE),
            ],
            'Facebook': [
                re.compile(rb'facebook\.com', re.IGNORECASE),
                re.compile(rb'fbcdn\.net', re.IGNORECASE),
                re.compile(rb'fb\.com', re.IGNORECASE),
            ],
            'Twitter': [
                re.compile(rb'twitter\.com', re.IGNORECASE),
                re.compile(rb'twimg\.com', re.IGNORECASE),
            ],
            'Instagram': [
                re.compile(rb'instagram\.com', re.IGNORECASE),
                re.compile(rb'cdninstagram\.com', re.IGNORECASE),
            ],
            'TikTok': [
                re.compile(rb'tiktok\.com', re.IGNORECASE),
                re.compile(rb'muscdn\.com', re.IGNORECASE),
            ]
        }
        
    def identify_application(self, packet_info, payload=None):
        """Identify application based on packet information and payload."""
        applications = set()
        
        # Port-based identification
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        
        if src_port in self.port_mappings:
            applications.add(self.port_mappings[src_port])
        if dst_port in self.port_mappings:
            applications.add(self.port_mappings[dst_port])
            
        # Deep packet inspection
        if self.deep_inspection_enabled and payload:
            dpi_apps = self._deep_packet_inspection(payload)
            applications.update(dpi_apps)
            
        # Hostname-based identification
        hostname_apps = self._identify_by_hostname(packet_info)
        applications.update(hostname_apps)
        
        # Protocol-specific identification
        protocol_apps = self._identify_by_protocol(packet_info)
        applications.update(protocol_apps)
        
        # If no specific application identified, use generic categories
        if not applications:
            applications.add(self._get_generic_category(packet_info))
            
        return list(applications)
        
    def _deep_packet_inspection(self, payload):
        """Perform deep packet inspection to identify applications."""
        identified_apps = []
        
        if not payload:
            return identified_apps
            
        # Convert to bytes if needed
        if isinstance(payload, str):
            payload = payload.encode('utf-8', errors='ignore')
        elif hasattr(payload, '__bytes__'):
            payload = bytes(payload)
            
        # Check against signature patterns
        for app, patterns in self.signature_patterns.items():
            for pattern in patterns:
                if pattern.search(payload):
                    identified_apps.append(app)
                    break
                    
        return identified_apps
        
    def _identify_by_hostname(self, packet_info):
        """Identify applications based on hostname/domain patterns."""
        applications = []
        
        # This would require DNS resolution or SNI inspection
        # For now, we'll implement basic domain matching if available
        
        return applications
        
    def _identify_by_protocol(self, packet_info):
        """Identify applications based on protocol characteristics."""
        applications = []
        protocol = packet_info.get('protocol', '').upper()
        src_port = packet_info.get('src_port', 0)
        dst_port = packet_info.get('dst_port', 0)
        
        # Gaming traffic patterns
        if protocol == 'UDP' and (src_port > 27000 or dst_port > 27000):
            if any(port in [src_port, dst_port] for port in range(27000, 28000)):
                applications.append('Gaming')
                
        # Video streaming patterns (high bandwidth UDP)
        if protocol == 'UDP' and packet_info.get('size', 0) > 1000:
            applications.append('Video Streaming')
            
        # VoIP patterns
        if protocol == 'UDP' and any(port in [src_port, dst_port] for port in [5060, 5061]):
            applications.append('VoIP')
            
        return applications
        
    def _get_generic_category(self, packet_info):
        """Get generic application category when specific app can't be identified."""
        protocol = packet_info.get('protocol', '').upper()
        src_port = packet_info.get('src_port', 0)
        dst_port = packet_info.get('dst_port', 0)
        
        # Web traffic
        if any(port in [src_port, dst_port] for port in [80, 443, 8080, 8443]):
            return 'Web Browsing'
            
        # Email ports
        if any(port in [src_port, dst_port] for port in [25, 110, 143, 993, 995, 587]):
            return 'Email'
            
        # File transfer
        if any(port in [src_port, dst_port] for port in [21, 22, 990]):
            return 'File Transfer'
            
        # High ports might be P2P or custom applications
        if src_port > 49152 or dst_port > 49152:
            return 'P2P/Custom'
            
        # System/Network services
        if any(port in [src_port, dst_port] for port in [53, 67, 68, 123, 161]):
            return 'System Services'
            
        return 'Unknown'
        
    def update_application_stats(self, applications, packet_info):
        """Update statistics for identified applications."""
        timestamp = datetime.now()
        packet_size = packet_info.get('size', 0)
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        
        for app in applications:
            stats = self.application_stats[app]
            stats['packet_count'] += 1
            stats['byte_count'] += packet_size
            
            if src_ip and dst_ip:
                stats['connections'].add(f"{src_ip}:{dst_ip}")
                
            if stats['first_seen'] is None:
                stats['first_seen'] = timestamp
            stats['last_seen'] = timestamp
            
    def get_application_stats(self, time_window=None):
        """Get application usage statistics."""
        if time_window:
            # Filter by time window
            cutoff_time = datetime.now() - timedelta(seconds=time_window)
            filtered_stats = {}
            
            for app, stats in self.application_stats.items():
                if stats['last_seen'] and stats['last_seen'] >= cutoff_time:
                    filtered_stats[app] = stats.copy()
                    filtered_stats[app]['connections'] = len(stats['connections'])
                    
            return filtered_stats
        else:
            # Return all stats
            result = {}
            for app, stats in self.application_stats.items():
                result[app] = stats.copy()
                result[app]['connections'] = len(stats['connections'])
                
            return result
            
    def get_top_applications(self, metric='byte_count', limit=10):
        """Get top applications by specified metric."""
        sorted_apps = sorted(
            self.application_stats.items(),
            key=lambda x: x[1].get(metric, 0),
            reverse=True
        )
        
        return sorted_apps[:limit]
        
    def get_application_bandwidth(self, time_window=300):
        """Get bandwidth usage per application in the last time window (seconds)."""
        cutoff_time = datetime.now() - timedelta(seconds=time_window)
        bandwidth_stats = {}
        
        for app, stats in self.application_stats.items():
            if stats['last_seen'] and stats['last_seen'] >= cutoff_time:
                bandwidth_stats[app] = {
                    'bytes_per_second': stats['byte_count'] / time_window,
                    'packets_per_second': stats['packet_count'] / time_window,
                    'total_bytes': stats['byte_count'],
                    'total_packets': stats['packet_count']
                }
                
        return bandwidth_stats
        
    def detect_suspicious_applications(self):
        """Detect potentially suspicious application activity."""
        suspicious = []
        
        # Look for applications using non-standard ports
        for app, stats in self.application_stats.items():
            if app == 'Unknown' and stats['packet_count'] > 100:
                suspicious.append({
                    'application': app,
                    'reason': 'High traffic from unknown application',
                    'packet_count': stats['packet_count'],
                    'byte_count': stats['byte_count']
                })
                
            # Check for applications with unusual traffic patterns
            if stats['packet_count'] > 10000 and app not in ['HTTP', 'HTTPS', 'DNS']:
                suspicious.append({
                    'application': app,
                    'reason': 'Unusually high packet count',
                    'packet_count': stats['packet_count']
                })
                
        return suspicious
        
    def export_application_data(self, filename):
        """Export application statistics to JSON file."""
        export_data = {}
        
        for app, stats in self.application_stats.items():
            export_stats = stats.copy()
            # Convert sets and datetime objects for JSON serialization
            export_stats['connections'] = list(stats['connections'])
            if stats['first_seen']:
                export_stats['first_seen'] = stats['first_seen'].isoformat()
            if stats['last_seen']:
                export_stats['last_seen'] = stats['last_seen'].isoformat()
                
            export_data[app] = export_stats
            
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
            
    def reset_stats(self):
        """Reset all application statistics."""
        self.application_stats.clear()


if __name__ == "__main__":
    # Example usage
    app_identifier = ApplicationIdentifier()
    
    # Example packet
    packet_info = {
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'src_port': 443,
        'dst_port': 45678,
        'protocol': 'TCP',
        'size': 1500
    }
    
    # Example HTTP payload
    http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n"
    
    # Identify application
    applications = app_identifier.identify_application(packet_info, http_payload)
    print(f"Identified applications: {applications}")
    
    # Update stats
    app_identifier.update_application_stats(applications, packet_info)
    
    # Get statistics
    stats = app_identifier.get_application_stats()
    print(f"Application stats: {stats}")
    
    # Get top applications
    top_apps = app_identifier.get_top_applications()
    print(f"Top applications: {top_apps}")