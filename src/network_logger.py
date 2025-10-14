"""
Logging and data export functionality for network monitoring.
"""

import json
import csv
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
import threading
from collections import deque


class NetworkLogger:
    def __init__(self, log_dir="logs", max_file_size=10*1024*1024):  # 10MB default
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.max_file_size = max_file_size
        
        # Set up logging
        self.setup_logging()
        
        # Database for structured data
        self.db_path = self.log_dir / "network_data.db"
        self.setup_database()
        
        # Buffer for batch operations
        self.packet_buffer = deque(maxlen=1000)
        self.device_buffer = deque(maxlen=100)
        self.app_buffer = deque(maxlen=100)
        self.buffer_lock = threading.Lock()
        
        # Auto-save timer
        self.auto_save_interval = 300  # 5 minutes
        self.last_save = datetime.now()
        
    def setup_logging(self):
        """Set up Python logging configuration."""
        # Create formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        simple_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Main application logger
        self.app_logger = logging.getLogger('NetworkMonitor')
        self.app_logger.setLevel(logging.INFO)
        
        # File handler for application logs
        app_log_path = self.log_dir / 'network_monitor.log'
        app_handler = logging.FileHandler(app_log_path)
        app_handler.setFormatter(detailed_formatter)
        self.app_logger.addHandler(app_handler)
        
        # Security events logger
        self.security_logger = logging.getLogger('Security')
        self.security_logger.setLevel(logging.WARNING)
        
        security_log_path = self.log_dir / 'security_events.log'
        security_handler = logging.FileHandler(security_log_path)
        security_handler.setFormatter(detailed_formatter)
        self.security_logger.addHandler(security_handler)
        
        # Traffic logger
        self.traffic_logger = logging.getLogger('Traffic')
        self.traffic_logger.setLevel(logging.INFO)
        
        traffic_log_path = self.log_dir / 'traffic.log' 
        traffic_handler = logging.FileHandler(traffic_log_path)
        traffic_handler.setFormatter(simple_formatter)
        self.traffic_logger.addHandler(traffic_handler)
        
    def setup_database(self):
        """Set up SQLite database for structured data storage."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Packets table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME,
                        src_mac TEXT,
                        dst_mac TEXT,
                        src_ip TEXT,
                        dst_ip TEXT,
                        src_port INTEGER,
                        dst_port INTEGER,
                        protocol TEXT,
                        size INTEGER,
                        applications TEXT,
                        raw_data BLOB
                    )
                ''')
                
                # Devices table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS devices (
                        mac_address TEXT PRIMARY KEY,
                        ip_addresses TEXT,
                        hostname TEXT,
                        vendor TEXT,
                        device_type TEXT,
                        first_seen DATETIME,
                        last_seen DATETIME,
                        packet_count INTEGER,
                        bytes_sent INTEGER,
                        bytes_received INTEGER
                    )
                ''')
                
                # Applications table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS applications (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME,
                        application TEXT,
                        packet_count INTEGER,
                        byte_count INTEGER,
                        connections INTEGER,
                        src_ip TEXT,
                        dst_ip TEXT
                    )
                ''')
                
                # Security events table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS security_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME,
                        event_type TEXT,
                        severity TEXT,
                        description TEXT,
                        src_ip TEXT,
                        dst_ip TEXT,
                        additional_data TEXT
                    )
                ''')
                
                # Create indexes for better performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_security_timestamp ON security_events(timestamp)')
                
                conn.commit()
                
        except Exception as e:
            self.app_logger.error(f"Database setup error: {e}")
            
    def log_packet(self, packet_info, raw_packet=None):
        """Log packet information."""
        try:
            # Add to buffer
            with self.buffer_lock:
                packet_data = packet_info.copy()
                if raw_packet:
                    packet_data['raw_data'] = bytes(raw_packet)
                self.packet_buffer.append(packet_data)
                
            # Log to text file for immediate visibility
            src = f"{packet_info.get('src_ip', 'N/A')}:{packet_info.get('src_port', '')}"
            dst = f"{packet_info.get('dst_ip', 'N/A')}:{packet_info.get('dst_port', '')}"
            protocol = packet_info.get('protocol', 'Unknown')
            size = packet_info.get('size', 0)
            
            self.traffic_logger.info(
                f"{protocol} {src} -> {dst} ({size}B)"
            )
            
            # Auto-save if buffer is full or time elapsed
            if len(self.packet_buffer) >= 100 or self._should_auto_save():
                self._flush_packet_buffer()
                
        except Exception as e:
            self.app_logger.error(f"Error logging packet: {e}")
            
    def log_device(self, device_id, device_info):
        """Log device information."""
        try:
            with self.buffer_lock:
                self.device_buffer.append((device_id, device_info.copy()))
                
            # Log device discovery
            self.app_logger.info(
                f"Device discovered: {device_id} - {device_info.get('hostname', 'Unknown')} "
                f"({device_info.get('vendor', 'Unknown')})"
            )
            
            if len(self.device_buffer) >= 10 or self._should_auto_save():
                self._flush_device_buffer()
                
        except Exception as e:
            self.app_logger.error(f"Error logging device: {e}")
            
    def log_application_activity(self, app_name, stats, src_ip=None, dst_ip=None):
        """Log application activity."""
        try:
            app_data = {
                'timestamp': datetime.now(),
                'application': app_name,
                'packet_count': stats.get('packet_count', 0),
                'byte_count': stats.get('byte_count', 0),
                'connections': len(stats.get('connections', [])),
                'src_ip': src_ip,
                'dst_ip': dst_ip
            }
            
            with self.buffer_lock:
                self.app_buffer.append(app_data)
                
            if len(self.app_buffer) >= 20 or self._should_auto_save():
                self._flush_app_buffer()
                
        except Exception as e:
            self.app_logger.error(f"Error logging application activity: {e}")
            
    def log_security_event(self, event_type, severity, description, src_ip=None, dst_ip=None, additional_data=None):
        """Log security events."""
        try:
            timestamp = datetime.now()
            
            # Log to security logger
            self.security_logger.warning(
                f"{event_type} - {severity} - {description} "
                f"(src: {src_ip}, dst: {dst_ip})"
            )
            
            # Store in database immediately for security events
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO security_events 
                    (timestamp, event_type, severity, description, src_ip, dst_ip, additional_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    timestamp,
                    event_type,
                    severity,
                    description,
                    src_ip,
                    dst_ip,
                    json.dumps(additional_data) if additional_data else None
                ))
                conn.commit()
                
        except Exception as e:
            self.app_logger.error(f"Error logging security event: {e}")
            
    def _should_auto_save(self):
        """Check if auto-save should be triggered."""
        return (datetime.now() - self.last_save).seconds >= self.auto_save_interval
        
    def _flush_packet_buffer(self):
        """Flush packet buffer to database."""
        try:
            with self.buffer_lock:
                if not self.packet_buffer:
                    return
                    
                packets_to_save = list(self.packet_buffer)
                self.packet_buffer.clear()
                
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for packet in packets_to_save:
                    applications = json.dumps(packet.get('applications', []))
                    raw_data = packet.get('raw_data')
                    
                    cursor.execute('''
                        INSERT INTO packets 
                        (timestamp, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, 
                         protocol, size, applications, raw_data)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        packet.get('timestamp', datetime.now()),
                        packet.get('src_mac'),
                        packet.get('dst_mac'),
                        packet.get('src_ip'),
                        packet.get('dst_ip'),
                        packet.get('src_port'),
                        packet.get('dst_port'),
                        packet.get('protocol'),
                        packet.get('size', 0),
                        applications,
                        raw_data
                    ))
                    
                conn.commit()
                self.last_save = datetime.now()
                
        except Exception as e:
            self.app_logger.error(f"Error flushing packet buffer: {e}")
            
    def _flush_device_buffer(self):
        """Flush device buffer to database."""
        try:
            with self.buffer_lock:
                if not self.device_buffer:
                    return
                    
                devices_to_save = list(self.device_buffer)
                self.device_buffer.clear()
                
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for device_id, device_info in devices_to_save:
                    # Convert lists and sets to JSON strings
                    ip_addresses = json.dumps(device_info.get('ip_addresses', []))
                    
                    cursor.execute('''
                        INSERT OR REPLACE INTO devices 
                        (mac_address, ip_addresses, hostname, vendor, device_type, 
                         first_seen, last_seen, packet_count, bytes_sent, bytes_received)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        device_id,
                        ip_addresses,
                        device_info.get('hostname'),
                        device_info.get('vendor'),
                        device_info.get('device_type'),
                        device_info.get('first_seen'),
                        device_info.get('last_seen'),
                        device_info.get('packet_count', 0),
                        device_info.get('bytes_sent', 0),
                        device_info.get('bytes_received', 0)
                    ))
                    
                conn.commit()
                
        except Exception as e:
            self.app_logger.error(f"Error flushing device buffer: {e}")
            
    def _flush_app_buffer(self):
        """Flush application buffer to database."""
        try:
            with self.buffer_lock:
                if not self.app_buffer:
                    return
                    
                apps_to_save = list(self.app_buffer)
                self.app_buffer.clear()
                
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for app_data in apps_to_save:
                    cursor.execute('''
                        INSERT INTO applications 
                        (timestamp, application, packet_count, byte_count, connections, src_ip, dst_ip)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        app_data['timestamp'],
                        app_data['application'],
                        app_data['packet_count'],
                        app_data['byte_count'],
                        app_data['connections'],
                        app_data.get('src_ip'),
                        app_data.get('dst_ip')
                    ))
                    
                conn.commit()
                
        except Exception as e:
            self.app_logger.error(f"Error flushing application buffer: {e}")
            
    def flush_all_buffers(self):
        """Flush all buffers to database."""
        self._flush_packet_buffer()
        self._flush_device_buffer()
        self._flush_app_buffer()
        
    def export_to_json(self, filename, data_type='packets', time_range=None):
        """Export data to JSON format."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if data_type == 'packets':
                    query = 'SELECT * FROM packets'
                    if time_range:
                        query += f' WHERE timestamp >= ? AND timestamp <= ?'
                        cursor.execute(query, time_range)
                    else:
                        cursor.execute(query)
                        
                elif data_type == 'devices':
                    cursor.execute('SELECT * FROM devices')
                    
                elif data_type == 'applications':
                    query = 'SELECT * FROM applications'
                    if time_range:
                        query += f' WHERE timestamp >= ? AND timestamp <= ?'
                        cursor.execute(query, time_range)
                    else:
                        cursor.execute(query)
                        
                elif data_type == 'security':
                    query = 'SELECT * FROM security_events'
                    if time_range:
                        query += f' WHERE timestamp >= ? AND timestamp <= ?'
                        cursor.execute(query, time_range)
                    else:
                        cursor.execute(query)
                
                # Get column names
                columns = [desc[0] for desc in cursor.description]
                
                # Fetch data and convert to dictionaries
                rows = cursor.fetchall()
                data = []
                for row in rows:
                    row_dict = dict(zip(columns, row))
                    # Convert binary data to base64 if present
                    if 'raw_data' in row_dict and row_dict['raw_data']:
                        import base64
                        row_dict['raw_data'] = base64.b64encode(row_dict['raw_data']).decode('utf-8')
                    data.append(row_dict)
                
                # Write to JSON file
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2, default=str)
                    
                self.app_logger.info(f"Exported {len(data)} {data_type} records to {filename}")
                return len(data)
                
        except Exception as e:
            self.app_logger.error(f"Error exporting to JSON: {e}")
            return 0
            
    def export_to_csv(self, filename, data_type='packets', time_range=None):
        """Export data to CSV format."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if data_type == 'packets':
                    query = '''SELECT timestamp, src_ip, dst_ip, src_port, dst_port, 
                              protocol, size, applications FROM packets'''
                    if time_range:
                        query += ' WHERE timestamp >= ? AND timestamp <= ?'
                        cursor.execute(query, time_range)
                    else:
                        cursor.execute(query)
                        
                elif data_type == 'devices':
                    cursor.execute('''SELECT mac_address, ip_addresses, hostname, vendor, 
                                     device_type, first_seen, last_seen, packet_count, 
                                     bytes_sent, bytes_received FROM devices''')
                    
                elif data_type == 'applications':
                    query = '''SELECT timestamp, application, packet_count, byte_count, 
                              connections, src_ip, dst_ip FROM applications'''
                    if time_range:
                        query += ' WHERE timestamp >= ? AND timestamp <= ?'
                        cursor.execute(query, time_range)
                    else:
                        cursor.execute(query)
                
                # Get column names and data
                columns = [desc[0] for desc in cursor.description]
                rows = cursor.fetchall()
                
                # Write to CSV file
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(columns)
                    writer.writerows(rows)
                    
                self.app_logger.info(f"Exported {len(rows)} {data_type} records to {filename}")
                return len(rows)
                
        except Exception as e:
            self.app_logger.error(f"Error exporting to CSV: {e}")
            return 0
            
    def get_statistics(self, time_range=None):
        """Get database statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                stats = {}
                
                # Packet statistics
                if time_range:
                    cursor.execute('SELECT COUNT(*) FROM packets WHERE timestamp >= ? AND timestamp <= ?', time_range)
                else:
                    cursor.execute('SELECT COUNT(*) FROM packets')
                stats['total_packets'] = cursor.fetchone()[0]
                
                # Device statistics
                cursor.execute('SELECT COUNT(*) FROM devices')
                stats['total_devices'] = cursor.fetchone()[0]
                
                # Application statistics
                if time_range:
                    cursor.execute('SELECT COUNT(DISTINCT application) FROM applications WHERE timestamp >= ? AND timestamp <= ?', time_range)
                else:
                    cursor.execute('SELECT COUNT(DISTINCT application) FROM applications')
                stats['unique_applications'] = cursor.fetchone()[0]
                
                # Security event statistics
                if time_range:
                    cursor.execute('SELECT COUNT(*) FROM security_events WHERE timestamp >= ? AND timestamp <= ?', time_range)
                else:
                    cursor.execute('SELECT COUNT(*) FROM security_events')
                stats['security_events'] = cursor.fetchone()[0]
                
                # Database size
                stats['database_size'] = os.path.getsize(self.db_path)
                
                return stats
                
        except Exception as e:
            self.app_logger.error(f"Error getting statistics: {e}")
            return {}
            
    def cleanup_old_data(self, days_to_keep=30):
        """Remove old data from database."""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Remove old packets
                cursor.execute('DELETE FROM packets WHERE timestamp < ?', (cutoff_date,))
                packets_removed = cursor.rowcount
                
                # Remove old application data
                cursor.execute('DELETE FROM applications WHERE timestamp < ?', (cutoff_date,))
                apps_removed = cursor.rowcount
                
                # Remove old security events (keep longer)
                old_security_cutoff = datetime.now() - timedelta(days=days_to_keep * 2)
                cursor.execute('DELETE FROM security_events WHERE timestamp < ?', (old_security_cutoff,))
                security_removed = cursor.rowcount
                
                # Update device last_seen but don't remove devices
                cursor.execute('UPDATE devices SET last_seen = NULL WHERE last_seen < ?', (cutoff_date,))
                
                conn.commit()
                
                # Vacuum database to reclaim space
                cursor.execute('VACUUM')
                
                self.app_logger.info(
                    f"Cleanup completed: {packets_removed} packets, {apps_removed} app records, "
                    f"{security_removed} security events removed"
                )
                
                return {
                    'packets_removed': packets_removed,
                    'apps_removed': apps_removed,
                    'security_removed': security_removed
                }
                
        except Exception as e:
            self.app_logger.error(f"Error during cleanup: {e}")
            return {}


if __name__ == "__main__":
    # Example usage
    logger = NetworkLogger()
    
    # Example packet
    packet_info = {
        'timestamp': datetime.now(),
        'src_mac': '00:11:22:33:44:55',
        'dst_mac': '66:77:88:99:aa:bb',
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'src_port': 443,
        'dst_port': 54321,
        'protocol': 'TCP',
        'size': 1500,
        'applications': ['HTTPS']
    }
    
    # Log packet
    logger.log_packet(packet_info)
    
    # Log security event
    logger.log_security_event(
        'suspicious_traffic',
        'medium',
        'High number of connections from single IP',
        src_ip='192.168.1.100'
    )
    
    # Flush buffers
    logger.flush_all_buffers()
    
    # Export data
    logger.export_to_json('network_data.json', 'packets')
    logger.export_to_csv('devices.csv', 'devices')
    
    # Get statistics
    stats = logger.get_statistics()
    print(f"Database statistics: {stats}")
    
    # Cleanup old data
    cleanup_stats = logger.cleanup_old_data(days_to_keep=7)
    print(f"Cleanup results: {cleanup_stats}")