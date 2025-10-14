#!/usr/bin/env python3
"""
Network Packet Sniffer and Monitor - Main Application

A comprehensive network monitoring tool that provides:
- Real-time packet capture and analysis
- Device identification and tracking
- Application traffic analysis
- Security event detection
- Data export and logging capabilities

Author: Network Monitor
License: MIT
"""

import sys
import os
import signal
import argparse
from pathlib import Path
from datetime import datetime

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

try:
    from src.packet_capture import PacketCapture
    from src.device_tracker import DeviceTracker
    from src.traffic_filter import TrafficFilter, TrafficAnalyzer
    from src.app_identifier import ApplicationIdentifier
    from src.network_ui import NetworkMonitorUI, create_argument_parser
    from src.network_logger import NetworkLogger
except ImportError as e:
    print(f"Error importing required modules: {e}")
    print("\nPlease ensure all dependencies are installed:")
    print("pip install -r requirements.txt")
    print("\nAlso make sure you're running with administrator/root privileges.")
    sys.exit(1)


class NetworkMonitor:
    def __init__(self, args):
        self.args = args
        self.running = False
        
        # Initialize components
        print("Initializing network monitor components...")
        
        self.packet_capture = PacketCapture(interface=args.interface)
        self.device_tracker = DeviceTracker()
        self.traffic_filter = TrafficFilter()
        self.traffic_analyzer = TrafficAnalyzer()
        self.app_identifier = ApplicationIdentifier()
        self.logger = NetworkLogger(log_dir=args.log_dir if hasattr(args, 'log_dir') else "logs")
        
        # Set up filters based on command line arguments
        self._setup_filters()
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Configure UI if not in headless mode
        if not getattr(args, 'headless', False):
            self.ui = NetworkMonitorUI(
                self.packet_capture, 
                self.device_tracker, 
                self.traffic_filter, 
                self.app_identifier
            )
            self.ui.display_mode = args.mode
            if hasattr(args, 'refresh_rate'):
                self.ui.refresh_rate = args.refresh_rate
        else:
            self.ui = None
            
    def _setup_filters(self):
        """Set up traffic filters based on command line arguments."""
        if self.args.mac:
            self.traffic_filter.add_mac_filter(self.args.mac)
            print(f"Added MAC filter: {self.args.mac}")
            
        if self.args.ip:
            self.traffic_filter.add_ip_filter(self.args.ip)
            print(f"Added IP filter: {self.args.ip}")
            
        if self.args.port:
            if ',' in self.args.port:
                ports = [int(p.strip()) for p in self.args.port.split(',')]
            elif '-' in self.args.port:
                start, end = map(int, self.args.port.split('-'))
                ports = list(range(start, end + 1))
            else:
                ports = [int(self.args.port)]
            self.traffic_filter.add_port_filter(ports)
            print(f"Added port filter: {ports}")
            
        if self.args.protocol:
            self.traffic_filter.add_protocol_filter(self.args.protocol)
            print(f"Added protocol filter: {self.args.protocol}")
            
        # Advanced filters
        if hasattr(self.args, 'min_size') and self.args.min_size:
            self.traffic_filter.add_size_filter(min_size=self.args.min_size)
        if hasattr(self.args, 'max_size') and self.args.max_size:
            self.traffic_filter.add_size_filter(max_size=self.args.max_size)
            
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        print(f"\nReceived signal {signum}, shutting down gracefully...")
        self.stop()
        
    def packet_callback(self, packet_info, raw_packet):
        """Main packet processing callback."""
        try:
            # Apply filters
            if not self.traffic_filter.matches_filter(packet_info, raw_packet):
                return
                
            # Add to traffic analyzer
            self.traffic_analyzer.add_packet(packet_info)
            
            # Identify applications
            payload = None
            if hasattr(raw_packet, 'payload'):
                payload = bytes(raw_packet.payload)
                
            applications = self.app_identifier.identify_application(packet_info, payload)
            packet_info['applications'] = applications
            
            # Update application stats
            self.app_identifier.update_application_stats(applications, packet_info)
            
            # Update device tracker
            src_mac = packet_info.get('src_mac')
            dst_mac = packet_info.get('dst_mac')
            src_ip = packet_info.get('src_ip')
            dst_ip = packet_info.get('dst_ip')
            
            if src_mac and src_ip:
                self.device_tracker.add_device_observation(src_mac, src_ip, packet_info)
            if dst_mac and dst_ip and dst_mac != src_mac:
                self.device_tracker.add_device_observation(dst_mac, dst_ip, packet_info)
                
            # Log packet
            self.logger.log_packet(packet_info, raw_packet)
            
            # Check for security anomalies
            self._check_security_anomalies(packet_info)
            
        except Exception as e:
            print(f"Error processing packet: {e}")
            
    def _check_security_anomalies(self, packet_info):
        """Check for potential security issues."""
        # Check for port scanning
        dst_port = packet_info.get('dst_port')
        if dst_port and dst_port in [22, 23, 3389, 135, 445]:
            src_ip = packet_info.get('src_ip')
            if src_ip:
                # Log potential security event
                self.logger.log_security_event(
                    'port_scan_attempt',
                    'medium',
                    f'Connection attempt to sensitive port {dst_port}',
                    src_ip=src_ip,
                    additional_data={'port': dst_port, 'protocol': packet_info.get('protocol')}
                )
                
        # Check for unusual traffic patterns
        anomalies = self.traffic_analyzer.detect_anomalies()
        for anomaly in anomalies:
            self.logger.log_security_event(
                anomaly['type'],
                anomaly['severity'],
                anomaly['description']
            )
            
    def device_discovery_callback(self, device_id, device_info):
        """Callback for new device discoveries."""
        self.logger.log_device(device_id, device_info)
        
    def start(self):
        """Start the network monitor."""
        print("Starting network monitor...")
        self.running = True
        
        try:
            # Perform initial network scan if requested
            if self.args.scan_network:
                print("Scanning local network for devices...")
                self.device_tracker.scan_local_network()
                
                # Log discovered devices
                devices = self.device_tracker.get_all_devices()
                for device_id, device_info in devices.items():
                    self.logger.log_device(device_id, device_info)
                    
                print(f"Found {len(devices)} devices on the network")
                
            # Register callbacks
            self.packet_capture.add_callback(self.packet_callback)
            
            # Start packet capture
            print(f"Starting packet capture on interface: {self.args.interface or 'default'}")
            self.packet_capture.start_capture(
                count=self.args.max_packets,
                timeout=self.args.timeout
            )
            
            # Start UI or run in headless mode
            if self.ui:
                self.ui.start()
            else:
                # Headless mode - just keep running
                print("Running in headless mode. Press Ctrl+C to stop.")
                try:
                    while self.running and self.packet_capture.is_capturing:
                        import time
                        time.sleep(1)
                except KeyboardInterrupt:
                    pass
                    
        except KeyboardInterrupt:
            print("\nStopping due to user interrupt...")
        except Exception as e:
            print(f"Error during execution: {e}")
        finally:
            self.stop()
            
    def stop(self):
        """Stop the network monitor."""
        if not self.running:
            return
            
        print("Stopping network monitor...")
        self.running = False
        
        # Stop packet capture
        self.packet_capture.stop_capture()
        
        # Stop UI
        if self.ui:
            self.ui.stop()
            
        # Flush all logged data
        print("Saving captured data...")
        self.logger.flush_all_buffers()
        
        # Export data if requested
        self._export_data()
        
        # Print final statistics
        self._print_final_stats()
        
        print("Network monitor stopped.")
        
    def _export_data(self):
        """Export data based on command line arguments."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        try:
            if self.args.export_devices:
                filename = self.args.export_devices
                if not filename.endswith('.json'):
                    filename = f"devices_{timestamp}.json"
                self.device_tracker.export_devices(filename)
                
            if self.args.export_apps:
                filename = self.args.export_apps
                if not filename.endswith('.json'):
                    filename = f"applications_{timestamp}.json"
                self.app_identifier.export_application_data(filename)
                
            # Export additional data types if specified
            if hasattr(self.args, 'export_packets') and self.args.export_packets:
                filename = f"packets_{timestamp}.json"
                self.logger.export_to_json(filename, 'packets')
                
            if hasattr(self.args, 'export_security') and self.args.export_security:
                filename = f"security_events_{timestamp}.json"
                self.logger.export_to_json(filename, 'security')
                
        except Exception as e:
            print(f"Error exporting data: {e}")
            
    def _print_final_stats(self):
        """Print final statistics."""
        try:
            print("\n" + "="*60)
            print("FINAL STATISTICS")
            print("="*60)
            
            # Capture statistics
            capture_stats = self.packet_capture.get_capture_stats()
            print(f"Total packets captured: {capture_stats.get('total_packets', 0)}")
            
            # Device statistics
            device_summary = self.device_tracker.get_device_summary()
            print(f"Devices discovered: {device_summary.get('total_devices', 0)}")
            print(f"Active devices: {device_summary.get('active_devices', 0)}")
            
            # Application statistics
            app_stats = self.app_identifier.get_application_stats()
            if app_stats:
                top_apps = sorted(app_stats.items(), key=lambda x: x[1]['byte_count'], reverse=True)[:5]
                print("Top applications by traffic:")
                for app, stats in top_apps:
                    bytes_formatted = self._format_bytes(stats['byte_count'])
                    print(f"  {app}: {stats['packet_count']} packets, {bytes_formatted}")
                    
            # Database statistics
            db_stats = self.logger.get_statistics()
            if db_stats:
                print(f"Database records:")
                print(f"  Packets: {db_stats.get('total_packets', 0)}")
                print(f"  Devices: {db_stats.get('total_devices', 0)}")
                print(f"  Security events: {db_stats.get('security_events', 0)}")
                
        except Exception as e:
            print(f"Error generating final statistics: {e}")
            
    def _format_bytes(self, bytes_count):
        """Format byte count in human-readable format."""
        if bytes_count < 1024:
            return f"{bytes_count} B"
        elif bytes_count < 1024**2:
            return f"{bytes_count/1024:.1f} KB"
        elif bytes_count < 1024**3:
            return f"{bytes_count/(1024**2):.1f} MB"
        else:
            return f"{bytes_count/(1024**3):.1f} GB"


def check_privileges():
    """Check if running with appropriate privileges."""
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:  # Unix-like systems
        return os.geteuid() == 0


def main():
    """Main application entry point."""
    # Check privileges
    if not check_privileges():
        print("ERROR: This application requires administrator/root privileges to capture network packets.")
        print("\nOn Windows: Run as Administrator")
        print("On Linux/Mac: Run with sudo")
        sys.exit(1)
        
    # Parse command line arguments
    parser = create_argument_parser()
    
    # Add additional arguments specific to the main application
    parser.add_argument('--headless', action='store_true',
                       help='Run without interactive UI')
    parser.add_argument('--log-dir', default='logs',
                       help='Directory for log files')
    parser.add_argument('--min-size', type=int,
                       help='Minimum packet size filter')
    parser.add_argument('--max-size', type=int,
                       help='Maximum packet size filter')
    parser.add_argument('--export-packets', action='store_true',
                       help='Export packet data on exit')
    parser.add_argument('--export-security', action='store_true',
                       help='Export security events on exit')
    
    args = parser.parse_args()
    
    # Create and run network monitor
    try:
        monitor = NetworkMonitor(args)
        monitor.start()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()