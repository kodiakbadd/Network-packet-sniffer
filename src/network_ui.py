"""
Command-line user interface for the network monitor.
"""

import argparse
import time
import threading
import os
import sys
from datetime import datetime
from collections import defaultdict

# Windows-specific keyboard input
try:
    import msvcrt
    WINDOWS_INPUT_AVAILABLE = True
except ImportError:
    WINDOWS_INPUT_AVAILABLE = False
    try:
        import select
        import tty
        import termios
        UNIX_INPUT_AVAILABLE = True
    except ImportError:
        UNIX_INPUT_AVAILABLE = False

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    # Fallback empty color constants
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    class Back:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ""

try:
    from tabulate import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False


class NetworkMonitorUI:
    def __init__(self, packet_capture, device_tracker, traffic_filter, app_identifier):
        self.packet_capture = packet_capture
        self.device_tracker = device_tracker
        self.traffic_filter = traffic_filter
        self.app_identifier = app_identifier
        
        self.display_mode = 'live'  # live, devices, apps, stats
        self.max_display_lines = 20
        self.refresh_rate = 1.0  # seconds
        self.running = False
        self.display_thread = None
        self.packet_buffer = []
        self.buffer_lock = threading.Lock()
        
        # Statistics
        self.total_packets = 0
        self.filtered_packets = 0
        self.start_time = None
        
    def clear_screen(self):
        """Clear the console screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def print_header(self):
        """Print the application header."""
        header = f"""
{Fore.CYAN}{'='*80}
{Fore.YELLOW}               NETWORK PACKET SNIFFER & MONITOR
{Fore.CYAN}{'='*80}{Style.RESET_ALL}
"""
        print(header)
        
    def print_status_bar(self):
        """Print the status bar with current information."""
        if not self.start_time:
            return
            
        elapsed = datetime.now() - self.start_time
        elapsed_str = str(elapsed).split('.')[0]  # Remove microseconds
        
        # Get active filters
        active_filters = self.traffic_filter.get_active_filters()
        filter_info = f"Filters: {', '.join(active_filters)}" if active_filters else "No filters"
        
        # Get capture status
        status = f"{Fore.GREEN}CAPTURING" if self.packet_capture.is_capturing else f"{Fore.RED}STOPPED"
        
        status_bar = f"""
{Fore.BLUE}Status: {status}{Style.RESET_ALL} | Elapsed: {elapsed_str} | Packets: {self.total_packets} | Filtered: {self.filtered_packets}
{Fore.MAGENTA}{filter_info}{Style.RESET_ALL}
Mode: {self.display_mode.title()} | Press 'h' for help
{'-'*80}
"""
        print(status_bar)
        
    def display_live_packets(self):
        """Display live packet information."""
        with self.buffer_lock:
            if not self.packet_buffer:
                print(f"{Fore.YELLOW}Waiting for packets...{Style.RESET_ALL}")
                return
                
            recent_packets = self.packet_buffer[-self.max_display_lines:]
            
        if TABULATE_AVAILABLE:
            headers = ["Time", "Protocol", "Source", "Destination", "Size", "App"]
            table_data = []
            
            for packet in recent_packets:
                timestamp = packet.get('timestamp', datetime.now()).strftime("%H:%M:%S")
                protocol = packet.get('protocol', 'Unknown')
                
                src = f"{packet.get('src_ip', 'N/A')}:{packet.get('src_port', '')}"
                dst = f"{packet.get('dst_ip', 'N/A')}:{packet.get('dst_port', '')}"
                
                size = f"{packet.get('size', 0)} B"
                apps = packet.get('applications', ['Unknown'])
                app_str = ', '.join(apps[:2])  # Show max 2 apps
                
                table_data.append([timestamp, protocol, src, dst, size, app_str])
                
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
        else:
            # Fallback to simple formatting
            for packet in recent_packets:
                timestamp = packet.get('timestamp', datetime.now()).strftime("%H:%M:%S")
                protocol = packet.get('protocol', 'Unknown')
                src_ip = packet.get('src_ip', 'N/A')
                dst_ip = packet.get('dst_ip', 'N/A')
                src_port = packet.get('src_port', '')
                dst_port = packet.get('dst_port', '')
                size = packet.get('size', 0)
                
                print(f"[{timestamp}] {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({size}B)")
                
    def display_devices(self):
        """Display discovered devices."""
        devices = self.device_tracker.get_active_devices(minutes=30)
        
        if not devices:
            print(f"{Fore.YELLOW}No active devices found{Style.RESET_ALL}")
            return
            
        print(f"{Fore.GREEN}Active Devices (last 30 minutes):{Style.RESET_ALL}")
        
        if TABULATE_AVAILABLE:
            headers = ["MAC Address", "IP Address", "Hostname", "Vendor", "Type", "Packets", "Last Seen"]
            table_data = []
            
            for device_id, device in devices.items():
                mac = device['mac_address']
                ips = ', '.join(device['ip_addresses'][:2])  # Show max 2 IPs
                hostname = device.get('hostname', 'Unknown')[:20]  # Truncate long hostnames
                vendor = device.get('vendor', 'Unknown')
                device_type = device.get('device_type', 'Unknown')
                packets = device.get('packet_count', 0)
                last_seen = device['last_seen'].strftime("%H:%M:%S")
                
                table_data.append([mac, ips, hostname, vendor, device_type, packets, last_seen])
                
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
        else:
            # Fallback formatting
            for device_id, device in devices.items():
                print(f"MAC: {device['mac_address']}")
                print(f"  IP: {', '.join(device['ip_addresses'])}")
                print(f"  Hostname: {device.get('hostname', 'Unknown')}")
                print(f"  Vendor: {device.get('vendor', 'Unknown')}")
                print(f"  Type: {device.get('device_type', 'Unknown')}")
                print(f"  Packets: {device.get('packet_count', 0)}")
                print(f"  Last seen: {device['last_seen'].strftime('%H:%M:%S')}")
                print()
                
    def display_applications(self):
        """Display application statistics."""
        app_stats = self.app_identifier.get_application_stats(time_window=300)  # Last 5 minutes
        
        if not app_stats:
            print(f"{Fore.YELLOW}No application data available{Style.RESET_ALL}")
            return
            
        print(f"{Fore.GREEN}Application Traffic (last 5 minutes):{Style.RESET_ALL}")
        
        # Sort by byte count
        sorted_apps = sorted(app_stats.items(), key=lambda x: x[1]['byte_count'], reverse=True)
        
        if TABULATE_AVAILABLE:
            headers = ["Application", "Packets", "Bytes", "Connections", "Bandwidth"]
            table_data = []
            
            for app, stats in sorted_apps[:self.max_display_lines]:
                packets = stats['packet_count']
                bytes_count = self.format_bytes(stats['byte_count'])
                connections = stats['connections']
                bandwidth = self.format_bytes(stats['byte_count'] / 300) + "/s"  # Per second over 5 min
                
                table_data.append([app, packets, bytes_count, connections, bandwidth])
                
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
        else:
            # Fallback formatting
            for app, stats in sorted_apps[:self.max_display_lines]:
                bytes_formatted = self.format_bytes(stats['byte_count'])
                print(f"{app}: {stats['packet_count']} packets, {bytes_formatted}, {stats['connections']} connections")
                
    def display_statistics(self):
        """Display overall network statistics."""
        print(f"{Fore.GREEN}Network Statistics:{Style.RESET_ALL}")
        
        # Capture statistics
        capture_stats = self.packet_capture.get_capture_stats()
        
        # Device summary
        device_summary = self.device_tracker.get_device_summary()
        
        # Filter statistics
        filter_stats = self.traffic_filter.get_filter_stats()
        
        # Application summary
        app_stats = self.app_identifier.get_application_stats()
        total_app_bytes = sum(stats['byte_count'] for stats in app_stats.values())
        
        stats_info = f"""
{Fore.CYAN}Capture Statistics:{Style.RESET_ALL}
  Total Packets Captured: {capture_stats.get('total_packets', 0)}
  Protocol Distribution: {capture_stats.get('protocols', {})}
  
{Fore.CYAN}Device Summary:{Style.RESET_ALL}
  Total Devices: {device_summary.get('total_devices', 0)}
  Active Devices: {device_summary.get('active_devices', 0)}
  Device Types: {dict(device_summary.get('device_types', {}))}
  
{Fore.CYAN}Filter Statistics:{Style.RESET_ALL}
  Packets Passed: {filter_stats.get('passed', 0)}
  Packets Filtered: {sum(v for k, v in filter_stats.items() if k != 'passed')}
  
{Fore.CYAN}Application Traffic:{Style.RESET_ALL}
  Total Applications: {len(app_stats)}
  Total Bytes: {self.format_bytes(total_app_bytes)}
"""
        print(stats_info)
        
    def format_bytes(self, bytes_count):
        """Format byte count in human-readable format."""
        if bytes_count < 1024:
            return f"{bytes_count} B"
        elif bytes_count < 1024**2:
            return f"{bytes_count/1024:.1f} KB"
        elif bytes_count < 1024**3:
            return f"{bytes_count/(1024**2):.1f} MB"
        else:
            return f"{bytes_count/(1024**3):.1f} GB"
            
    def packet_callback(self, packet_info, raw_packet):
        """Callback function for captured packets."""
        self.total_packets += 1
        
        # Apply filters
        if not self.traffic_filter.matches_filter(packet_info, raw_packet):
            self.filtered_packets += 1
            return
            
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
        if dst_mac and dst_ip:
            self.device_tracker.add_device_observation(dst_mac, dst_ip, packet_info)
            
        # Add to display buffer
        with self.buffer_lock:
            self.packet_buffer.append(packet_info)
            # Keep buffer size manageable
            if len(self.packet_buffer) > 1000:
                self.packet_buffer = self.packet_buffer[-500:]
                
    def display_loop(self):
        """Main display loop."""
        while self.running:
            try:
                self.clear_screen()
                self.print_header()
                self.print_status_bar()
                
                if self.display_mode == 'live':
                    self.display_live_packets()
                elif self.display_mode == 'devices':
                    self.display_devices()
                elif self.display_mode == 'apps':
                    self.display_applications()
                elif self.display_mode == 'stats':
                    self.display_statistics()
                    
                print(f"\n{Fore.YELLOW}Commands: [q]uit [l]ive [d]evices [a]pps [s]tats [h]elp{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Current mode: {self.display_mode.upper()}{Style.RESET_ALL}")
                
                time.sleep(self.refresh_rate)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Display error: {e}")
                time.sleep(1)
                
    def show_help(self):
        """Show help information."""
        help_text = f"""
{Fore.CYAN}Network Monitor Help:{Style.RESET_ALL}

{Fore.YELLOW}Commands:{Style.RESET_ALL}
  q - Quit the application
  l - Switch to live packet view
  d - Switch to devices view
  a - Switch to applications view
  s - Switch to statistics view
  h - Show this help

{Fore.YELLOW}Filtering Options:{Style.RESET_ALL}
  --mac MAC_ADDRESS    Filter by MAC address
  --ip IP_ADDRESS      Filter by IP address or CIDR range
  --port PORT(S)       Filter by port number(s)
  --protocol PROTOCOL  Filter by protocol (TCP, UDP, etc.)
  --app APPLICATION    Filter by application type

{Fore.YELLOW}Display Modes:{Style.RESET_ALL}
  Live    - Show real-time packet capture
  Devices - Show discovered network devices
  Apps    - Show application traffic analysis
  Stats   - Show overall network statistics

{Fore.YELLOW}Examples:{Style.RESET_ALL}
  python network_monitor.py --mac 00:11:22:33:44:55
  python network_monitor.py --ip 192.168.1.0/24 --port 80,443
  python network_monitor.py --protocol TCP --app web

Press any key to continue...
"""
        print(help_text)
        input()
        
    def start(self):
        """Start the user interface."""
        self.running = True
        self.start_time = datetime.now()
        
        # Register packet callback
        self.packet_capture.add_callback(self.packet_callback)
        
        # Start display thread
        self.display_thread = threading.Thread(target=self.display_loop)
        self.display_thread.daemon = True
        self.display_thread.start()
        
        print(f"{Fore.GREEN}Network monitor started. Press 'h' for help, 'q' to quit.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Commands: [q]uit [l]ive [d]evices [a]pps [s]tats [h]elp{Style.RESET_ALL}")
        
        # Handle user input with non-blocking keyboard detection
        try:
            while self.running:
                key = self._get_key_press()
                
                if key:
                    if key == 'q':
                        print(f"\n{Fore.RED}Quitting...{Style.RESET_ALL}")
                        break
                    elif key == 'l':
                        self.display_mode = 'live'
                        print(f"\n{Fore.CYAN}→ Switched to Live mode{Style.RESET_ALL}")
                    elif key == 'd':
                        self.display_mode = 'devices'
                        print(f"\n{Fore.CYAN}→ Switched to Devices mode{Style.RESET_ALL}")
                    elif key == 'a':
                        self.display_mode = 'apps'
                        print(f"\n{Fore.CYAN}→ Switched to Applications mode{Style.RESET_ALL}")
                    elif key == 's':
                        self.display_mode = 'stats'
                        print(f"\n{Fore.CYAN}→ Switched to Statistics mode{Style.RESET_ALL}")
                    elif key == 'h':
                        self.show_help()
                        
                time.sleep(0.1)  # Small delay to prevent high CPU usage
                    
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
            
    def stop(self):
        """Stop the user interface."""
        self.running = False
        if self.display_thread and self.display_thread.is_alive():
            self.display_thread.join(timeout=2)
        print(f"\n{Fore.YELLOW}Network monitor stopped.{Style.RESET_ALL}")
        
    def _get_key_press(self):
        """Get a key press in a non-blocking way."""
        if WINDOWS_INPUT_AVAILABLE:
            if msvcrt.kbhit():
                try:
                    key = msvcrt.getch()
                    if isinstance(key, bytes):
                        key = key.decode('utf-8')
                    return key.lower()
                except:
                    return None
        elif UNIX_INPUT_AVAILABLE:
            # Unix/Linux implementation
            if select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], []):
                try:
                    return sys.stdin.read(1).lower()
                except:
                    return None
        else:
            # Fallback - blocking input (not ideal but works)
            try:
                return input("Enter command (q/l/d/a/s/h): ").lower().strip()
            except:
                return None
        return None


def create_argument_parser():
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        description="Network Packet Sniffer and Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python network_monitor.py
  python network_monitor.py --interface eth0
  python network_monitor.py --mac 00:11:22:33:44:55
  python network_monitor.py --ip 192.168.1.100
  python network_monitor.py --port 80,443 --protocol TCP
  python network_monitor.py --scan-network
        """
    )
    
    # Network interface
    parser.add_argument('--interface', '-i', 
                       help='Network interface to monitor (default: auto-detect)')
    
    # Filtering options
    parser.add_argument('--mac', 
                       help='Filter by MAC address')
    parser.add_argument('--ip', 
                       help='Filter by IP address or CIDR range')
    parser.add_argument('--port', 
                       help='Filter by port(s) - comma separated or range (e.g., 80,443 or 8000-8080)')
    parser.add_argument('--protocol', 
                       help='Filter by protocol (TCP, UDP, ICMP, etc.)')
    parser.add_argument('--app', 
                       help='Filter by application type')
    
    # Display options
    parser.add_argument('--mode', choices=['live', 'devices', 'apps', 'stats'],
                       default='live', help='Initial display mode')
    parser.add_argument('--max-packets', type=int, default=0,
                       help='Maximum packets to capture (0 = unlimited)')
    parser.add_argument('--timeout', type=int,
                       help='Capture timeout in seconds')
    
    # Actions
    parser.add_argument('--scan-network', action='store_true',
                       help='Scan local network for devices before monitoring')
    parser.add_argument('--export-devices', 
                       help='Export device information to JSON file')
    parser.add_argument('--export-apps', 
                       help='Export application statistics to JSON file')
    
    # Configuration
    parser.add_argument('--no-colors', action='store_true',
                       help='Disable colored output')
    parser.add_argument('--refresh-rate', type=float, default=1.0,
                       help='Display refresh rate in seconds')
    
    return parser


if __name__ == "__main__":
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Import required modules (would be done at the top in the main script)
    try:
        from packet_capture import PacketCapture
        from device_tracker import DeviceTracker
        from traffic_filter import TrafficFilter
        from app_identifier import ApplicationIdentifier
    except ImportError as e:
        print(f"Error importing modules: {e}")
        print("Make sure all required modules are available and dependencies are installed.")
        sys.exit(1)
        
    # Initialize components
    packet_capture = PacketCapture(interface=args.interface)
    device_tracker = DeviceTracker()
    traffic_filter = TrafficFilter()
    app_identifier = ApplicationIdentifier()
    
    # Apply filters based on command line arguments
    if args.mac:
        traffic_filter.add_mac_filter(args.mac)
    if args.ip:
        traffic_filter.add_ip_filter(args.ip)
    if args.port:
        if ',' in args.port:
            ports = [int(p.strip()) for p in args.port.split(',')]
        elif '-' in args.port:
            start, end = map(int, args.port.split('-'))
            ports = list(range(start, end + 1))
        else:
            ports = [int(args.port)]
        traffic_filter.add_port_filter(ports)
    if args.protocol:
        traffic_filter.add_protocol_filter(args.protocol)
        
    # Perform network scan if requested
    if args.scan_network:
        print("Scanning local network for devices...")
        device_tracker.scan_local_network()
        
    # Create and configure UI
    ui = NetworkMonitorUI(packet_capture, device_tracker, traffic_filter, app_identifier)
    ui.display_mode = args.mode
    ui.refresh_rate = args.refresh_rate
    
    try:
        # Start packet capture
        packet_capture.start_capture(count=args.max_packets, timeout=args.timeout)
        
        # Start UI
        ui.start()
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Clean up
        packet_capture.stop_capture()
        
        # Export data if requested
        if args.export_devices:
            device_tracker.export_devices(args.export_devices)
        if args.export_apps:
            app_identifier.export_application_data(args.export_apps)