import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import json
from datetime import datetime
import os
import sys

# Add src directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(current_dir, 'src')
sys.path.insert(0, src_dir)

# Windows-native packet capture (no scapy - it's broken on Windows!)
print("🔧 Initializing Windows-native network monitoring...")
try:
    import subprocess
    import json
    # Test Windows network commands
    result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, timeout=3, creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode == 0:
        print("✅ Windows network tools working!")
        MODULES_AVAILABLE = True
        print("🚀 WINDOWS-NATIVE CAPTURE ENABLED!")
    else:
        raise Exception("Windows network access failed")
except Exception as e:
    print(f"⚠️  Windows network error: {e}")
    print("🔄 Falling back to demo mode...")
    MODULES_AVAILABLE = False

# Simple implementations to replace missing modules
class DeviceTracker:
    def __init__(self):
        self.devices = []
    
class TrafficFilter:
    def __init__(self):
        pass
        
class ApplicationIdentifier:
    def __init__(self):
        pass
        
class PacketCapture:
    def __init__(self):
        self.running = False
        self.filter_ip = None
        self.filter_mac = None
        self.callbacks = []
        
    def set_filter(self, ip=None, mac=None, port=None):
        self.filter_ip = ip
        self.filter_mac = mac
        
    def add_callback(self, callback):
        self.callbacks.append(callback)
        
    def start_capture(self, callback=None):
        if callback:
            self.callbacks.append(callback)
        self.running = True
        # Start Windows network monitoring thread
        import threading
        threading.Thread(target=self._capture_loop, daemon=True).start()
        
    def stop_capture(self):
        self.running = False
        
    def _capture_loop(self):
        import subprocess
        import time
        import random
        
        seen_connections = set()  # Track seen connections to avoid duplicates
        
        while self.running:
            try:
                # Use netstat to get real network connections
                result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
                lines = result.stdout.split('\n')
                
                for line in lines:
                    if 'ESTABLISHED' in line and ':' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            local = parts[1]
                            remote = parts[2]
                            
                            if ':' in local and ':' in remote:
                                local_ip, local_port = local.rsplit(':', 1)
                                remote_ip, remote_port = remote.rsplit(':', 1)
                                
                                # Create connection key to avoid duplicates
                                connection_key = f"{local_ip}:{local_port}->{remote_ip}:{remote_port}"
                                if connection_key in seen_connections:
                                    continue
                                seen_connections.add(connection_key)
                                
                                # Filter by IP if specified (extract actual IP from filter)
                                if self.filter_ip:
                                    # Extract IP from filter (could be string or dict)
                                    if isinstance(self.filter_ip, dict) and 'ip' in self.filter_ip:
                                        filter_ip_str = self.filter_ip['ip']
                                    else:
                                        filter_ip_str = str(self.filter_ip)
                                    
                                    if filter_ip_str and filter_ip_str != local_ip:
                                        continue  # Skip if IP doesn't match exactly
                                    
                                print(f"✅ REAL CONNECTION: {local_ip}:{local_port} -> {remote_ip}:{remote_port}")
                                    
                                # Determine protocol and app
                                protocol = "TCP"
                                app_name = "Unknown"
                                
                                if remote_port == "443":
                                    protocol = "HTTPS"
                                    app_name = "Browser"
                                elif remote_port == "80":
                                    protocol = "HTTP" 
                                    app_name = "Web"
                                elif remote_port in ["25", "587", "465"]:
                                    app_name = "Email"
                                elif remote_port in ["21", "22"]:
                                    app_name = "FTP/SSH"
                                
                                # Create packet data
                                packet_data = {
                                    'src_ip': local_ip,
                                    'dst_ip': remote_ip,
                                    'src_port': local_port,
                                    'dst_port': remote_port,
                                    'protocol': protocol,
                                    'app': app_name,
                                    'size': random.randint(64, 1500)
                                }
                                
                                # Call all callbacks with real packet
                                for callback in self.callbacks:
                                    try:
                                        callback(packet_data)
                                    except Exception as e:
                                        print(f"Callback error: {e}")
                                    
            except Exception as e:
                print(f"Capture error: {e}")
                
            time.sleep(5)  # Check every 5 seconds to reduce flashing

class NetworkMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.setup_window()
        self.setup_styles()
        self.setup_variables()
        self.create_widgets()
        
        # Initialize network components
        if MODULES_AVAILABLE:
            print("🔥 Initializing REAL network components...")
            self.init_network_components()
        else:
            print("🎮 Initializing demo mode...")
            self.init_demo_mode()
            
        # Update dropdown with loaded configurations
        self.update_config_dropdown()
        
        # Start background updates
        self.start_background_updates()
        
    def setup_window(self):
        """Configure main window"""
        self.root.title("HCC Network Packet Monitor")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')
        
        # Try to set icon (optional)
        self.load_custom_icon()
    
    def load_custom_icon(self):
        """Load custom icon from HCC Favicon folder"""
        try:
            # Try bundled ICO first (for .exe) - PyInstaller bundles files in sys._MEIPASS
            if hasattr(sys, '_MEIPASS'):
                bundled_ico = os.path.join(sys._MEIPASS, 'favicon.ico')
                if os.path.exists(bundled_ico):
                    try:
                        self.root.iconbitmap(bundled_ico)
                        print(f"✅ Loaded bundled ICO icon: {bundled_ico}")
                        return
                    except Exception as e:
                        print(f"❌ Failed to load bundled ICO icon: {e}")
            
            # Try local ICO (better for Windows title bar)
            local_ico = os.path.join(os.path.dirname(__file__), 'favicon.ico')
            if os.path.exists(local_ico):
                try:
                    self.root.iconbitmap(local_ico)
                    print(f"✅ Loaded ICO icon: {local_ico}")
                    return
                except Exception as e:
                    print(f"❌ Failed to load ICO icon: {e}")
            
            # Try local PNG icon as fallback
            local_icon = os.path.join(os.path.dirname(__file__), 'favicon.png')
            if os.path.exists(local_icon):
                try:
                    # Convert PNG to PhotoImage for tkinter
                    import tkinter as tk
                    icon_image = tk.PhotoImage(file=local_icon)
                    self.root.iconphoto(True, icon_image)
                    print(f"✅ Loaded PNG icon: {local_icon}")
                    return
                except Exception as e:
                    print(f"❌ Failed to load PNG icon: {e}")
            
            # Try ICO files
            icon_folders = [
                r'C:\Users\James\Documents\HCC Favicon',
                os.path.dirname(__file__)
            ]
            
            icon_names = [
                'favicon.ico', 'hcc.ico', 'icon.ico', 'logo.ico',
                'app.ico', 'network.ico', 'monitor.ico'
            ]
            
            for folder in icon_folders:
                if os.path.exists(folder):
                    for icon_name in icon_names:
                        icon_path = os.path.join(folder, icon_name)
                        if os.path.exists(icon_path):
                            try:
                                self.root.iconbitmap(icon_path)
                                print(f"✅ Loaded ICO icon: {icon_path}")
                                return
                            except Exception as e:
                                print(f"❌ Failed to load {icon_path}: {e}")
                                continue
            
            print("⚠️ No compatible icon file found")
            
        except Exception as e:
            print(f"Could not load icon: {e}")
            
        # Configure dark title bar (Windows 10/11)
        self.configure_dark_title_bar()
            
    def setup_styles(self):
        """Configure dark theme styles"""
        style = ttk.Style()
        
        # Configure dark theme
        style.theme_use('clam')
        
        # Dark colors
        bg_color = '#1e1e1e'
        fg_color = '#ffffff'
        select_color = '#404040'
        accent_color = '#0078d4'
        
        style.configure('Dark.TFrame', background=bg_color)
        style.configure('Dark.TLabel', background=bg_color, foreground=fg_color)
        style.configure('Dark.TButton', background='#404040', foreground=fg_color)
        style.map('Dark.TButton', background=[('active', accent_color)])
        style.configure('Dark.TNotebook', background=bg_color, borderwidth=0)
        style.configure('Dark.TNotebook.Tab', background='#2d2d2d', foreground=fg_color, padding=[20, 8])
        style.map('Dark.TNotebook.Tab', background=[('selected', accent_color)])
        
        # Configure dark scrollbars
        style.configure('Dark.Vertical.TScrollbar', 
                       background='#2d2d2d',
                       troughcolor='#1e1e1e',
                       bordercolor='#404040',
                       arrowcolor='#ffffff',
                       darkcolor='#2d2d2d',
                       lightcolor='#404040')
        style.map('Dark.Vertical.TScrollbar',
                 background=[('active', '#404040')])
        
        style.configure('Dark.Horizontal.TScrollbar',
                       background='#2d2d2d',
                       troughcolor='#1e1e1e', 
                       bordercolor='#404040',
                       arrowcolor='#ffffff',
                       darkcolor='#2d2d2d',
                       lightcolor='#404040')
        style.map('Dark.Horizontal.TScrollbar',
                 background=[('active', '#404040')])
        
        # Configure TreeView dark theme
        style.configure('Dark.Treeview',
                       background='#000000',
                       foreground='#00ff00',
                       fieldbackground='#000000',
                       borderwidth=1,
                       relief='solid',
                       font=('Consolas', 9))
        style.configure('Dark.Treeview.Heading',
                       background='#2d2d2d',
                       foreground='#00ff00',
                       relief='flat',
                       font=('Arial', 9, 'bold'))
        style.map('Dark.Treeview',
                 background=[('selected', '#404040')],
                 foreground=[('selected', '#00ff00')])
        style.map('Dark.Treeview.Heading',
                 background=[('active', '#404040')])
    
    def configure_dark_scrollbar(self, widget):
        """Configure dark scrollbar for text widgets"""
        try:
            # Get the scrollbar from the ScrolledText widget
            scrollbar = None
            for child in widget.winfo_children():
                if isinstance(child, tk.Scrollbar):
                    scrollbar = child
                    break
            
            if scrollbar:
                scrollbar.configure(
                    bg='#2d2d2d',
                    troughcolor='#1e1e1e',
                    highlightbackground='#1e1e1e',
                    highlightcolor='#404040',
                    activebackground='#404040',
                    activerelief='flat',
                    relief='flat'
                )
        except Exception as e:
            print(f"Could not configure scrollbar: {e}")
    
    def configure_dark_title_bar(self):
        """Configure dark title bar for Windows 10/11"""
        try:
            import ctypes
            from ctypes import wintypes
            
            # Update the window after it's been created
            self.root.update()
            
            # Get window handle
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            
            # Define constants for Windows API
            DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1 = 19
            DWMWA_USE_IMMERSIVE_DARK_MODE = 20
            
            # Try Windows 11/newer Windows 10 first
            try:
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, 
                    ctypes.byref(ctypes.c_int(1)), ctypes.sizeof(ctypes.c_int)
                )
            except:
                # Fallback for older Windows 10
                try:
                    ctypes.windll.dwmapi.DwmSetWindowAttribute(
                        hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1,
                        ctypes.byref(ctypes.c_int(1)), ctypes.sizeof(ctypes.c_int)
                    )
                except:
                    pass
                    
        except Exception as e:
            print(f"Could not set dark title bar: {e}")
        
    def setup_variables(self):
        """Initialize variables"""
        self.monitoring = False
        self.packets_captured = 0
        self.devices_found = []
        self.applications_detected = []
        self.console_lines = []
        
        # Multi-monitor sessions
        self.monitor_sessions = {}  # Dictionary to store multiple monitoring sessions
        self.active_session_id = "Session-1"
        self.session_counter = 1
        
        # Filter variables
        self.filter_mac = tk.StringVar()  # Legacy - kept for compatibility
        self.filter_ip = tk.StringVar()   # Legacy - kept for compatibility  
        self.filter_port = tk.StringVar() # Legacy - kept for compatibility
        self.filter_protocol = tk.StringVar(value="ALL")
        
        # Saved configurations
        self.saved_configs = {}
        self.config_name = tk.StringVar()
        self.selected_config = tk.StringVar()
        self.load_saved_configurations()
        
    def init_network_components(self):
        """Initialize network monitoring components"""
        try:
            self.device_tracker = DeviceTracker()
            self.traffic_filter = TrafficFilter()
            self.app_identifier = ApplicationIdentifier()
            self.network_capture = None
            self.log_to_console("✅ Network components initialized")
        except Exception as e:
            self.log_to_console(f"❌ Error initializing network components: {e}")
            
    def init_demo_mode(self):
        """Initialize demo mode with sample data"""
        self.log_to_console("🎮 Demo Mode - Network modules not available")
        self.log_to_console("📊 Generating sample data...")
        
        # Initialize empty lists - will be populated dynamically
        self.devices_found = []
        self.applications_detected = []
        
        # Start generating data
        self.generate_demo_data()
        
    def create_widgets(self):
        """Create all GUI widgets"""
        # Main container
        main_frame = ttk.Frame(self.root, style='Dark.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = ttk.Label(main_frame, text="HCC Network Packet Monitor", 
                               style='Dark.TLabel', font=('Arial', 16, 'bold'))
        title_label.pack(pady=(0, 5))
        
        # Status label to show demo vs real mode
        mode_text = "🎮 DEMO MODE - Sample Data Only" if not MODULES_AVAILABLE else "🔥 LIVE MODE - Real Network Capture"
        mode_color = "#FF6B6B" if not MODULES_AVAILABLE else "#4ECDC4"
        self.mode_label = ttk.Label(main_frame, text=mode_text, 
                                   style='Dark.TLabel', font=('Arial', 12, 'bold'))
        self.mode_label.configure(foreground=mode_color)
        self.mode_label.pack(pady=(0, 10))
        
        # Main Control Panel (at top)
        self.create_main_control_panel(main_frame)
        
        # Monitor Sessions label (directly above main monitor)
        sessions_label = ttk.Label(main_frame, text="Monitor Sessions:", 
                                  style='Dark.TLabel', font=('Arial', 10, 'bold'))
        sessions_label.pack(anchor=tk.W, pady=(10, 5))
        
        # Main content area - taller main monitor display
        self.create_main_monitor_area(main_frame)
        
        # Session Management Buttons (below main monitor)
        self.create_session_management_buttons(main_frame)
    
    def create_main_monitor_area(self, parent):
        """Create the main monitor display area - taller and more prominent"""
        # Main display container
        self.main_display_frame = ttk.Frame(parent, style='Dark.TFrame')
        self.main_display_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Initialize session notebook for tabs (Main Monitor will be first tab)
        self.session_notebook = ttk.Notebook(self.main_display_frame, style='Dark.TNotebook')
        self.session_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Initialize first session (Main Monitor)
        self.create_monitoring_session("Session-1", "Main Monitor")
        
        # Initially show single view
        self.split_view_active = False
        self.current_display_mode = "single"
    
    def create_session_management_buttons(self, parent):
        """Create session management buttons below the main monitor"""
        # Session control buttons frame
        session_buttons_frame = ttk.Frame(parent, style='Dark.TFrame')
        session_buttons_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Left side - session controls
        session_controls = ttk.Frame(session_buttons_frame, style='Dark.TFrame')
        session_controls.pack(side=tk.LEFT)
        
        add_session_btn = ttk.Button(session_controls, text="➕ Add Session", 
                                    command=self.add_new_session, style='Dark.TButton')
        add_session_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        remove_session_btn = ttk.Button(session_controls, text="➖ Remove Session", 
                                       command=self.remove_current_session, style='Dark.TButton')
        remove_session_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        split_view_btn = ttk.Button(session_controls, text="🔀 Split View", 
                                   command=self.toggle_split_view, style='Dark.TButton')
        split_view_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        save_session_btn = ttk.Button(session_controls, text="💾 Save Session", 
                                     command=self.save_current_session, style='Dark.TButton')
        save_session_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        analyze_btn = ttk.Button(session_controls, text="📊 Analyze Packets", 
                               command=self.analyze_packets, style='Dark.TButton')
        analyze_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Right side - device scanning
        device_controls = ttk.Frame(session_buttons_frame, style='Dark.TFrame')
        device_controls.pack(side=tk.RIGHT)
        
        scan_devices_btn = ttk.Button(device_controls, text="🔍 Scan Devices", 
                                     command=self.scan_for_devices, style='Dark.TButton')
        scan_devices_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        # Add Save Session button
        save_session_btn = ttk.Button(device_controls, text="💾 Save Session", 
                                     command=self.save_current_session, style='Dark.TButton')
        save_session_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        # Add Analyze Packets button
        analyze_btn = ttk.Button(device_controls, text="📊 Analyze Packets", 
                                command=self.analyze_packets, style='Dark.TButton')
        analyze_btn.pack(side=tk.LEFT)
    
    def scan_for_devices(self):
        """Scan for devices on the network"""
        self.log_to_console("🔍 Scan Devices button clicked - starting scan...")
        
        def scan_thread():
            try:
                self.log_to_console("🔍 Scanning for devices on network...")
                
                if MODULES_AVAILABLE:
                    # Use real device scanning
                    devices = self.device_tracker.scan_local_network()
                    discovered = self.device_tracker.get_all_devices()
                    
                    self.log_to_console(f"✅ Found {len(discovered)} devices")
                    
                    # Update all active sessions with discovered devices
                    for session_id, session in self.monitor_sessions.items():
                        for device_id, device_info in discovered.items():
                            device_data = {
                                'mac': device_info['mac_address'],
                                'ip': device_info['ip_addresses'][0] if device_info['ip_addresses'] else 'Unknown',
                                'hostname': device_info.get('hostname', 'Unknown'),
                                'vendor': device_info.get('vendor', 'Unknown'),
                                'type': device_info.get('device_type', 'Unknown'),
                                'packets': 0
                            }
                            
                            # Add to session if not already present
                            if device_data not in session['devices_found']:
                                session['devices_found'].append(device_data)
                                
                            # Update devices tree if it exists
                            if session['devices_tree']:
                                def update_tree():
                                    # Clear and repopulate tree
                                    for item in session['devices_tree'].get_children():
                                        session['devices_tree'].delete(item)
                                    
                                    for device in session['devices_found']:
                                        session['devices_tree'].insert('', tk.END, values=(
                                            device.get('mac', ''),
                                            device.get('ip', ''),
                                            device.get('hostname', ''),
                                            device.get('vendor', ''),
                                            device.get('type', ''),
                                            device.get('packets', 0)
                                        ))
                                
                                self.root.after(0, update_tree)
                    
                    self.log_to_console("📋 Device scan complete - check Devices tab")
                    
                else:
                    # Demo mode - generate sample devices
                    self.log_to_console("🎮 Demo mode - generating sample devices...")
                    demo_devices = [
                        {'mac': '78:B6:EE:F1:06:3F', 'ip': '10.14.0.2', 'hostname': 'Desktop-PC', 'vendor': 'Intel', 'type': 'Computer', 'packets': 15},
                        {'mac': '2e:80:02:62:18:46', 'ip': '10.14.0.151', 'hostname': 'iPhone-12', 'vendor': 'Apple', 'type': 'Mobile', 'packets': 8},
                        {'mac': 'AC:BC:32:D4:A1:F2', 'ip': '10.14.0.1', 'hostname': 'Router', 'vendor': 'Netgear', 'type': 'Router', 'packets': 25},
                        {'mac': '44:D9:E7:02:8B:91', 'ip': '10.14.0.102', 'hostname': 'Smart-TV', 'vendor': 'Samsung', 'type': 'Media', 'packets': 3}
                    ]
                    
                    # Add demo devices to all sessions
                    for session_id, session in self.monitor_sessions.items():
                        session['devices_found'].extend(demo_devices)
                        
                        # Update devices tree if it exists
                        if session['devices_tree']:
                            def update_demo_tree():
                                for device in demo_devices:
                                    session['devices_tree'].insert('', tk.END, values=(
                                        device['mac'], device['ip'], device['hostname'],
                                        device['vendor'], device['type'], device['packets']
                                    ))
                            
                            self.root.after(0, update_demo_tree)
                    
                    self.log_to_console("✅ Found 4 demo devices")
                    
            except Exception as e:
                self.log_to_console(f"❌ Device scan error: {e}")
        
        # Run scan in background thread
        import threading
        thread = threading.Thread(target=scan_thread, daemon=True)
        thread.start()
    
    def save_current_session(self):
        """Save current session to file"""
        from tkinter import filedialog, messagebox
        import json
        from datetime import datetime
        
        active_session = self.monitor_sessions.get(self.active_session_id)
        if not active_session:
            self.log_to_console("❌ No active session to save")
            return
        
        # Get session data
        session_data = {
            'session_name': active_session['name'],
            'timestamp': datetime.now().isoformat(),
            'filters': {
                'mac': active_session['filter_mac'].get(),
                'ip': active_session['filter_ip'].get(),
                'port': active_session['filter_port'].get()
            },
            'devices_found': active_session['devices_found'],
            'monitoring': active_session['monitoring'],
            'packet_data': []
        }
        
        # Get packet data if available
        if active_session['packet_text']:
            packet_content = active_session['packet_text'].get(1.0, tk.END)
            session_data['packet_data'] = packet_content.split('\n')
        
        # Ask user for save location
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title=f"Save Session: {active_session['name']}"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(session_data, f, indent=2, default=str)
                self.log_to_console(f"💾 Session saved to: {filename}")
                messagebox.showinfo("Success", f"Session saved successfully to:\n{filename}")
            except Exception as e:
                self.log_to_console(f"❌ Error saving session: {e}")
                messagebox.showerror("Error", f"Failed to save session:\n{e}")
    
    def analyze_packets(self):
        """Analyze packets in current session"""
        active_session = self.monitor_sessions.get(self.active_session_id)
        if not active_session:
            self.log_to_console("❌ No active session to analyze")
            return
        
        if not active_session['packet_text']:
            self.log_to_console("❌ No packet data to analyze")
            return
        
        # Create analysis window
        analysis_window = tk.Toplevel(self.root)
        analysis_window.title(f"Packet Analysis - {active_session['name']}")
        analysis_window.geometry("800x600")
        analysis_window.configure(bg='#000000')
        
        # Analysis notebook
        analysis_notebook = ttk.Notebook(analysis_window, style='Dark.TNotebook')
        analysis_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Statistics tab
        stats_frame = ttk.Frame(analysis_notebook, style='Dark.TFrame')
        analysis_notebook.add(stats_frame, text="📊 Statistics")
        
        stats_text = scrolledtext.ScrolledText(stats_frame, bg='#000000', fg='#00ff00',
                                              insertbackground='white', font=('Consolas', 10))
        stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Get packet data
        packet_content = active_session['packet_text'].get(1.0, tk.END)
        packet_lines = [line.strip() for line in packet_content.split('\n') if line.strip()]
        
        # Analyze packets
        analysis_results = self.perform_packet_analysis(packet_lines)
        
        # Display results
        stats_text.insert(1.0, analysis_results)
        stats_text.config(state=tk.DISABLED)
        
        # Protocol breakdown tab
        protocol_frame = ttk.Frame(analysis_notebook, style='Dark.TFrame')
        analysis_notebook.add(protocol_frame, text="🔍 Protocols")
        
        protocol_text = scrolledtext.ScrolledText(protocol_frame, bg='#000000', fg='#00ff00',
                                                 insertbackground='white', font=('Consolas', 10))
        protocol_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Protocol analysis
        protocol_analysis = self.analyze_protocols(packet_lines)
        protocol_text.insert(1.0, protocol_analysis)
        protocol_text.config(state=tk.DISABLED)
        
        self.log_to_console(f"📊 Packet analysis opened for {active_session['name']}")
    
    def perform_packet_analysis(self, packet_lines):
        """Perform statistical analysis on packet data"""
        from datetime import datetime
        from collections import Counter
        
        total_packets = len(packet_lines)
        
        # Count different types
        tcp_count = sum(1 for line in packet_lines if 'TCP' in line)
        udp_count = sum(1 for line in packet_lines if 'UDP' in line)
        icmp_count = sum(1 for line in packet_lines if 'ICMP' in line)
        http_count = sum(1 for line in packet_lines if 'HTTP' in line or ':80' in line or ':443' in line)
        
        # IP analysis
        ips = []
        for line in packet_lines:
            if ' -> ' in line:
                parts = line.split(' -> ')
                if len(parts) >= 2:
                    src_ip = parts[0].split()[-1] if parts[0] else ''
                    dst_ip = parts[1].split()[0] if parts[1] else ''
                    if src_ip: ips.append(src_ip)
                    if dst_ip: ips.append(dst_ip)
        
        unique_ips = set(ips)
        
        analysis = f"""
🔍 PACKET ANALYSIS REPORT
{'='*50}

📊 GENERAL STATISTICS:
   Total Packets:     {total_packets}
   Unique IP Addresses: {len(unique_ips)}
   Time Analyzed:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

🌐 PROTOCOL BREAKDOWN:
   TCP Packets:       {tcp_count} ({tcp_count/total_packets*100:.1f}%)
   UDP Packets:       {udp_count} ({udp_count/total_packets*100:.1f}%)
   ICMP Packets:      {icmp_count} ({icmp_count/total_packets*100:.1f}%)
   HTTP/HTTPS:        {http_count} ({http_count/total_packets*100:.1f}%)

📈 TOP IP ADDRESSES:
"""
        
        ip_counts = Counter(ips)
        for ip, count in ip_counts.most_common(10):
            analysis += f"   {ip:<15} {count:>3} packets\n"
        
        return analysis
    
    def analyze_protocols(self, packet_lines):
        """Analyze protocol distribution"""
        protocols = {}
        
        for line in packet_lines:
            # Extract protocol info
            if 'TCP' in line:
                protocols['TCP'] = protocols.get('TCP', 0) + 1
            elif 'UDP' in line:
                protocols['UDP'] = protocols.get('UDP', 0) + 1
            elif 'ICMP' in line:
                protocols['ICMP'] = protocols.get('ICMP', 0) + 1
            elif 'ARP' in line:
                protocols['ARP'] = protocols.get('ARP', 0) + 1
            elif 'DNS' in line:
                protocols['DNS'] = protocols.get('DNS', 0) + 1
            else:
                protocols['Other'] = protocols.get('Other', 0) + 1
        
        result = f"""
🔍 PROTOCOL ANALYSIS
{'='*40}

"""
        
        total = sum(protocols.values())
        for protocol, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            bar = '█' * int(percentage / 2)
            result += f"{protocol:<8} {count:>4} packets {percentage:>5.1f}% {bar}\n"
        
        return result

    def create_monitoring_session(self, session_id, display_name):
        """Create a new monitoring session with its own filters and displays"""
        # Create session tab
        session_frame = ttk.Frame(self.session_notebook, style='Dark.TFrame')
        self.session_notebook.add(session_frame, text=display_name)
        
        # Session-specific variables
        session_data = {
            'id': session_id,
            'name': display_name,
            'frame': session_frame,
            'monitoring': False,
            'packets_captured': 0,
            'devices_found': [],
            'applications_detected': [],
            'filter_mac': tk.StringVar(value=""),
            'filter_ip': tk.StringVar(value=""), 
            'filter_port': tk.StringVar(),
            'notebook': None,
            'packet_text': None,
            'devices_tree': None,
            'apps_tree': None,
            'stats_text': None
        }
        
        # Create session-specific monitoring display
        self.create_session_display(session_data)
        
        # Store session
        self.monitor_sessions[session_id] = session_data
        
        # Set as active session
        self.active_session_id = session_id
    
    def create_session_display(self, session_data):
        """Create monitoring display for a specific session"""
        session_frame = session_data['frame']
        
        # Session info header
        info_frame = ttk.Frame(session_frame, style='Dark.TFrame')
        info_frame.pack(fill=tk.X, pady=(5, 5))
        
        session_label = ttk.Label(info_frame, text=f"Session: {session_data['name']}", 
                                 style='Dark.TLabel', font=('Arial', 10, 'bold'))
        session_label.pack(side=tk.LEFT)
        
        status_label = ttk.Label(info_frame, text="● Stopped", 
                                style='Dark.TLabel', foreground='#ff6b6b')
        status_label.pack(side=tk.RIGHT)
        session_data['status_label'] = status_label
        
        # Session control panel with improved layout
        control_frame = ttk.Frame(session_frame, style='Dark.TFrame')
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Top row - Filters
        filters_row = ttk.Frame(control_frame, style='Dark.TFrame')
        filters_row.pack(fill=tk.X, pady=(0, 5))
        
        # MAC Filter
        mac_frame = ttk.Frame(filters_row, style='Dark.TFrame')
        mac_frame.pack(side=tk.LEFT, padx=(0, 15))
        ttk.Label(mac_frame, text="MAC Address:", style='Dark.TLabel').pack(anchor=tk.W)
        mac_entry = tk.Entry(mac_frame, textvariable=session_data['filter_mac'], width=20,
                            bg='#2d2d2d', fg='white', insertbackground='white')
        mac_entry.pack()

        
        # IP Filter  
        ip_frame = ttk.Frame(filters_row, style='Dark.TFrame')
        ip_frame.pack(side=tk.LEFT, padx=(0, 15))
        ttk.Label(ip_frame, text="IP Address:", style='Dark.TLabel').pack(anchor=tk.W)
        ip_entry = tk.Entry(ip_frame, textvariable=session_data['filter_ip'], width=15,
                           bg='#2d2d2d', fg='white', insertbackground='white')
        ip_entry.pack()

        
        # Port Filter
        port_frame = ttk.Frame(filters_row, style='Dark.TFrame')
        port_frame.pack(side=tk.LEFT, padx=(0, 15))
        ttk.Label(port_frame, text="Port:", style='Dark.TLabel').pack(anchor=tk.W)
        port_entry = tk.Entry(port_frame, textvariable=session_data['filter_port'], width=10,
                             bg='#2d2d2d', fg='white', insertbackground='white')
        port_entry.pack()

        
        # Bottom row - Minimal session controls
        buttons_row = ttk.Frame(control_frame, style='Dark.TFrame')
        buttons_row.pack(fill=tk.X)
        
        start_btn = ttk.Button(buttons_row, text="🚀 Start", 
                              command=lambda: self.toggle_session_monitoring(session_data['id']), 
                              style='Dark.TButton')
        start_btn.pack(side=tk.LEFT, padx=(0, 10))
        session_data['start_button'] = start_btn
        
        apply_btn = ttk.Button(buttons_row, text="📝 Apply Filters", 
                              command=lambda: self.apply_session_filters(session_data['id']),
                              style='Dark.TButton')
        apply_btn.pack(side=tk.LEFT)
        
        # Monitoring display notebook
        display_notebook = ttk.Notebook(session_frame, style='Dark.TNotebook')
        display_notebook.pack(fill=tk.BOTH, expand=True)
        session_data['notebook'] = display_notebook
        
        # Create tabs for this session
        self.create_session_tabs(session_data)
    
    def create_session_tabs(self, session_data):
        """Create monitoring tabs for a specific session"""
        notebook = session_data['notebook']
        
        # Live Packets tab with pop-out button
        packet_frame = ttk.Frame(notebook, style='Dark.TFrame')  
        notebook.add(packet_frame, text="📦 Packets")
        
        # Packet tab header with pop-out button
        packet_header = ttk.Frame(packet_frame, style='Dark.TFrame')
        packet_header.pack(fill=tk.X, padx=5, pady=(5, 0))
        
        ttk.Label(packet_header, text="Live Packet Capture", 
                 style='Dark.TLabel', font=('Arial', 10, 'bold')).pack(side=tk.LEFT)
        
        popout_packet_btn = ttk.Button(packet_header, text="🔗 Pop Out", 
                                      command=lambda: self.pop_out_tab(session_data['id'], 'packets'),
                                      style='Dark.TButton')
        popout_packet_btn.pack(side=tk.RIGHT)
        
        packet_text = scrolledtext.ScrolledText(packet_frame, height=12,
                                               bg='#000000', fg='#00ff00',
                                               insertbackground='white', font=('Consolas', 9))
        packet_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        session_data['packet_text'] = packet_text
        
        # Devices tab with pop-out button
        devices_frame = ttk.Frame(notebook, style='Dark.TFrame')
        notebook.add(devices_frame, text="🖥️ Devices")
        
        # Devices tab header
        devices_header = ttk.Frame(devices_frame, style='Dark.TFrame')
        devices_header.pack(fill=tk.X, padx=5, pady=(5, 0))
        
        ttk.Label(devices_header, text="Network Devices", 
                 style='Dark.TLabel', font=('Arial', 10, 'bold')).pack(side=tk.LEFT)
        
        popout_devices_btn = ttk.Button(devices_header, text="🔗 Pop Out",
                                       command=lambda: self.pop_out_tab(session_data['id'], 'devices'),
                                       style='Dark.TButton')
        popout_devices_btn.pack(side=tk.RIGHT)
        
        columns = ('MAC', 'IP', 'Hostname', 'Vendor', 'Type', 'Packets')
        devices_tree = ttk.Treeview(devices_frame, columns=columns, show='headings', height=8, style='Dark.Treeview')
        for col in columns:
            devices_tree.heading(col, text=col)
            devices_tree.column(col, width=110)
        devices_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        session_data['devices_tree'] = devices_tree
        
        # Applications tab with pop-out button
        apps_frame = ttk.Frame(notebook, style='Dark.TFrame')
        notebook.add(apps_frame, text="📱 Apps")
        
        # Apps tab header
        apps_header = ttk.Frame(apps_frame, style='Dark.TFrame')
        apps_header.pack(fill=tk.X, padx=5, pady=(5, 0))
        
        ttk.Label(apps_header, text="Application Traffic", 
                 style='Dark.TLabel', font=('Arial', 10, 'bold')).pack(side=tk.LEFT)
        
        popout_apps_btn = ttk.Button(apps_header, text="🔗 Pop Out",
                                    command=lambda: self.pop_out_tab(session_data['id'], 'apps'),
                                    style='Dark.TButton')
        popout_apps_btn.pack(side=tk.RIGHT)
        
        app_columns = ('Device', 'Application', 'Protocol', 'Port', 'Packets')
        apps_tree = ttk.Treeview(apps_frame, columns=app_columns, show='headings', height=8, style='Dark.Treeview')
        for col in app_columns:
            apps_tree.heading(col, text=col)
            apps_tree.column(col, width=110)
        apps_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        session_data['apps_tree'] = apps_tree
        
        # Statistics tab with pop-out button
        stats_frame = ttk.Frame(notebook, style='Dark.TFrame')
        notebook.add(stats_frame, text="📊 Stats")
        
        # Stats tab header
        stats_header = ttk.Frame(stats_frame, style='Dark.TFrame')
        stats_header.pack(fill=tk.X, padx=5, pady=(5, 0))
        
        ttk.Label(stats_header, text="Session Statistics", 
                 style='Dark.TLabel', font=('Arial', 10, 'bold')).pack(side=tk.LEFT)
        
        popout_stats_btn = ttk.Button(stats_header, text="🔗 Pop Out",
                                     command=lambda: self.pop_out_tab(session_data['id'], 'stats'),
                                     style='Dark.TButton')
        popout_stats_btn.pack(side=tk.RIGHT)
        
        stats_text = scrolledtext.ScrolledText(stats_frame, height=12,
                                             bg='#1e1e1e', fg='#ffffff',
                                             insertbackground='white', font=('Consolas', 10))
        stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        session_data['stats_text'] = stats_text
        
    def add_new_session(self):
        """Add a new monitoring session"""
        self.session_counter += 1
        session_id = f"Session-{self.session_counter}"
        display_name = f"Monitor {self.session_counter}"
        
        self.create_monitoring_session(session_id, display_name)
        self.log_to_console(f"➕ Added new session: {display_name}")
        
    def remove_current_session(self):
        """Remove the currently selected session"""
        if len(self.monitor_sessions) <= 1:
            self.log_to_console("❌ Cannot remove the last session")
            return
            
        current_tab = self.session_notebook.index(self.session_notebook.select())
        session_id = list(self.monitor_sessions.keys())[current_tab]
        
        # Stop monitoring if active
        if self.monitor_sessions[session_id]['monitoring']:
            self.toggle_session_monitoring(session_id)
            
        # Remove from notebook and sessions
        self.session_notebook.forget(current_tab)
        del self.monitor_sessions[session_id]
        
        # Set new active session
        if self.monitor_sessions:
            self.active_session_id = list(self.monitor_sessions.keys())[0]
            
        self.log_to_console(f"➖ Removed session: {session_id}")
    
    def save_current_session(self):
        """Save complete session state including filters, devices, and packet data"""
        active_session = self.monitor_sessions.get(self.active_session_id)
        if not active_session:
            self.log_to_console("❌ No active session to save")
            return
        
        # Create a dialog to get session name
        import tkinter.simpledialog as simpledialog
        session_name = simpledialog.askstring(
            "Save Session", 
            f"Enter name for session '{active_session['name']}':",
            initialvalue=active_session['name']
        )
        
        if not session_name:
            return
        
        # Get packet data
        packet_data = ""
        if active_session['packet_text']:
            packet_data = active_session['packet_text'].get(1.0, tk.END)
        
        # Create session export data
        session_export = {
            'name': session_name,
            'session_id': self.active_session_id,
            'filters': {
                'mac': active_session['filter_mac'].get(),
                'ip': active_session['filter_ip'].get(),
                'port': active_session['filter_port'].get()
            },
            'devices_found': active_session['devices_found'],
            'packet_data': packet_data,
            'monitoring_state': active_session['monitoring'],
            'statistics': {
                'total_packets': active_session.get('packet_count', 0),
                'devices_count': len(active_session['devices_found']),
                'monitoring_time': active_session.get('monitoring_start_time', '')
            },
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Save to file
        from pathlib import Path
        filename = f"session_{session_name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = Path(filename)
        
        try:
            with open(filepath, 'w') as f:
                json.dump(session_export, f, indent=2, default=str)
            
            self.log_to_console(f"💾 Session saved: {filepath}")
            self.log_to_console(f"   • Filters: MAC={session_export['filters']['mac'] or 'None'}, IP={session_export['filters']['ip'] or 'None'}")
            self.log_to_console(f"   • Devices: {session_export['statistics']['devices_count']} found")
            self.log_to_console(f"   • Packets: {len(packet_data.split(chr(10))) if packet_data else 0} captured")
            
        except Exception as e:
            self.log_to_console(f"❌ Failed to save session: {e}")
    
    def analyze_packets(self):
        """Analyze packets in current session and show statistics"""
        active_session = self.monitor_sessions.get(self.active_session_id)
        if not active_session:
            self.log_to_console("❌ No active session to analyze")
            return
        
        if not active_session['packet_text']:
            self.log_to_console("❌ No packet data to analyze")
            return
        
        # Get packet data
        packet_data = active_session['packet_text'].get(1.0, tk.END)
        if not packet_data.strip():
            self.log_to_console("❌ No packet data found")
            return
        
        # Create analysis window
        analysis_window = tk.Toplevel(self.root)
        analysis_window.title(f"📊 Packet Analysis - {active_session['name']}")
        analysis_window.geometry("800x600")
        analysis_window.configure(bg='#000000')
        
        # Apply dark theme
        style = ttk.Style()
        analysis_window.tk.call('source', 'sun-valley.tcl')
        style.theme_use('sun-valley-dark')
        
        # Main frame
        main_frame = ttk.Frame(analysis_window, style='Dark.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = ttk.Label(main_frame, text=f"📊 Packet Analysis: {active_session['name']}", 
                               style='Dark.TLabel', font=('Arial', 14, 'bold'))
        title_label.pack(pady=(0, 10))
        
        # Analysis notebook
        analysis_notebook = ttk.Notebook(main_frame, style='Dark.TNotebook')
        analysis_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Statistics tab
        stats_frame = ttk.Frame(analysis_notebook, style='Dark.TFrame')
        analysis_notebook.add(stats_frame, text="📈 Statistics")
        
        # Protocol breakdown tab
        protocol_frame = ttk.Frame(analysis_notebook, style='Dark.TFrame')
        analysis_notebook.add(protocol_frame, text="🔍 Protocols")
        
        # Traffic flow tab
        flow_frame = ttk.Frame(analysis_notebook, style='Dark.TFrame')
        analysis_notebook.add(flow_frame, text="🌊 Traffic Flow")
        
        # Parse packet data
        lines = packet_data.strip().split('\n')
        total_packets = len([l for l in lines if l.strip()])
        
        # Basic statistics
        stats_text = scrolledtext.ScrolledText(stats_frame, height=20,
                                              bg='#000000', fg='#00ff00',
                                              insertbackground='white', font=('Consolas', 10))
        stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Analyze packet content
        protocols = {}
        ips = {}
        ports = {}
        
        for line in lines:
            if not line.strip():
                continue
                
            # Simple packet parsing (enhanced for real data when scapy is available)
            if 'TCP' in line.upper():
                protocols['TCP'] = protocols.get('TCP', 0) + 1
            elif 'UDP' in line.upper():
                protocols['UDP'] = protocols.get('UDP', 0) + 1
            elif 'HTTP' in line.upper():
                protocols['HTTP'] = protocols.get('HTTP', 0) + 1
            elif 'HTTPS' in line.upper():
                protocols['HTTPS'] = protocols.get('HTTPS', 0) + 1
            elif 'DNS' in line.upper():
                protocols['DNS'] = protocols.get('DNS', 0) + 1
            elif 'ARP' in line.upper():
                protocols['ARP'] = protocols.get('ARP', 0) + 1
            else:
                protocols['Other'] = protocols.get('Other', 0) + 1
            
            # Extract IPs and ports (basic regex patterns)
            import re
            ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
            port_pattern = r':(\d+)'
            
            ip_matches = re.findall(ip_pattern, line)
            for ip in ip_matches:
                ips[ip] = ips.get(ip, 0) + 1
            
            port_matches = re.findall(port_pattern, line)
            for port in port_matches:
                ports[port] = ports.get(port, 0) + 1
        
        # Display statistics
        stats_content = f"""
📊 PACKET ANALYSIS RESULTS
{'='*50}

📦 Total Packets Captured: {total_packets}
🕒 Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
📱 Session: {active_session['name']}

🔍 PROTOCOL BREAKDOWN:
{'-'*30}
"""
        
        for protocol, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            stats_content += f"{protocol:12}: {count:4} packets ({percentage:5.1f}%)\n"
        
        if ips:
            stats_content += f"\n🌐 TOP IP ADDRESSES:\n{'-'*30}\n"
            for ip, count in sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10]:
                percentage = (count / total_packets * 100) if total_packets > 0 else 0
                stats_content += f"{ip:15}: {count:4} packets ({percentage:5.1f}%)\n"
        
        if ports:
            stats_content += f"\n🔌 TOP PORTS:\n{'-'*30}\n"
            for port, count in sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10]:
                percentage = (count / total_packets * 100) if total_packets > 0 else 0
                port_name = self.get_port_name(int(port))
                stats_content += f"{port:5} ({port_name:12}): {count:4} packets ({percentage:5.1f}%)\n"
        
        stats_content += f"\n📊 DEVICE INFORMATION:\n{'-'*30}\n"
        stats_content += f"Devices Found: {len(active_session['devices_found'])}\n"
        for device in active_session['devices_found'][:5]:  # Show top 5 devices
            stats_content += f"• {device.get('hostname', 'Unknown')} ({device.get('ip', 'Unknown IP')})\n"
        
        stats_text.insert(1.0, stats_content)
        stats_text.config(state=tk.DISABLED)
        
        # Protocol breakdown (pie chart simulation with text)
        protocol_text = scrolledtext.ScrolledText(protocol_frame, height=20,
                                                 bg='#000000', fg='#00ff00',
                                                 insertbackground='white', font=('Consolas', 10))
        protocol_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        protocol_content = f"""
🔍 DETAILED PROTOCOL ANALYSIS
{'='*50}

"""
        for protocol, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            bar_length = int(percentage / 2)  # Scale for display
            bar = '█' * bar_length + '░' * (50 - bar_length)
            protocol_content += f"{protocol:12}: {bar} {count:4} ({percentage:5.1f}%)\n"
        
        protocol_text.insert(1.0, protocol_content)
        protocol_text.config(state=tk.DISABLED)
        
        # Traffic flow analysis
        flow_text = scrolledtext.ScrolledText(flow_frame, height=20,
                                             bg='#000000', fg='#00ff00',
                                             insertbackground='white', font=('Consolas', 10))
        flow_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        flow_content = f"""
🌊 TRAFFIC FLOW ANALYSIS
{'='*50}

📈 Packet Distribution Over Time:
(Note: Real-time analysis available with full packet capture)

🔄 Connection Patterns:
• Most Active IPs: {len(ips)} unique addresses
• Port Usage: {len(ports)} unique ports
• Protocol Distribution: {len(protocols)} protocols detected

💡 INSIGHTS:
"""
        
        if protocols:
            dominant_protocol = max(protocols.items(), key=lambda x: x[1])
            flow_content += f"• Dominant Protocol: {dominant_protocol[0]} ({dominant_protocol[1]} packets)\n"
        
        if ips:
            most_active_ip = max(ips.items(), key=lambda x: x[1])
            flow_content += f"• Most Active IP: {most_active_ip[0]} ({most_active_ip[1]} packets)\n"
        
        if ports:
            most_used_port = max(ports.items(), key=lambda x: x[1])
            port_name = self.get_port_name(int(most_used_port[0]))
            flow_content += f"• Most Used Port: {most_used_port[0]} - {port_name} ({most_used_port[1]} packets)\n"
        
        flow_content += f"""
🎯 RECOMMENDATIONS:
• Monitor {dominant_protocol[0] if protocols else 'dominant'} traffic for anomalies
• Check unusual port activity on port {most_used_port[0] if ports else 'N/A'}
• Investigate high-volume connections from {most_active_ip[0] if ips else 'active IPs'}
"""
        
        flow_text.insert(1.0, flow_content)
        flow_text.config(state=tk.DISABLED)
        
        self.log_to_console(f"📊 Packet analysis complete - analyzed {total_packets} packets")
    
    def get_port_name(self, port):
        """Get common port names"""
        port_names = {
            80: 'HTTP', 443: 'HTTPS', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP', 110: 'POP3',
            143: 'IMAP', 993: 'IMAPS', 995: 'POP3S', 3389: 'RDP', 5432: 'PostgreSQL',
            3306: 'MySQL', 1433: 'MSSQL', 6379: 'Redis', 27017: 'MongoDB'
        }
        return port_names.get(port, 'Unknown')
    
    def close_session_from_split(self, session_data):
        """Close a session from split screen view"""
        if len(self.monitor_sessions) <= 1:
            self.log_to_console("❌ Cannot close the last session")
            return
        
        # Find session ID by matching session data
        session_id = None
        for sid, sdata in self.monitor_sessions.items():
            if sdata == session_data:
                session_id = sid
                break
        
        if not session_id:
            self.log_to_console("❌ Session not found")
            return
        
        # Stop monitoring if active
        if session_data['monitoring']:
            self.toggle_session_monitoring(session_id)
        
        # Remove session
        del self.monitor_sessions[session_id]
        
        # Update active session
        if self.monitor_sessions:
            self.active_session_id = list(self.monitor_sessions.keys())[0]
        
        self.log_to_console(f"❌ Closed session: {session_data['name']}")
        
        # Refresh split view if still active
        if self.split_view_active:
            self.disable_split_view()
            if len(self.monitor_sessions) >= 2:
                self.enable_split_view()
            else:
                self.split_view_active = False
                self.log_to_console("📱 Switched to single view - not enough sessions for split")
    
    def toggle_split_view(self):
        """Toggle between single and split view"""
        self.split_view_active = not self.split_view_active
        
        if self.split_view_active:
            self.log_to_console("🔀 Split view enabled - showing multiple sessions side by side")
            self.enable_split_view()
        else:
            self.log_to_console("📱 Single view enabled - showing tabbed sessions")
            self.disable_split_view()
    
    def enable_split_view(self):
        """Enable split view layout - show sessions side by side"""
        if len(self.monitor_sessions) < 2:
            self.log_to_console("⚠️ Need at least 2 sessions for split view. Add another session first.")
            self.split_view_active = False
            return
        
        # Hide the notebook and create split layout
        self.session_notebook.pack_forget()
        
        # Create horizontal split frame
        self.split_frame = ttk.Frame(self.main_display_frame, style='Dark.TFrame')
        self.split_frame.pack(fill=tk.BOTH, expand=True)
        
        # Get first two sessions for split view
        session_list = list(self.monitor_sessions.values())[:2]
        
        # Left side (first session)
        left_frame = ttk.Frame(self.split_frame, style='Dark.TFrame')
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Create duplicate display for first session
        self.create_split_session_display(left_frame, session_list[0], "left")
        
        # Right side (second session)
        right_frame = ttk.Frame(self.split_frame, style='Dark.TFrame')
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Create duplicate display for second session
        self.create_split_session_display(right_frame, session_list[1], "right")
        
        self.log_to_console(f"🔀 Split view: {session_list[0]['name']} | {session_list[1]['name']}")
    
    def disable_split_view(self):
        """Disable split view and return to tabbed layout"""
        if hasattr(self, 'split_frame'):
            self.split_frame.destroy()
        
        # Clean up split widget references from all sessions
        for session in self.monitor_sessions.values():
            for side in ['left', 'right']:
                split_key = f'split_{side}_packets'
                if split_key in session:
                    del session[split_key]
                split_key = f'split_{side}_devices'
                if split_key in session:
                    del session[split_key]
        
        # Restore the notebook
        self.session_notebook.pack(fill=tk.BOTH, expand=True)
    
    def create_split_session_display(self, parent, session_data, side):
        """Create a session display for split view"""
        # Session header
        header_frame = ttk.Frame(parent, style='Dark.TFrame')
        header_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        session_title = ttk.Label(header_frame, text=f"� {session_data['name']}", 
                                 style='Dark.TLabel', font=('Arial', 12, 'bold'))
        session_title.pack(side=tk.LEFT)
        
        # Control buttons
        controls_frame = ttk.Frame(header_frame, style='Dark.TFrame')
        controls_frame.pack(side=tk.RIGHT)
        
        # Close session button
        close_btn = ttk.Button(controls_frame, text="❌", width=3,
                              command=lambda: self.close_session_from_split(session_data),
                              style='Dark.TButton')
        close_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Status indicator
        status_color = '#51cf66' if session_data['monitoring'] else '#ff6b6b'
        status_text = '● Running' if session_data['monitoring'] else '● Stopped'
        status_label = ttk.Label(controls_frame, text=status_text, 
                                style='Dark.TLabel', foreground=status_color)
        status_label.pack(side=tk.RIGHT, padx=(0, 5))
        
        # Create mini notebook for this session
        mini_notebook = ttk.Notebook(parent, style='Dark.TNotebook')
        mini_notebook.pack(fill=tk.BOTH, expand=True, padx=5)
        
        # Add tabs (just show packets and devices for space)
        # Packets tab
        packets_frame = ttk.Frame(mini_notebook, style='Dark.TFrame')
        mini_notebook.add(packets_frame, text="📦 Packets")
        
        packet_text = scrolledtext.ScrolledText(packets_frame, height=15,
                                               bg='#000000', fg='#00ff00',
                                               insertbackground='white', font=('Consolas', 8))
        packet_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        # Copy current packet data
        if session_data['packet_text']:
            current_content = session_data['packet_text'].get(1.0, tk.END)
            packet_text.insert(1.0, current_content)
        
        # Store reference for updates
        session_data[f'split_{side}_packets'] = packet_text
        
        # Devices tab
        devices_frame = ttk.Frame(mini_notebook, style='Dark.TFrame')
        mini_notebook.add(devices_frame, text="🖥️ Devices")
        
        columns = ('MAC', 'IP', 'Hostname', 'Packets')
        devices_tree = ttk.Treeview(devices_frame, columns=columns, show='headings', 
                                   height=12, style='Dark.Treeview')
        for col in columns:
            devices_tree.heading(col, text=col)
            devices_tree.column(col, width=80)
        devices_tree.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        # Populate with current device data
        for device in session_data['devices_found']:
            devices_tree.insert('', tk.END, values=(
                device.get('mac', '')[:12] + '...',  # Truncate for space
                device.get('ip', ''),
                device.get('hostname', '')[:10] + '...',  # Truncate for space
                device.get('packets', 0)
            ))
        
        # Store reference for updates
        session_data[f'split_{side}_devices'] = devices_tree
    
    def apply_session_filters(self, session_id):
        """Apply filters for a specific session"""
        session = self.monitor_sessions[session_id]
        mac = session['filter_mac'].get().strip()
        ip = session['filter_ip'].get().strip()
        port = session['filter_port'].get().strip()
        
        self.log_to_console(f"📝 Applied filters for {session['name']}: MAC={mac}, IP={ip}, Port={port}")
        
        # Regenerate demo data with new filters
        if not MODULES_AVAILABLE:
            self.generate_session_demo_data(session_id)
    
    def toggle_session_monitoring(self, session_id):
        """Start/stop monitoring for a specific session"""
        session = self.monitor_sessions[session_id]
        
        if not session['monitoring']:
            session['monitoring'] = True
            self.log_to_console(f"🚀 Started monitoring session: {session['name']}")
            
            # Update UI elements
            if 'start_button' in session:
                session['start_button'].config(text="🛑 Stop Monitoring")
            if 'status_label' in session:
                session['status_label'].config(text="● Running", foreground='#51cf66')
            
            # Start monitoring for this session
            if MODULES_AVAILABLE:
                print(f"🔥 Starting REAL packet capture for session {session_id}")
                self.start_session_real_monitoring(session_id)
            else:
                print(f"🎮 Starting demo monitoring for session {session_id}")
                self.start_session_demo_monitoring(session_id)
        else:
            session['monitoring'] = False
            self.log_to_console(f"🛑 Stopped monitoring session: {session['name']}")
            
            # Update UI elements
            if 'start_button' in session:
                session['start_button'].config(text="🚀 Start Monitoring")
            if 'status_label' in session:
                session['status_label'].config(text="● Stopped", foreground='#ff6b6b')
    
    def clear_session_data(self, session_id):
        """Clear data for a specific session"""
        session = self.monitor_sessions[session_id]
        
        # Clear displays
        if session['packet_text']:
            session['packet_text'].delete(1.0, tk.END)
        if session['devices_tree']:
            for item in session['devices_tree'].get_children():
                session['devices_tree'].delete(item)
        if session['apps_tree']:
            for item in session['apps_tree'].get_children():
                session['apps_tree'].delete(item)
        if session['stats_text']:
            session['stats_text'].delete(1.0, tk.END)
            
        # Reset counters
        session['packets_captured'] = 0
        session['devices_found'] = []
        session['applications_detected'] = []
        
        self.log_to_console(f"🗑️ Cleared data for session: {session['name']}")
    
    def pop_out_tab(self, session_id, tab_type):
        """Pop out a tab into a separate window"""
        session = self.monitor_sessions[session_id]
        
        # Create new window
        popup = tk.Toplevel(self.root)
        popup.title(f"HCC Monitor - {session['name']} - {tab_type.title()}")
        popup.geometry("800x600")
        popup.configure(bg='#1e1e1e')
        
        # Set same icon as main window
        try:
            local_icon = os.path.join(os.path.dirname(__file__), 'favicon.png')
            if os.path.exists(local_icon):
                icon_image = tk.PhotoImage(file=local_icon)
                popup.iconphoto(True, icon_image)
        except:
            pass
        
        # Apply dark title bar
        try:
            popup.update()
            import ctypes
            hwnd = ctypes.windll.user32.GetParent(popup.winfo_id())
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 20, ctypes.byref(ctypes.c_int(1)), ctypes.sizeof(ctypes.c_int)
            )
        except:
            pass
        
        # Create content based on tab type
        if tab_type == 'packets':
            self.create_popup_packets_view(popup, session)
        elif tab_type == 'devices':
            self.create_popup_devices_view(popup, session)
        elif tab_type == 'apps':
            self.create_popup_apps_view(popup, session)
        elif tab_type == 'stats':
            self.create_popup_stats_view(popup, session)
            
        self.log_to_console(f"🔗 Popped out {tab_type} view for {session['name']}")
    
    def create_popup_packets_view(self, popup, session):
        """Create pop-out packets view"""
        main_frame = ttk.Frame(popup, style='Dark.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header = ttk.Label(main_frame, text=f"Live Packets - {session['name']}", 
                          style='Dark.TLabel', font=('Arial', 14, 'bold'))
        header.pack(pady=(0, 10))
        
        # Filter info
        filter_info = ttk.Label(main_frame, 
                               text=f"Filters: MAC={session['filter_mac'].get()} | IP={session['filter_ip'].get()} | Port={session['filter_port'].get() or 'All'}", 
                               style='Dark.TLabel')
        filter_info.pack(pady=(0, 10))
        
        # Packet display (larger in pop-out)
        packet_text = scrolledtext.ScrolledText(main_frame, height=30,
                                               bg='#000000', fg='#00ff00',
                                               insertbackground='white', font=('Consolas', 9))
        packet_text.pack(fill=tk.BOTH, expand=True)
        
        # Copy current packets to pop-out
        if session['packet_text']:
            current_content = session['packet_text'].get(1.0, tk.END)
            packet_text.insert(1.0, current_content)
            
        # Store reference for future updates
        session[f'popup_packets_{popup.winfo_id()}'] = packet_text
    
    def create_popup_devices_view(self, popup, session):
        """Create pop-out devices view"""
        main_frame = ttk.Frame(popup, style='Dark.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header = ttk.Label(main_frame, text=f"Network Devices - {session['name']}", 
                          style='Dark.TLabel', font=('Arial', 14, 'bold'))
        header.pack(pady=(0, 10))
        
        # Devices tree (larger in pop-out)
        columns = ('MAC', 'IP', 'Hostname', 'Vendor', 'Type', 'Packets')
        devices_tree = ttk.Treeview(main_frame, columns=columns, show='headings', height=25, style='Dark.Treeview')
        for col in columns:
            devices_tree.heading(col, text=col)
            devices_tree.column(col, width=130)
        devices_tree.pack(fill=tk.BOTH, expand=True)
        
        # Copy current devices to pop-out
        self.update_popup_devices_tree(devices_tree, session['devices_found'])
        
        # Store reference for future updates
        session[f'popup_devices_{popup.winfo_id()}'] = devices_tree
    
    def create_popup_apps_view(self, popup, session):
        """Create pop-out applications view"""
        main_frame = ttk.Frame(popup, style='Dark.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header = ttk.Label(main_frame, text=f"Application Traffic - {session['name']}", 
                          style='Dark.TLabel', font=('Arial', 14, 'bold'))
        header.pack(pady=(0, 10))
        
        # Apps tree (larger in pop-out)
        app_columns = ('Device', 'Application', 'Protocol', 'Port', 'Packets')
        apps_tree = ttk.Treeview(main_frame, columns=app_columns, show='headings', height=25, style='Dark.Treeview')
        for col in app_columns:
            apps_tree.heading(col, text=col)
            apps_tree.column(col, width=150)
        apps_tree.pack(fill=tk.BOTH, expand=True)
        
        # Copy current apps to pop-out
        self.update_popup_apps_tree(apps_tree, session['applications_detected'])
        
        # Store reference for future updates
        session[f'popup_apps_{popup.winfo_id()}'] = apps_tree
    
    def create_popup_stats_view(self, popup, session):
        """Create pop-out statistics view"""
        main_frame = ttk.Frame(popup, style='Dark.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header = ttk.Label(main_frame, text=f"Statistics - {session['name']}", 
                          style='Dark.TLabel', font=('Arial', 14, 'bold'))
        header.pack(pady=(0, 10))
        
        # Stats display (larger in pop-out)
        stats_text = scrolledtext.ScrolledText(main_frame, height=30,
                                             bg='#1e1e1e', fg='#ffffff',
                                             insertbackground='white', font=('Consolas', 10))
        stats_text.pack(fill=tk.BOTH, expand=True)
        
        # Copy current stats to pop-out
        if session['stats_text']:
            current_content = session['stats_text'].get(1.0, tk.END)
            stats_text.insert(1.0, current_content)
            
        # Store reference for future updates
        session[f'popup_stats_{popup.winfo_id()}'] = stats_text
    
    def update_popup_devices_tree(self, tree, devices_data):
        """Update a pop-out devices tree"""
        # Clear existing items
        for item in tree.get_children():
            tree.delete(item)
            
        # Add current devices
        for device in devices_data:
            tree.insert('', tk.END, values=(
                device.get('mac', ''),
                device.get('ip', ''),
                device.get('hostname', ''),
                device.get('vendor', ''),
                device.get('type', ''),
                device.get('packets', 0)
            ))
    
    def update_popup_apps_tree(self, tree, apps_data):
        """Update a pop-out applications tree"""
        # Clear existing items
        for item in tree.get_children():
            tree.delete(item)
            
        # Add current applications
        for app in apps_data:
            tree.insert('', tk.END, values=(
                app.get('device', ''),
                app.get('app', ''),
                app.get('protocol', ''),
                app.get('port', ''),
                app.get('count', 0)
            ))
    
    def start_session_demo_monitoring(self, session_id):
        """Start demo monitoring for a specific session"""
        def demo_loop():
            session = self.monitor_sessions[session_id]
            # Filter out placeholder text and use defaults for demo
            mac_val = session['filter_mac'].get()
            if mac_val.startswith("e.g.,") or not mac_val:
                mac = "78:B6:EE:F1:06:3F"
            else:
                mac = mac_val
                
            ip_val = session['filter_ip'].get()
            if ip_val.startswith("e.g.,") or not ip_val:
                ip = "10.14.0.2"
            else:
                ip = ip_val
                
            port_val = session['filter_port'].get()
            if port_val.startswith("e.g.,") or not port_val:
                port_filter = ""
            else:
                port_filter = port_val
            
            # Generate sample packets
            packet_templates = [
                f"📦 {ip}:443 -> 142.250.185.78:443 [HTTPS] Chrome (MAC: {mac})",
                f"📦 {ip}:6667 -> 162.159.130.232:6667 [IRC] Discord (MAC: {mac})",
                f"📦 {ip}:80 -> 93.184.216.34:80 [HTTP] Web (MAC: {mac})"
            ]
            
            if port_filter:
                try:
                    port_num = int(port_filter)
                    packet_templates = [f"📦 {ip}:{port_num} -> 8.8.8.8:53 [PORT-{port_num}] Filtered (MAC: {mac})"]
                except ValueError:
                    pass
            
            packet_index = 0
            while session['monitoring']:
                if packet_index < len(packet_templates):
                    self.display_session_packet(session_id, packet_templates[packet_index])
                    session['packets_captured'] += 1
                    packet_index += 1
                else:
                    packet_index = 0
                time.sleep(2)
        
        # Start demo thread
        demo_thread = threading.Thread(target=demo_loop, daemon=True)
        demo_thread.start()
    
    def start_session_real_monitoring(self, session_id):
        """Start real packet capture for a specific session"""
        def packet_capture_loop():
            session = self.monitor_sessions[session_id]
            mac_filter = session['filter_mac'].get()
            ip_filter = session['filter_ip'].get()
            port_filter = session['filter_port'].get()
            
            try:
                # Initialize packet capture for this session
                capture = PacketCapture()
                
                # Set up filters if specified
                filter_dict = {}
                if mac_filter:
                    filter_dict['mac'] = mac_filter
                if ip_filter:
                    filter_dict['ip'] = ip_filter
                if port_filter:
                    filter_dict['port'] = int(port_filter)
                
                if filter_dict:
                    capture.set_filter(filter_dict)
                
                # Set up callback for packet processing
                def process_packet(packet_data):
                    if not session['monitoring']:
                        return
                        
                    try:
                        # Format packet for display from Windows netstat data
                        src_ip = packet_data.get('src_ip', 'Unknown')
                        dst_ip = packet_data.get('dst_ip', 'Unknown')
                        src_port = packet_data.get('src_port', '')
                        dst_port = packet_data.get('dst_port', '')
                        protocol = packet_data.get('protocol', 'Unknown')
                        app_name = packet_data.get('app', 'Unknown')
                        
                        # Try to identify application
                        app_name = 'Unknown'
                        if protocol == 'TCP':
                            if dst_port == 80:
                                app_name = 'Web'
                            elif dst_port == 443:
                                app_name = 'HTTPS'
                            elif dst_port == 22:
                                app_name = 'SSH'
                            elif dst_port == 21:
                                app_name = 'FTP'
                        
                        # Format display string
                        port_info = f"{src_port}:{dst_port}" if src_port and dst_port else ""
                        display_text = f"📦 {src_ip}:{port_info} -> {dst_ip} [{protocol}] {app_name} (MAC: {packet_data.get('src_mac', 'Unknown')})"
                        
                        # Display packet in session with error handling
                        print(f"🔍 DEBUG: Processing packet: {display_text[:50]}...")
                        try:
                            self.display_session_packet(session_id, display_text)
                            print(f"✅ DEBUG: Packet display called successfully")
                        except Exception as display_error:
                            print(f"❌ DEBUG: Display packet failed: {display_error}")
                        
                        # Update session statistics
                        session['packets_captured'] += 1
                        
                        # Track device if we have MAC and IP
                        if packet_data.get('src_mac') and packet_data.get('src_mac') != 'Unknown' and src_ip and src_ip != 'Unknown':
                            self.device_tracker.add_device_observation(packet_data.get('src_mac'), src_ip, packet_data)
                        
                        # Add to applications list if not already present
                        app_info = {
                            'device': src_ip,
                            'app': app_name,
                            'protocol': protocol,
                            'port': dst_port,
                            'count': 1
                        }
                        if app_info not in session['applications_detected']:
                            session['applications_detected'].append(app_info)
                            
                    except Exception as e:
                        # Don't spam errors - just log occasionally
                        if not hasattr(session, 'error_count'):
                            session['error_count'] = 0
                        session['error_count'] += 1
                        if session['error_count'] <= 3:  # Only log first 3 errors
                            self.log_to_console(f"⚠️ Packet processing error: {e}")
                
                capture.add_callback(process_packet)
                
                # Start capturing packets
                self.log_to_console(f"🔥 Starting real packet capture for {session['name']}")
                capture.start_capture()
                
                # Keep capturing while monitoring is active
                while session['monitoring']:
                    time.sleep(1)  # Check once per second instead of 10 times
                    
                # Stop capture when monitoring is stopped
                capture.stop_capture()
                self.log_to_console(f"🛑 Stopped real packet capture for {session['name']}")
                
            except Exception as e:
                self.log_to_console(f"❌ Packet capture error for {session['name']}: {e}")
                # Fall back to demo mode if real capture fails
                self.log_to_console(f"🔄 Falling back to demo mode for {session['name']}")
                self.start_session_demo_monitoring(session_id)
        
        # Start capture thread
        capture_thread = threading.Thread(target=packet_capture_loop, daemon=True)
        capture_thread.start()
    
    def display_session_packet(self, session_id, packet_info):
        """Display packet in session-specific display"""
        session = self.monitor_sessions.get(session_id)
        if not session:
            print(f"❌ DEBUG: No session found for ID: {session_id}")
            return
        
        def update_display():
            timestamp = datetime.now().strftime('%H:%M:%S')
            # Clean packet info to avoid encoding issues
            clean_packet_info = packet_info.replace('📦', '[PKT]').replace('🔥', '[HOT]').replace('⚠️', '[WARN]')
            packet_line = f"[{timestamp}] {clean_packet_info}\n"
            
            print(f"🔍 DEBUG: Attempting to display packet: {packet_line.strip()}")  # Debug output
            
            # Update main session display
            if session['packet_text']:
                try:
                    print(f"📦 DEBUG: Inserting into widget: {type(session['packet_text'])}")
                    session['packet_text'].insert(tk.END, packet_line)
                    session['packet_text'].see(tk.END)
                    print(f"✅ DEBUG: Packet inserted successfully")
                    
                    # Keep only last 200 lines for better history
                    content = session['packet_text'].get(1.0, tk.END)
                    lines = content.split('\n')
                    if len(lines) > 200:
                        # Remove oldest lines
                        session['packet_text'].delete(1.0, f"{len(lines)-200}.0")
                except Exception as e:
                    print(f"❌ DEBUG: Widget operation failed: {e}")
            else:
                print(f"❌ DEBUG: No packet_text widget found for session {session_id}")
            
            # Update split screen displays if they exist
            if self.split_view_active:
                for side in ['left', 'right']:
                    split_widget_key = f'split_{side}_packets'
                    if split_widget_key in session:
                        try:
                            split_widget = session[split_widget_key]
                            split_widget.insert(tk.END, packet_line)
                            split_widget.see(tk.END)
                            
                            # Keep only last 200 lines in split display too
                            content = split_widget.get(1.0, tk.END)
                            lines = content.split('\n')
                            if len(lines) > 200:
                                split_widget.delete(1.0, f"{len(lines)-200}.0")
                        except (tk.TclError, KeyError):
                            # Widget might be destroyed, clean up reference
                            if split_widget_key in session:
                                del session[split_widget_key]
        
        # Schedule update immediately for better responsiveness with error handling
        try:
            if hasattr(self, 'root') and self.root:
                self.root.after(0, update_display)
            else:
                print("❌ DEBUG: No root window available")
                # Fallback: try direct update
                update_display()
        except Exception as e:
            print(f"❌ DEBUG: GUI update scheduling failed: {e}")
            # Last resort: direct call
            try:
                update_display()
            except Exception as e2:
                print(f"❌ DEBUG: Direct GUI update failed: {e2}")
    
    def update_session_displays(self, session_id):
        """Update displays for a specific session"""
        session = self.monitor_sessions[session_id] 
        
        # Generate demo data for this session
        if not MODULES_AVAILABLE:
            self.generate_session_demo_data(session_id)
            
        # Update session devices tree
        if session['devices_tree']:
            # Clear existing items
            for item in session['devices_tree'].get_children():
                session['devices_tree'].delete(item)
                
            # Add current devices
            for device in session['devices_found']:
                session['devices_tree'].insert('', tk.END, values=(
                    device.get('mac', ''),
                    device.get('ip', ''),
                    device.get('hostname', ''),
                    device.get('vendor', ''),
                    device.get('type', ''),
                    device.get('packets', 0)
                ))
        
        # Update session applications tree
        if session['apps_tree']:
            # Clear existing items
            for item in session['apps_tree'].get_children():
                session['apps_tree'].delete(item)
                
            # Add current applications
            for app in session['applications_detected']:
                session['apps_tree'].insert('', tk.END, values=(
                    app.get('device', ''),
                    app.get('app', ''),
                    app.get('protocol', ''),
                    app.get('port', ''),
                    app.get('count', 0)
                ))
        
        # Update session statistics
        if session['stats_text']:
            stats = [
                f"📊 SESSION STATISTICS - {session['name']}",
                f"=" * 50,
                f"📦 Packets Captured: {session['packets_captured']}",
                f"🖥️ Devices Found: {len(session['devices_found'])}",
                f"📱 Applications: {len(session['applications_detected'])}",
                f"",
                f"🎯 CURRENT FILTERS:",
                f"   MAC:  {session['filter_mac'].get()}",
                f"   IP:   {session['filter_ip'].get()}",
                f"   Port: {session['filter_port'].get() or 'All Ports'}",
                f"",
                f"🔄 Status: {'Active' if session['monitoring'] else 'Stopped'}"
            ]
            
            def update_stats():
                session['stats_text'].delete(1.0, tk.END)
                session['stats_text'].insert(1.0, '\n'.join(stats))
            # Schedule stats update with delay
            self.root.after(200, update_stats)
        
        # Update any pop-out windows for this session
        self.update_session_popouts(session_id)
    
    def update_session_popouts(self, session_id):
        """Update any pop-out windows for this session"""
        session = self.monitor_sessions[session_id]
        
        # Update pop-out devices
        for key, popup_tree in session.items():
            if key.startswith('popup_devices_') and popup_tree:
                try:
                    self.update_popup_devices_tree(popup_tree, session['devices_found'])
                except:
                    pass  # Pop-out window may have been closed
                    
        # Update pop-out applications
        for key, popup_tree in session.items():
            if key.startswith('popup_apps_') and popup_tree:
                try:
                    self.update_popup_apps_tree(popup_tree, session['applications_detected'])
                except:
                    pass  # Pop-out window may have been closed
                    
        # Update pop-out packets
        for key, popup_text in session.items():
            if key.startswith('popup_packets_') and popup_text:
                try:
                    # Copy current packets to pop-out
                    if session['packet_text']:
                        current_content = session['packet_text'].get(1.0, tk.END)
                        popup_text.delete(1.0, tk.END)
                        popup_text.insert(1.0, current_content)
                except:
                    pass  # Pop-out window may have been closed
                    
        # Update pop-out stats
        for key, popup_stats in session.items():
            if key.startswith('popup_stats_') and popup_stats:
                try:
                    # Copy current stats to pop-out
                    if session['stats_text']:
                        current_content = session['stats_text'].get(1.0, tk.END)
                        popup_stats.delete(1.0, tk.END)
                        popup_stats.insert(1.0, current_content)
                except:
                    pass  # Pop-out window may have been closed
    
    def generate_session_demo_data(self, session_id):
        """Generate demo data for a specific session"""
        session = self.monitor_sessions[session_id]
        
        # Get session filter values (filter out placeholder text)
        mac_val = session['filter_mac'].get().strip()
        if mac_val.startswith("e.g.,") or not mac_val:
            target_mac = "78:B6:EE:F1:06:3F"
        else:
            target_mac = mac_val
            
        ip_val = session['filter_ip'].get().strip()
        if ip_val.startswith("e.g.,") or not ip_val:
            target_ip = "10.14.0.2"
        else:
            target_ip = ip_val
            
        port_val = session['filter_port'].get().strip()
        if port_val.startswith("e.g.,") or not port_val:
            target_port = ""
        else:
            target_port = port_val
        
        # Generate devices data
        session['devices_found'] = [
            {"mac": target_mac, "ip": target_ip, "hostname": "Target-Device", 
             "vendor": "Unknown", "type": "Computer", "packets": session['packets_captured'] + 45},
            {"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.1", "hostname": "Router", 
             "vendor": "TP-Link", "type": "Gateway", "packets": 12},
            {"mac": "11:22:33:44:55:66", "ip": "10.0.0.100", "hostname": "Phone", 
             "vendor": "Samsung", "type": "Mobile", "packets": 8}
        ]
        
        # Generate applications data based on port filter
        if target_port:
            try:
                port_num = int(target_port)
                if port_num == 443:
                    app_name = "HTTPS Browser"
                elif port_num == 80:
                    app_name = "HTTP Browser"
                elif port_num == 22:
                    app_name = "SSH Client"
                else:
                    app_name = f"Port-{port_num} App"
                    
                session['applications_detected'] = [
                    {"device": target_ip, "app": app_name, "protocol": "TCP", 
                     "port": port_num, "count": session['packets_captured'] + 15}
                ]
            except ValueError:
                # Invalid port, show general apps
                session['applications_detected'] = [
                    {"device": target_ip, "app": "Chrome", "protocol": "HTTPS", 
                     "port": 443, "count": session['packets_captured'] + 25},
                    {"device": target_ip, "app": "Discord", "protocol": "WSS", 
                     "port": 443, "count": 12},
                    {"device": target_ip, "app": "Steam", "protocol": "TCP", 
                     "port": 27036, "count": 8}
                ]
        else:
            # No port filter, show general applications
            session['applications_detected'] = [
                {"device": target_ip, "app": "Chrome", "protocol": "HTTPS", 
                 "port": 443, "count": session['packets_captured'] + 25},
                {"device": target_ip, "app": "Discord", "protocol": "WSS", 
                 "port": 443, "count": 12},
                {"device": target_ip, "app": "Steam", "protocol": "TCP", 
                 "port": 27036, "count": 8}
            ]
    
    def create_global_console(self, parent):
        """Create global console for system messages"""
        console_frame = ttk.Frame(parent, style='Dark.TFrame')
        console_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Label(console_frame, text="System Console:", style='Dark.TLabel', 
                 font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        
        self.console_text = scrolledtext.ScrolledText(console_frame, height=4,
                                                     bg='#012456', fg='#ffffff',
                                                     insertbackground='white', font=('Consolas', 9))
        self.console_text.pack(fill=tk.X, padx=5)
        
        # Initial console message
        self.log_to_console("HCC Network Monitor System Console Initialized")
        self.log_to_console("Multi-session monitoring ready...")
    
    def create_main_control_panel(self, parent):
        """Create main control panel at the top"""
        control_frame = ttk.Frame(parent, style='Dark.TFrame')
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Left side - Main control buttons
        button_frame = ttk.Frame(control_frame, style='Dark.TFrame')
        button_frame.pack(side=tk.LEFT)
        
        self.main_start_button = ttk.Button(button_frame, text="🚀 Start All Sessions", 
                                           command=self.start_all_sessions, style='Dark.TButton')
        self.main_start_button.pack(side=tk.LEFT, padx=(0, 10))
        
        clear_all_button = ttk.Button(button_frame, text="🗑️ Clear All Data", 
                                     command=self.clear_all_data, style='Dark.TButton')
        clear_all_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Right side - Global configuration management
        config_frame = ttk.Frame(control_frame, style='Dark.TFrame')
        config_frame.pack(side=tk.RIGHT)
        
        # Load configuration dropdown
        ttk.Label(config_frame, text="Config:", style='Dark.TLabel').pack(side=tk.LEFT, padx=(0, 5))
        self.config_combo = ttk.Combobox(config_frame, textvariable=self.selected_config, 
                                        width=15, state="readonly")
        self.config_combo.pack(side=tk.LEFT, padx=(0, 5))
        self.config_combo.bind('<<ComboboxSelected>>', self.load_selected_config)
        
        load_button = ttk.Button(config_frame, text="📂 Load", 
                                command=self.load_selected_config, style='Dark.TButton')
        load_button.pack(side=tk.LEFT, padx=(0, 5))
        
        delete_button = ttk.Button(config_frame, text="🗑️", 
                                  command=self.delete_selected_config, style='Dark.TButton')
        delete_button.pack(side=tk.LEFT, padx=(0, 5))
        
        # Save configuration
        ttk.Label(config_frame, text="Save as:", style='Dark.TLabel').pack(side=tk.LEFT, padx=(10, 5))
        save_entry = tk.Entry(config_frame, textvariable=self.config_name, width=12,
                             bg='#2d2d2d', fg='white', insertbackground='white')
        save_entry.pack(side=tk.LEFT, padx=(0, 5))
        
        save_button = ttk.Button(config_frame, text="💾 Save", 
                                command=self.save_current_config, style='Dark.TButton')
        save_button.pack(side=tk.LEFT)
        
    def create_control_panel(self, parent):
        """Create control buttons and filters"""
        control_frame = ttk.Frame(parent, style='Dark.TFrame')
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Top row - Control buttons
        button_frame = ttk.Frame(control_frame, style='Dark.TFrame')
        button_frame.pack(fill=tk.X, pady=(0, 5))
        
        # Left side buttons
        left_buttons = ttk.Frame(button_frame, style='Dark.TFrame')
        left_buttons.pack(side=tk.LEFT)
        
        self.start_button = ttk.Button(left_buttons, text="🚀 Start Monitoring", 
                                      command=self.toggle_monitoring, style='Dark.TButton')
        self.start_button.pack(side=tk.LEFT, padx=(0, 10))
        
        clear_button = ttk.Button(left_buttons, text="🗑️ Clear Data", 
                                 command=self.clear_data, style='Dark.TButton')
        clear_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Right side - Config management
        config_frame = ttk.Frame(button_frame, style='Dark.TFrame')
        config_frame.pack(side=tk.RIGHT)
        
        # Load configuration dropdown
        ttk.Label(config_frame, text="Config:", style='Dark.TLabel').pack(side=tk.LEFT, padx=(0, 5))
        self.config_combo = ttk.Combobox(config_frame, textvariable=self.selected_config, 
                                        width=15, state="readonly")
        self.config_combo.pack(side=tk.LEFT, padx=(0, 5))
        self.config_combo.bind('<<ComboboxSelected>>', self.load_selected_config)
        
        load_button = ttk.Button(config_frame, text="📂 Load", 
                                command=self.load_selected_config, style='Dark.TButton')
        load_button.pack(side=tk.LEFT, padx=(0, 5))
        
        delete_button = ttk.Button(config_frame, text="🗑️", 
                                  command=self.delete_selected_config, style='Dark.TButton')
        delete_button.pack(side=tk.LEFT, padx=(0, 5))
        
        # Bottom row - Filters
        filter_frame = ttk.Frame(control_frame, style='Dark.TFrame')
        filter_frame.pack(fill=tk.X)
        
        # Left side - Filter inputs
        inputs_frame = ttk.Frame(filter_frame, style='Dark.TFrame')
        inputs_frame.pack(side=tk.LEFT)
        
        # MAC Filter
        ttk.Label(inputs_frame, text="MAC:", style='Dark.TLabel').pack(side=tk.LEFT, padx=(0, 5))
        mac_entry = tk.Entry(inputs_frame, textvariable=self.filter_mac, width=18, 
                            bg='#2d2d2d', fg='white', insertbackground='white')
        mac_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        # IP Filter
        ttk.Label(inputs_frame, text="IP:", style='Dark.TLabel').pack(side=tk.LEFT, padx=(0, 5))
        ip_entry = tk.Entry(inputs_frame, textvariable=self.filter_ip, width=12, 
                           bg='#2d2d2d', fg='white', insertbackground='white')
        ip_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        # Port Filter
        ttk.Label(inputs_frame, text="Port:", style='Dark.TLabel').pack(side=tk.LEFT, padx=(0, 5))
        port_entry = tk.Entry(inputs_frame, textvariable=self.filter_port, width=8, 
                             bg='#2d2d2d', fg='white', insertbackground='white')
        port_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        # Right side - Action buttons
        actions_frame = ttk.Frame(filter_frame, style='Dark.TFrame')
        actions_frame.pack(side=tk.RIGHT)
        
        # Save configuration
        ttk.Label(actions_frame, text="Save as:", style='Dark.TLabel').pack(side=tk.LEFT, padx=(0, 5))
        save_entry = tk.Entry(actions_frame, textvariable=self.config_name, width=12,
                             bg='#2d2d2d', fg='white', insertbackground='white')
        save_entry.pack(side=tk.LEFT, padx=(0, 5))
        
        save_button = ttk.Button(actions_frame, text="💾 Save", 
                                command=self.save_current_config, style='Dark.TButton')
        save_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Apply button
        apply_button = ttk.Button(actions_frame, text="📝 Apply Filters", 
                                 command=self.apply_filters, style='Dark.TButton')
        apply_button.pack(side=tk.LEFT)
        
    def monitoring_loop(self):
        """Real monitoring loop"""
        try:
            # Apply current filters to traffic filter
            mac = self.filter_mac.get().strip().lower()
            ip = self.filter_ip.get().strip()
            port = self.filter_port.get().strip()
            
            if mac:
                self.traffic_filter.add_mac_filter(mac)
                self.log_to_console(f"🎯 Monitoring MAC: {mac}")
            if ip:
                self.traffic_filter.add_ip_filter(ip)
                self.log_to_console(f"🎯 Monitoring IP: {ip}")
            if port:
                try:
                    port_num = int(port)
                    self.traffic_filter.add_port_filter(port_num)
                    self.log_to_console(f"🎯 Monitoring Port: {port_num}")
                except ValueError:
                    self.log_to_console(f"❌ Invalid port: {port}")
            
            self.network_capture.start_capture(self.process_packet_with_filter)
        except Exception as e:
            self.log_to_console(f"❌ Monitoring error: {e}")
    
    def process_packet_with_filter(self, packet):
        """Process packet with filtering applied"""
        try:
            # Check if packet matches our filters
            if hasattr(self, 'traffic_filter') and not self.traffic_filter.should_capture_packet(packet):
                return  # Skip this packet
                
            # Process the packet
            self.process_packet(packet)
        except Exception as e:
            self.log_to_console(f"❌ Error filtering packet: {e}")
            
    def demo_monitoring_loop(self):
        """Demo monitoring loop"""
        # Use current filter values for demo (filter out placeholder text)
        ip_val = self.filter_ip.get().strip()
        if ip_val.startswith("e.g.,") or not ip_val:
            target_ip = "10.0.0.151"
        else:
            target_ip = ip_val
            
        mac_val = self.filter_mac.get().strip()
        if mac_val.startswith("e.g.,") or not mac_val:
            target_mac = "2e:80:02:62:18:46"
        else:
            target_mac = mac_val
        target_port = self.filter_port.get().strip()
        
        # Generate packets based on port filter
        if target_port:
            try:
                port_num = int(target_port)
                sample_packets = [
                    f"📦 {target_ip}:{port_num} -> 142.250.185.78:443 [PORT-{port_num}] Filtered Traffic (MAC: {target_mac})",
                    f"📦 {target_ip}:{port_num} -> 162.159.130.232:443 [PORT-{port_num}] Filtered Traffic (MAC: {target_mac})",
                    f"📦 142.250.185.78:443 -> {target_ip}:{port_num} [PORT-{port_num}] Response Traffic (MAC: {target_mac})",
                    f"📦 {target_ip}:{port_num} -> 208.78.164.9:80 [PORT-{port_num}] Outbound Traffic (MAC: {target_mac})"
                ]
                self.log_to_console(f"🎮 Demo monitoring port {port_num} on {target_ip} / {target_mac}")
            except ValueError:
                target_port = None
        
        if not target_port:
            sample_packets = [
                f"📦 {target_ip}:443 -> 142.250.185.78:443 [HTTPS] Chrome Traffic (MAC: {target_mac})",
                f"📦 {target_ip}:6667 -> 162.159.130.232:6667 [IRC] Discord Traffic (MAC: {target_mac})", 
                f"📦 {target_ip}:27036 -> 208.78.164.9:27036 [TCP] Steam Traffic (MAC: {target_mac})",
                f"📦 {target_ip}:53 -> 8.8.8.8:53 [DNS] DNS Query (MAC: {target_mac})",
                f"📦 {target_ip}:80 -> 93.184.216.34:80 [HTTP] Web Traffic (MAC: {target_mac})"
            ]
            self.log_to_console(f"🎮 Demo monitoring device: {target_ip} / {target_mac}")
        
        packet_index = 0
        while self.monitoring:
            if packet_index < len(sample_packets):
                self.display_packet(sample_packets[packet_index])
                packet_index += 1
                self.packets_captured += 1
                
                # Trigger data regeneration every few packets
                if self.packets_captured % 5 == 0:
                    self.root.after(0, self.generate_demo_data)
            else:
                packet_index = 0  # Loop the demo packets
            time.sleep(2)
            
    def process_packet(self, packet_data):
        """Process captured packet data from Windows netstat"""
        try:
            # Update packet count
            self.packets_captured += 1
            
            # Format real packet info
            timestamp = time.strftime("%H:%M:%S")
            src = f"{packet_data['src_ip']}:{packet_data['src_port']}"
            dst = f"{packet_data['dst_ip']}:{packet_data['dst_port']}"
            protocol = packet_data['protocol']
            app = packet_data['app']
            
            # Display REAL packet (no fake MAC since Windows netstat doesn't provide it)
            packet_info = f"[{timestamp}] 📦 {src} -> {dst} [{protocol}] {app} (REAL CONNECTION)"
            self.display_packet(packet_info)
            
            # Log to console that this is real data
            self.log_to_console(f"✅ Real connection captured: {src} -> {dst}")
                    
            # Update session data
            current_session = self.get_current_session()
            if current_session:
                current_session['packets_captured'] += 1
                    
        except Exception as e:
            self.log_to_console(f"❌ Error processing packet: {e}")
            
    def display_packet(self, packet_info):
        """Display packet in GUI - routes to active session display"""
        # Get the active session to display packets
        active_session = self.get_current_session()
        if active_session and active_session['packet_text']:
            # Use the session-based packet display method
            self.display_session_packet(active_session['id'], packet_info)
        else:
            # Fallback to console if no active session
            self.log_to_console(f"📦 {packet_info}")
        
    def toggle_monitoring(self):
        """Toggle main monitoring on/off - controls the original single-session monitoring"""
        if not hasattr(self, 'monitoring'):
            self.monitoring = False
            
        if not self.monitoring:
            # Start monitoring
            self.monitoring = True
            self.start_button.config(text="🛑 Stop Monitoring", state=tk.NORMAL)
            self.log_to_console("🚀 Starting main monitoring session")
            
            # Clear the main packet display for fresh start
            if hasattr(self, 'packet_text') and self.packet_text:
                self.packet_text.delete(1.0, tk.END)
            
            # Start monitoring thread
            if MODULES_AVAILABLE:
                self.log_to_console("🔥 Starting real packet capture")
                monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
                monitor_thread.start()
            else:
                self.log_to_console("🎮 Starting demo monitoring")
                demo_thread = threading.Thread(target=self.demo_monitoring_loop, daemon=True)
                demo_thread.start()
        else:
            # Stop monitoring
            self.monitoring = False
            self.start_button.config(text="🚀 Start Monitoring", state=tk.NORMAL)
            self.log_to_console("🛑 Stopped main monitoring session")
    
    def apply_filters(self):
        """Apply current filters"""
        self.log_to_console("📝 Applying filters...")
        mac = self.filter_mac.get().strip().lower()
        ip = self.filter_ip.get().strip()
        port = self.filter_port.get().strip()
        
        if mac:
            self.log_to_console(f"🔍 MAC Filter: {mac}")
            if hasattr(self, 'traffic_filter'):
                self.traffic_filter.add_mac_filter(mac)
        if ip:
            self.log_to_console(f"🔍 IP Filter: {ip}")
            if hasattr(self, 'traffic_filter'):
                self.traffic_filter.add_ip_filter(ip)
        if port:
            try:
                port_num = int(port)
                self.log_to_console(f"🔍 Port Filter: {port_num}")
                if hasattr(self, 'traffic_filter'):
                    self.traffic_filter.add_port_filter(port_num)
            except ValueError:
                self.log_to_console(f"❌ Invalid port number: {port}")
            
            self.log_to_console("✅ Filters applied - restart monitoring to take effect")
            
        # Regenerate demo data with new filters
        if not MODULES_AVAILABLE:
            self.generate_demo_data()
            
    def get_current_filters(self):
        """Get current filter settings"""
        filters = {}
        if self.filter_mac.get().strip():
            filters['mac'] = self.filter_mac.get().strip()
        if self.filter_ip.get().strip():
            filters['ip'] = self.filter_ip.get().strip()
        return filters
        
    def clear_data(self):
        """Clear all displayed data from active session"""
        active_session = self.get_current_session()
        if active_session:
            # Clear packet display
            if active_session['packet_text']:
                active_session['packet_text'].delete(1.0, tk.END)
            
            # Clear stats display  
            if active_session['stats_text']:
                active_session['stats_text'].delete(1.0, tk.END)
            
            # Clear trees
            if active_session['devices_tree']:
                for item in active_session['devices_tree'].get_children():
                    active_session['devices_tree'].delete(item)
                    
            if active_session['apps_tree']:
                for item in active_session['apps_tree'].get_children():
                    active_session['apps_tree'].delete(item)
            
            # Reset packet counter for this session
            active_session['packets_captured'] = 0
            
        self.packets_captured = 0
        self.log_to_console("🗑️ Active session data cleared")
        

        
    def log_to_console(self, message):
        """Add message to console"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        formatted_message = f"[{timestamp}] {message}"
        
        def update_console():
            # Check if console_text exists
            if hasattr(self, 'console_text') and self.console_text:
                self.console_text.insert(tk.END, formatted_message + '\n')
                self.console_text.see(tk.END)
                # Keep only last 100 lines
                lines = self.console_text.get(1.0, tk.END).split('\n')
                if len(lines) > 100:
                    self.console_text.delete(1.0, f"{len(lines)-100}.0")
            else:
                # Fallback to print if console not ready
                print(formatted_message)
                
        # Schedule console update with delay
        self.root.after(50, update_console)
    
    def scan_network_devices(self):
        """Scan local network for other devices"""
        import subprocess
        import ipaddress
        
        devices_found = []
        try:
            # Get current IP to determine network range
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            lines = result.stdout.split('\n')
            
            current_ip = None
            for line in lines:
                if 'IPv4 Address' in line and '10.0.0.' in line:
                    current_ip = line.split(':')[-1].strip()
                    break
            
            if current_ip:
                # Scan common devices on 10.0.0.x network
                network = ipaddress.IPv4Network(f"{current_ip}/24", strict=False)
                common_ips = ['10.0.0.1', '10.0.0.151', '10.0.0.198', '10.0.0.212']  # Router, Phone, Current, RPI
                
                for ip in common_ips:
                    if ipaddress.IPv4Address(ip) in network:
                        # Try to ping each device
                        ping_result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                                   capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
                        if ping_result.returncode == 0:
                            device_type = "Unknown"
                            if ip == "10.0.0.1":
                                device_type = "Router"
                            elif ip == "10.0.0.151":
                                device_type = "Phone"
                            elif ip == "10.0.0.198":
                                device_type = "Computer"
                            elif ip == "10.0.0.212":
                                device_type = "Raspberry Pi"
                            
                            devices_found.append({
                                "mac": "Unknown", 
                                "ip": ip, 
                                "hostname": f"Device-{ip.split('.')[-1]}", 
                                "vendor": "Unknown", 
                                "type": device_type, 
                                "packets": 0 if ip != current_ip else 25
                            })
        except Exception as e:
            print(f"Network scan error: {e}")
            
        return devices_found

    def generate_demo_data(self):
        """Generate demo data based on current filters"""
        # Get current filter values
        target_mac = self.filter_mac.get().strip() or "78:B6:EE:F1:06:3F"
        target_ip = self.filter_ip.get().strip() or "10.14.0.2"
        target_port = self.filter_port.get().strip()
        
        # Generate devices data - use real network scan if available
        try:
            scanned_devices = self.scan_network_devices()
            if scanned_devices:
                self.devices_found = scanned_devices
            else:
                # Fallback to demo data
                self.devices_found = [
                    {"mac": target_mac, "ip": target_ip, "hostname": "Target-Device", "vendor": "Unknown", "type": "Computer", "packets": self.packets_captured + 45},
                    {"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.1", "hostname": "Router", "vendor": "TP-Link", "type": "Gateway", "packets": 12},
                    {"mac": "11:22:33:44:55:66", "ip": "10.0.0.151", "hostname": "Phone", "vendor": "Samsung", "type": "Mobile", "packets": 0},
                    {"mac": "cc:dd:ee:ff:11:22", "ip": "10.0.0.212", "hostname": "RaspberryPi", "vendor": "Raspberry Pi Foundation", "type": "IoT Device", "packets": 0}
                ]
        except Exception as e:
            print(f"Device scan failed: {e}")
            # Fallback to demo data
            self.devices_found = [
                {"mac": target_mac, "ip": target_ip, "hostname": "Target-Device", "vendor": "Unknown", "type": "Computer", "packets": self.packets_captured + 45},
                {"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.1", "hostname": "Router", "vendor": "TP-Link", "type": "Gateway", "packets": 12},
                {"mac": "11:22:33:44:55:66", "ip": "10.0.0.151", "hostname": "Phone", "vendor": "Samsung", "type": "Mobile", "packets": 0},
                {"mac": "cc:dd:ee:ff:11:22", "ip": "10.0.0.212", "hostname": "RaspberryPi", "vendor": "Raspberry Pi Foundation", "type": "IoT Device", "packets": 0}
            ]
        
        # Generate applications data based on port filter
        if target_port:
            try:
                port_num = int(target_port)
                if port_num == 443:
                    app_name = "HTTPS Browser"
                elif port_num == 80:
                    app_name = "HTTP Browser"
                elif port_num == 22:
                    app_name = "SSH Client"
                elif port_num == 25:
                    app_name = "SMTP Mail"
                elif port_num == 21:
                    app_name = "FTP Client"
                else:
                    app_name = f"Port-{port_num} App"
                    
                self.applications_detected = [
                    {"device": target_ip, "app": app_name, "protocol": "TCP", "port": port_num, "count": self.packets_captured + 15}
                ]
            except ValueError:
                # Invalid port, show general apps
                self.applications_detected = [
                    {"device": target_ip, "app": "Chrome", "protocol": "HTTPS", "port": 443, "count": self.packets_captured + 25},
                    {"device": target_ip, "app": "Discord", "protocol": "WSS", "port": 443, "count": 12},
                    {"device": target_ip, "app": "Steam", "protocol": "TCP", "port": 27036, "count": 8}
                ]
        else:
            # No port filter, show general applications
            self.applications_detected = [
                {"device": target_ip, "app": "Chrome", "protocol": "HTTPS", "port": 443, "count": self.packets_captured + 25},
                {"device": target_ip, "app": "Discord", "protocol": "WSS", "port": 443, "count": 12},
                {"device": target_ip, "app": "Steam", "protocol": "TCP", "port": 27036, "count": 8}
            ]
    
    def save_current_config(self):
        """Save current filter configuration"""
        config_name = self.config_name.get().strip()
        if not config_name:
            self.log_to_console("❌ Please enter a configuration name")
            return
            
        # Get current active session filters
        active_session = self.monitor_sessions.get(self.active_session_id)
        if not active_session:
            self.log_to_console("❌ No active session found")
            return
            
        config = {
            'mac': active_session['filter_mac'].get().strip(),
            'ip': active_session['filter_ip'].get().strip(),
            'port': active_session['filter_port'].get().strip(),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        self.saved_configs[config_name] = config
        self.save_configurations_to_file()
        self.update_config_dropdown()
        self.config_name.set("")  # Clear the save field
        
        self.log_to_console(f"💾 Configuration '{config_name}' saved successfully")
        
    def load_selected_config(self, event=None):
        """Load selected configuration"""
        config_name = self.selected_config.get()
        if not config_name or config_name not in self.saved_configs:
            return
            
        config = self.saved_configs[config_name]
        
        # Load config into active session only
        active_session = self.monitor_sessions.get(self.active_session_id)
        if not active_session:
            self.log_to_console("❌ No active session found")
            return
            
        active_session['filter_mac'].set(config.get('mac', ''))
        active_session['filter_ip'].set(config.get('ip', ''))  
        active_session['filter_port'].set(config.get('port', ''))
        
        self.log_to_console(f"📂 Configuration '{config_name}' loaded into {self.active_session_id}")
        self.log_to_console(f"   MAC: {config.get('mac', 'None')}")
        self.log_to_console(f"   IP:  {config.get('ip', 'None')}")
        self.log_to_console(f"   Port: {config.get('port', 'None')}")
        
    def update_config_dropdown(self):
        """Update the configuration dropdown with saved configs"""
        config_names = list(self.saved_configs.keys())
        self.config_combo['values'] = config_names
        
    def save_configurations_to_file(self):
        """Save configurations to JSON file"""
        try:
            config_file = os.path.join(os.path.dirname(__file__), 'saved_configs.json')
            with open(config_file, 'w') as f:
                json.dump(self.saved_configs, f, indent=2)
        except Exception as e:
            self.log_to_console(f"❌ Error saving configurations: {e}")
            
    def load_saved_configurations(self):
        """Load configurations from JSON file"""
        try:
            config_file = os.path.join(os.path.dirname(__file__), 'saved_configs.json')
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    self.saved_configs = json.load(f)
                self.log_to_console(f"📂 Loaded {len(self.saved_configs)} saved configurations")
            else:
                # Create default configurations
                self.create_default_configurations()
        except Exception as e:
            self.log_to_console(f"❌ Error loading configurations: {e}")
            self.create_default_configurations()
            
    def create_default_configurations(self):
        """Create some default configurations"""
        self.saved_configs = {
            "My Device": {
                "mac": "2e:80:02:62:18:46",
                "ip": "10.0.0.151", 
                "port": "",
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            },
            "HTTPS Traffic": {
                "mac": "",
                "ip": "",
                "port": "443",
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            },
            "HTTP Traffic": {
                "mac": "",
                "ip": "",
                "port": "80", 
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        }
        self.save_configurations_to_file()
        
    def delete_selected_config(self):
        """Delete the selected configuration"""
        config_name = self.selected_config.get()
        if not config_name or config_name not in self.saved_configs:
            return
            
        del self.saved_configs[config_name]
        self.save_configurations_to_file()
        self.update_config_dropdown()
        self.selected_config.set("")
        self.log_to_console(f"🗑️ Configuration '{config_name}' deleted")
    
    def start_all_sessions(self):
        """Start or stop all monitoring sessions"""
        active_sessions = [s for s in self.monitor_sessions.values() if s['monitoring']]
        
        if len(active_sessions) == 0:
            # Start all sessions
            for session_id in self.monitor_sessions:
                if not self.monitor_sessions[session_id]['monitoring']:
                    self.toggle_session_monitoring(session_id)
            self.main_start_button.config(text="🛑 Stop All Sessions")
            self.log_to_console("🚀 Started all monitoring sessions")
        else:
            # Stop all sessions
            for session_id in self.monitor_sessions:
                if self.monitor_sessions[session_id]['monitoring']:
                    self.toggle_session_monitoring(session_id)
            self.main_start_button.config(text="🚀 Start All Sessions")
            self.log_to_console("🛑 Stopped all monitoring sessions")
    
    def clear_all_data(self):
        """Clear data for all sessions"""
        for session_id in self.monitor_sessions:
            self.clear_session_data(session_id)
        self.log_to_console("🗑️ Cleared data for all sessions")
        
    def start_background_updates(self):
        """Start background update threads"""
        def update_displays():
            """Update all displays safely from main thread"""
            try:
                # Update all active sessions
                for session_id, session in self.monitor_sessions.items():
                    if session['monitoring']:
                        self.update_session_displays(session_id)
            except Exception as e:
                print(f"Update error: {e}")
            finally:
                # Schedule next update - reduced frequency to prevent focus stealing
                self.root.after(10000, update_displays)  # Every 10 seconds instead of 3
        
        # Start the update cycle - delayed start
        self.root.after(5000, update_displays)  # Start after 5 seconds instead of 1

def main():
    """Main application entry point"""
    root = tk.Tk()
    app = NetworkMonitorGUI(root)
    
    # Apply dark title bar after window is fully initialized - run once only
    root.after(1000, app.configure_dark_title_bar)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\n🛑 Application closed by user")
    except Exception as e:
        print(f"❌ Application error: {e}")

if __name__ == "__main__":
    main()