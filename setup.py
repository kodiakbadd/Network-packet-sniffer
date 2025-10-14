#!/usr/bin/env python3
"""
Setup script for Network Packet Sniffer
"""

import subprocess
import sys
import os
import platform
from pathlib import Path


def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 7):
        print("ERROR: Python 3.7 or higher is required.")
        print(f"Current version: {sys.version}")
        return False
    return True


def install_requirements():
    """Install required packages."""
    requirements_file = Path(__file__).parent / "requirements.txt"
    
    if not requirements_file.exists():
        print("ERROR: requirements.txt not found!")
        return False
        
    try:
        print("Installing required packages...")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", str(requirements_file)
        ])
        print("✓ Requirements installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Failed to install requirements: {e}")
        return False


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


def install_system_dependencies():
    """Install system-level dependencies if needed."""
    system = platform.system().lower()
    
    print(f"Detected system: {system}")
    
    if system == "windows":
        print("On Windows, you may need to install:")
        print("1. Npcap (https://nmap.org/npcap/) or WinPcap")
        print("2. Microsoft Visual C++ Redistributable")
        print("\nThese are required for packet capture functionality.")
        
    elif system == "linux":
        print("On Linux, you may need to install:")
        print("sudo apt-get update")
        print("sudo apt-get install python3-dev libpcap-dev")
        print("or equivalent for your distribution")
        
    elif system == "darwin":  # macOS
        print("On macOS, you may need to install:")
        print("brew install libpcap")
        print("or use MacPorts: sudo port install libpcap")
        
    return True


def create_directories():
    """Create necessary directories."""
    directories = ["logs", "exports", "data"]
    
    for directory in directories:
        dir_path = Path(__file__).parent / directory
        try:
            dir_path.mkdir(exist_ok=True)
            print(f"✓ Created directory: {directory}")
        except Exception as e:
            print(f"WARNING: Could not create directory {directory}: {e}")
            
    return True


def verify_installation():
    """Verify that the installation was successful."""
    try:
        # Test imports
        import scapy.all
        import colorama
        import tabulate
        print("✓ All required packages are importable")
        
        # Test privilege requirements
        if not check_privileges():
            print("⚠ WARNING: Not running with administrator/root privileges")
            print("  Packet capture will require elevated privileges")
        else:
            print("✓ Running with appropriate privileges")
            
        return True
        
    except ImportError as e:
        print(f"✗ Import error: {e}")
        print("Some required packages may not be installed correctly")
        return False


def main():
    """Main setup function."""
    print("Network Packet Sniffer Setup")
    print("=" * 40)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
        
    # Install requirements
    if not install_requirements():
        print("Setup failed during package installation")
        sys.exit(1)
        
    # Create directories
    create_directories()
    
    # Show system dependency information
    install_system_dependencies()
    
    # Verify installation
    print("\nVerifying installation...")
    if verify_installation():
        print("\n✓ Setup completed successfully!")
        print("\nUsage:")
        print("  python network_monitor.py")
        print("  python network_monitor.py --help")
        print("\nNote: You may need to run with administrator/root privileges")
        print("for packet capture functionality.")
    else:
        print("\n✗ Setup completed with warnings")
        print("Please check the error messages above and resolve any issues")
        

if __name__ == "__main__":
    main()