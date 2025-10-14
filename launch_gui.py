import sys
import os

def check_admin():
    """Check if running as administrator"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def main():
    if not check_admin():
        print("❌ Administrator privileges required!")
        print("Right-click on PowerShell and select 'Run as Administrator'")
        print("Then run: python launch_gui.py")
        input("Press Enter to exit...")
        return
        
    print("🚀 Launching Network Monitor GUI...")
    
    # Add current directory to Python path
    current_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, current_dir)
    
    try:
        # Import and run GUI
        from network_gui import main as gui_main
        gui_main()
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Some modules may not be available. Starting basic GUI...")
        # Try to start basic GUI anyway
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo("Network Monitor", "GUI modules loading... Check console for details.")
        try:
            from network_gui import main as gui_main
            gui_main()
        except Exception as gui_error:
            messagebox.showerror("Error", f"Failed to load GUI:\n{str(gui_error)}")
        root.destroy()
    except Exception as e:
        print(f"❌ Error running GUI: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()