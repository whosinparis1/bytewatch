import os
import hashlib
import json
import threading
import time
import sqlite3
from datetime import datetime
import re
import platform
from concurrent.futures import ThreadPoolExecutor
import zipfile
import tarfile
import struct
import ctypes
from collections import defaultdict
import shutil
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# Core Antivirus Functions
def file_scanner(file_path):
    signatures = load_signatures()
    file_hash = calculate_file_hash(file_path)
    if file_hash and file_hash in signatures:
        return signatures[file_hash]
    return None

def load_signatures():
    try:
        with open('signatures.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}

def calculate_file_hash(file_path):
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        return None

def scan_directory(directory):
    infected_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            result = file_scanner(file_path)
            if result:
                infected_files.append((file_path, result))
    return infected_files

def quarantine_file(file_path):
    os.makedirs('quarantine', exist_ok=True)
    quarantine_log = 'quarantine_log.txt'
    try:
        file = os.path.basename(file_path)
        quarantine_path = os.path.join('quarantine', file)
        shutil.move(file_path, quarantine_path)
    except Exception as e:
        with open(quarantine_log, 'a') as log:
            log.write(f"{datetime.now()}: Failed to quarantine {file_path}. Error: {e}\n")
        return False
    else:
        with open(quarantine_log, 'a') as log:
            log.write(f"{datetime.now()}: quarantined {file_path} to {quarantine_path}\n")
        return True

def recover_file(file_name):
    quarantine_path = os.path.join('quarantine', file_name)
    if os.path.exists(quarantine_path):
        recovered_path = os.path.join('recovered', file_name)
        os.makedirs('recovered', exist_ok=True)
        shutil.move(quarantine_path, recovered_path)
        return True
    return False

def start_real_time_monitoring():
    # This would be implemented for real-time monitoring
    pass

def auto_quarantine_on_scan(directory):
    results = scan_directory(directory)
    if results:
        for file_path, threat in results:
            print(f"threat found: {file_path} - {threat}. quarantining")
            quarantine_file(file_path)
    else:
        print("no threats found.")

def start_up_on_boot():
    if platform.system() == "Windows":
        try:
            import winreg as reg
            key = r"Software\Microsoft\Windows\CurrentVersion\Run"
            value_name = "byteWatch"
            exe_path = os.path.abspath(__file__)
            with reg.OpenKey(reg.HKEY_CURRENT_USER, key, 0, reg.KEY_SET_VALUE) as registry_key:
                reg.SetValueEx(registry_key, value_name, 0, reg.REG_SZ, exe_path)
            return True
        except Exception as e:
            return False
    return False

# GUI Class
class ByteWatchGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("byteWatch Antivirus")
        self.root.geometry("800x600")
        
        self.setup_gui()
    
    def setup_gui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="byteWatch Antivirus", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=10)
        
        # Scan section
        scan_frame = ttk.LabelFrame(main_frame, text="Scan Options", padding="10")
        scan_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Button(scan_frame, text="Quick Scan", 
                  command=self.quick_scan).grid(row=0, column=0, padx=5, pady=5)
        
        ttk.Button(scan_frame, text="Custom Scan", 
                  command=self.custom_scan).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(scan_frame, text="Full System Scan", 
                  command=self.full_scan).grid(row=0, column=2, padx=5, pady=5)
        
        # Protection section
        protection_frame = ttk.LabelFrame(main_frame, text="Protection", padding="10")
        protection_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Button(protection_frame, text="Enable Startup Protection", 
                  command=self.enable_startup).grid(row=0, column=0, padx=5, pady=5)
        
        ttk.Button(protection_frame, text="Auto-Quarantine Scan", 
                  command=self.auto_quarantine_scan).grid(row=0, column=1, padx=5, pady=5)
        
        # Quarantine management
        quarantine_frame = ttk.LabelFrame(main_frame, text="Quarantine Management", padding="10")
        quarantine_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Button(quarantine_frame, text="View Quarantined Files", 
                  command=self.view_quarantine).grid(row=0, column=0, padx=5, pady=5)
        
        ttk.Button(quarantine_frame, text="Restore File", 
                  command=self.restore_file_dialog).grid(row=0, column=1, padx=5, pady=5)
        
        # Results area
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="10")
        results_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=15, width=80)
        self.results_text.grid(row=0, column=0, columnspan=3)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready to scan")
        status_label = ttk.Label(main_frame, textvariable=self.status_var)
        status_label.grid(row=6, column=0, columnspan=3, sticky=tk.W)
        
        # Configure grid weights for resizing
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=1)
    
    def log_message(self, message):
        """Add message to results text area"""
        self.results_text.insert(tk.END, f"{message}\n")
        self.results_text.see(tk.END)
        self.root.update()
    
    def quick_scan(self):
        """Scan common user directories"""
        self.log_message("Starting quick scan...")
        self.status_var.set("Scanning user directories...")
        self.progress.start()
        
        def scan_thread():
            try:
                common_dirs = [
                    os.path.expanduser("~\\Downloads"),
                    os.path.expanduser("~\\Desktop"),
                    os.path.expanduser("~\\Documents"),
                ]
                
                threats_found = []
                for directory in common_dirs:
                    if os.path.exists(directory):
                        self.log_message(f"Scanning: {directory}")
                        threats = scan_directory(directory)
                        threats_found.extend(threats)
                
                self.root.after(0, self.scan_complete, threats_found)
            except Exception as e:
                self.root.after(0, self.scan_error, str(e))
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def custom_scan(self):
        """Let user choose directory to scan"""
        directory = filedialog.askdirectory()
        if directory:
            self.log_message(f"Starting custom scan of: {directory}")
            self.status_var.set(f"Scanning: {directory}")
            self.progress.start()
            
            def scan_thread():
                try:
                    threats = scan_directory(directory)
                    self.root.after(0, self.scan_complete, threats)
                except Exception as e:
                    self.root.after(0, self.scan_error, str(e))
            
            threading.Thread(target=scan_thread, daemon=True).start()
    
    def full_scan(self):
        """Warn user about full system scan"""
        if messagebox.askyesno("Warning", "Full system scan may take a long time and impact system performance. Continue?"):
            self.log_message("Starting full system scan...")
            self.status_var.set("Performing full system scan...")
            self.progress.start()
            
            def scan_thread():
                try:
                    # Scan system drive
                    system_drive = "C:\\" if platform.system() == "Windows" else "/"
                    threats = scan_directory(system_drive)
                    self.root.after(0, self.scan_complete, threats)
                except Exception as e:
                    self.root.after(0, self.scan_error, str(e))
            
            threading.Thread(target=scan_thread, daemon=True).start()
    
    def scan_complete(self, threats):
        """Handle scan completion"""
        self.progress.stop()
        
        if threats:
            self.log_message(f"Scan complete! Found {len(threats)} threats.")
            for file_path, threat in threats:
                self.log_message(f"🚨 THREAT: {file_path} - {threat}")
            
            self.status_var.set(f"Scan complete - Found {len(threats)} threats")
            
            if messagebox.askyesno("Threats Found", f"Found {len(threats)} threats. Quarantine them automatically?"):
                self.quarantine_threats(threats)
        else:
            self.log_message("✅ Scan complete! No threats found.")
            self.status_var.set("Scan complete - No threats found")
    
    def scan_error(self, error):
        """Handle scan errors"""
        self.progress.stop()
        self.log_message(f"❌ Scan error: {error}")
        self.status_var.set("Scan failed")
        messagebox.showerror("Scan Error", f"An error occurred during scanning: {error}")
    
    def quarantine_threats(self, threats):
        """Quarantine found threats"""
        self.log_message("Quarantining threats...")
        self.status_var.set("Quarantining files...")
        
        def quarantine_thread():
            try:
                success_count = 0
                for file_path, threat in threats:
                    if quarantine_file(file_path):
                        success_count += 1
                        self.root.after(0, self.log_message, f"✅ Quarantined: {os.path.basename(file_path)}")
                
                self.root.after(0, self.quarantine_complete, success_count, len(threats))
            except Exception as e:
                self.root.after(0, self.quarantine_error, str(e))
        
        threading.Thread(target=quarantine_thread, daemon=True).start()
    
    def quarantine_complete(self, success_count, total_count):
        """Handle quarantine completion"""
        self.log_message(f"✅ Quarantine complete: {success_count}/{total_count} files quarantined")
        self.status_var.set("Quarantine complete")
    
    def quarantine_error(self, error):
        """Handle quarantine errors"""
        self.log_message(f"❌ Quarantine error: {error}")
        self.status_var.set("Quarantine failed")
    
    def enable_startup(self):
        """Enable startup protection"""
        if start_up_on_boot():
            messagebox.showinfo("Success", "byteWatch will now run on startup!")
            self.log_message("✅ Startup protection enabled")
        else:
            messagebox.showerror("Error", "Failed to enable startup protection")
            self.log_message("❌ Failed to enable startup protection")
    
    def auto_quarantine_scan(self):
        """Run scan with auto-quarantine"""
        directory = filedialog.askdirectory()
        if directory:
            self.log_message(f"Starting auto-quarantine scan of: {directory}")
            self.status_var.set("Auto-quarantine scan running...")
            self.progress.start()
            
            def scan_thread():
                try:
                    results = scan_directory(directory)
                    if results:
                        for file_path, threat in results:
                            quarantine_file(file_path)
                        self.root.after(0, self.auto_quarantine_complete, len(results))
                    else:
                        self.root.after(0, self.auto_quarantine_complete, 0)
                except Exception as e:
                    self.root.after(0, self.scan_error, str(e))
            
            threading.Thread(target=scan_thread, daemon=True).start()
    
    def auto_quarantine_complete(self, threat_count):
        """Handle auto-quarantine completion"""
        self.progress.stop()
        if threat_count > 0:
            self.log_message(f"✅ Auto-quarantine complete: {threat_count} threats quarantined")
            self.status_var.set(f"Auto-quarantine complete - {threat_count} threats removed")
        else:
            self.log_message("✅ Auto-quarantine complete: No threats found")
            self.status_var.set("Auto-quarantine complete - No threats found")
    
    def view_quarantine(self):
        """Show quarantined files"""
        quarantine_dir = 'quarantine'
        if os.path.exists(quarantine_dir):
            files = os.listdir(quarantine_dir)
            if files:
                self.log_message("📁 Quarantined files:")
                for file in files:
                    self.log_message(f"   - {file}")
            else:
                self.log_message("📁 No files in quarantine")
        else:
            self.log_message("📁 Quarantine folder not found")
    
    def restore_file_dialog(self):
        """Dialog to restore file from quarantine"""
        quarantine_dir = 'quarantine'
        if not os.path.exists(quarantine_dir):
            messagebox.showinfo("Info", "No quarantine folder found")
            return
        
        files = os.listdir(quarantine_dir)
        if not files:
            messagebox.showinfo("Info", "No files in quarantine")
            return
        
        # Create restore dialog
        restore_window = tk.Toplevel(self.root)
        restore_window.title("restore File from Quarantine")
        restore_window.geometry("400x300")
        
        ttk.Label(restore_window, text="select file to restore:").pack(pady=10)
        
        listbox = tk.Listbox(restore_window)
        for file in files:
            listbox.insert(tk.END, file)
        listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        def restore_selected():
            selection = listbox.curselection()
            if selection:
                file_name = listbox.get(selection[0])
                if recover_file(file_name):
                    messagebox.showinfo("success", f"restored {file_name}")
                    self.log_message(f" restored: {file_name}")
                    restore_window.destroy()
                else:
                    messagebox.showerror("Error", f"Failed to restore {file_name}")
        
        ttk.Button(restore_window, text="Restore Selected", 
                  command=restore_selected).pack(pady=10)

# Main application
def main():
    root = tk.Tk()
    app = ByteWatchGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()