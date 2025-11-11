import os
import hashlib
import json
import threading
import time
import platform
import shutil
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from threading import Event
from collections import deque, defaultdict

# File scanning functions
def scan_file(file_path):
    """Check if a file matches known malware signatures"""
    known_threats = load_threat_database()
    file_fingerprint = get_file_hash(file_path)
    
    if file_fingerprint and file_fingerprint in known_threats:
        return known_threats[file_fingerprint]
    return None

def load_threat_database():
    """Load our database of known bad files"""
    try:
        with open('signatures.json', 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}  # No threats database yet
    except json.JSONDecodeError:
        return {}  # Database is corrupted

def get_file_hash(file_path):
    """Calculate a unique fingerprint for a file"""
    hasher = hashlib.md5()
    try:
        with open(file_path, "rb") as file:
            # Read file in chunks to handle large files
            for chunk in iter(lambda: file.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None  # Can't read the file

def scan_folder(folder_path):
    """Scan all files in a folder and subfolders"""
    found_threats = []
    
    for root, directories, files in os.walk(folder_path):
        for filename in files:
            full_path = os.path.join(root, filename)
            scan_result = scan_file(full_path)
            
            if scan_result:
                found_threats.append((full_path, scan_result))
    
    return found_threats

def move_to_quarantine(file_path):
    """Move suspicious file to quarantine area"""
    os.makedirs('quarantine', exist_ok=True)
    log_file = 'quarantine_log.txt'
    
    try:
        filename = os.path.basename(file_path)
        quarantine_location = os.path.join('quarantine', filename)
        shutil.move(file_path, quarantine_location)
        
        # Log the action
        with open(log_file, 'a') as log:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log.write(f"{timestamp}: Quarantined {file_path} -> {quarantine_location}\n")
        return True
        
    except Exception as error:
        # Log the failure
        with open(log_file, 'a') as log:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log.write(f"{timestamp}: FAILED to quarantine {file_path}. Error: {error}\n")
        return False

def restore_from_quarantine(filename):
    """Restore a file from quarantine"""
    quarantine_location = os.path.join('quarantine', filename)
    
    if os.path.exists(quarantine_location):
        restore_location = os.path.join('recovered', filename)
        os.makedirs('recovered', exist_ok=True)
        shutil.move(quarantine_location, restore_location)
        return True
    return False

def run_automatic_scan_and_quarantine(folder_path):
    """Scan a folder and automatically quarantine any threats found"""
    scan_results = scan_folder(folder_path)
    
    if scan_results:
        for file_path, threat_info in scan_results:
            print(f"Found threat: {file_path} - {threat_info}. Moving to quarantine...")
            move_to_quarantine(file_path)
    else:
        print("Scan complete - no threats found!")

def setup_startup_protection():
    """Make byteWatch run automatically when computer starts"""
    if platform.system() == "Windows":
        try:
            import winreg as registry
            startup_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
            app_name = "byteWatch"
            app_path = os.path.abspath(__file__)
            
            with registry.OpenKey(registry.HKEY_CURRENT_USER, startup_key, 0, registry.KEY_SET_VALUE) as key:
                registry.SetValueEx(key, app_name, 0, registry.REG_SZ, app_path)
            return True
            
        except Exception as error:
            return False
    return False

# Ransomware protection system
class RansomwareDetector:
    def __init__(self):
        self.monitor_active = Event()
        self.file_activity_log = defaultdict(deque)
        self.suspicious_keywords = ['.encrypted', '.locked', '.crypted', '.ransom']
        self.suspicious_activity_threshold = 100
    
    def start_protection(self):
        """Begin monitoring for ransomware behavior"""
        self.monitor_thread = threading.Thread(target=self._watch_for_threats, daemon=True)
        self.monitor_thread.start()
        print("🛡️ Ransomware protection is now active")
    
    def _watch_for_threats(self):
        """Continuously monitor for suspicious file activity"""
        while not self.monitor_active.is_set():
            self._check_for_mass_file_changes()
            self._cleanup_old_logs()
            time.sleep(10)  # Check every 10 seconds
    
    def _check_for_mass_file_changes(self):
        """Look for patterns that suggest ransomware activity"""
        current_time = time.time()
        suspicious_patterns_detected = 0
        
        for file_type, timestamps in self.file_activity_log.items():
            # Count how many operations happened in the last 2 minutes
            recent_activity = [ts for ts in timestamps if current_time - ts < 120]
            
            if len(recent_activity) > 50:  # Too many changes of same file type
                suspicious_patterns_detected += 1
        
        if suspicious_patterns_detected > 3:
            self._raise_alert("Detected mass file modifications - possible ransomware!")
    
    def _cleanup_old_logs(self):
        """Remove old activity records to save memory"""
        current_time = time.time()
        
        for file_type in list(self.file_activity_log.keys()):
            self.file_activity_log[file_type] = deque(
                timestamp for timestamp in self.file_activity_log[file_type] 
                if current_time - timestamp < 300  # Keep last 5 minutes only
            )
    
    def _raise_alert(self, reason):
        """Handle ransomware detection alert"""
        print(f"🚨 RANSOMWARE ALERT: {reason}")

# Main application interface
class ByteWatchAntivirus:
    def __init__(self, window):
        self.window = window
        self.window.title("byteWatch Antivirus")
        self.window.geometry("800x600")
        
        self.create_interface()
    
    def create_interface(self):
        """Build the main user interface"""
        # Main container
        main_container = ttk.Frame(self.window, padding="10")
        main_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Application title
        title = ttk.Label(main_container, text="byteWatch Antivirus", 
                         font=('Arial', 16, 'bold'))
        title.grid(row=0, column=0, columnspan=3, pady=10)
        
        # Scanning options
        scan_section = ttk.LabelFrame(main_container, text="Scan Your Computer", padding="10")
        scan_section.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Button(scan_section, text="Quick Scan", 
                  command=self.run_quick_scan).grid(row=0, column=0, padx=5, pady=5)
        
        ttk.Button(scan_section, text="Scan Specific Folder", 
                  command=self.run_custom_scan).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(scan_section, text="Full System Scan", 
                  command=self.run_full_scan).grid(row=0, column=2, padx=5, pady=5)
        
        # Protection features
        protection_section = ttk.LabelFrame(main_container, text="Security Features", padding="10")
        protection_section.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Button(protection_section, text="Run on Startup", 
                  command=self.enable_startup).grid(row=0, column=0, padx=5, pady=5)
        
        ttk.Button(protection_section, text="Auto-Quarantine Scan", 
                  command=self.run_auto_quarantine).grid(row=0, column=1, padx=5, pady=5)
        
        # Quarantine management
        quarantine_section = ttk.LabelFrame(main_container, text="Quarantine Management", padding="10")
        quarantine_section.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Button(quarantine_section, text="View Quarantined Files", 
                  command=self.show_quarantine).grid(row=0, column=0, padx=5, pady=5)
        
        ttk.Button(quarantine_section, text="Restore File", 
                  command=self.open_restore_dialog).grid(row=0, column=1, padx=5, pady=5)
        
        # Results display
        results_section = ttk.LabelFrame(main_container, text="Scan Results", padding="10")
        results_section.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        self.results_display = scrolledtext.ScrolledText(results_section, height=15, width=80)
        self.results_display.grid(row=0, column=0, columnspan=3)
        
        # Progress indicator
        self.progress_bar = ttk.Progressbar(main_container, mode='indeterminate')
        self.progress_bar.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # Status message
        self.status_message = tk.StringVar(value="Ready to scan")
        status_display = ttk.Label(main_container, textvariable=self.status_message)
        status_display.grid(row=6, column=0, columnspan=3, sticky=tk.W)
        
        # Make interface resizable
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        main_container.columnconfigure(0, weight=1)
        main_container.rowconfigure(4, weight=1)
    
    def add_to_log(self, message):
        """Add a message to the results display"""
        self.results_display.insert(tk.END, f"{message}\n")
        self.results_display.see(tk.END)
        self.window.update()
    
    def run_quick_scan(self):
        """Scan common user folders"""
        self.add_to_log("Starting quick scan...")
        self.status_message.set("Scanning your documents...")
        self.progress_bar.start()
        
        def scanning_job():
            try:
                folders_to_scan = [
                    os.path.expanduser("~\\Downloads"),
                    os.path.expanduser("~\\Desktop"),
                    os.path.expanduser("~\\Documents"),
                ]
                
                all_threats = []
                for folder in folders_to_scan:
                    if os.path.exists(folder):
                        self.add_to_log(f"Scanning: {folder}")
                        threats_found = scan_folder(folder)
                        all_threats.extend(threats_found)
                
                self.window.after(0, self.handle_scan_results, all_threats)
            except Exception as error:
                self.window.after(0, self.handle_scan_error, str(error))
        
        threading.Thread(target=scanning_job, daemon=True).start()
    
    def run_custom_scan(self):
        """Let user choose which folder to scan"""
        selected_folder = filedialog.askdirectory()
        if selected_folder:
            self.add_to_log(f"Scanning folder: {selected_folder}")
            self.status_message.set(f"Scanning: {selected_folder}")
            self.progress_bar.start()
            
            def scanning_job():
                try:
                    threats_found = scan_folder(selected_folder)
                    self.window.after(0, self.handle_scan_results, threats_found)
                except Exception as error:
                    self.window.after(0, self.handle_scan_error, str(error))
            
            threading.Thread(target=scanning_job, daemon=True).start()
    
    def run_full_scan(self):
        """Warn user before running intensive full system scan"""
        if messagebox.askyesno("Heads up", "Full system scan can take a long time and slow down your computer. Continue?"):
            self.add_to_log("Starting full system scan...")
            self.status_message.set("Scanning entire system...")
            self.progress_bar.start()
            
            def scanning_job():
                try:
                    system_root = "C:\\" if platform.system() == "Windows" else "/"
                    threats_found = scan_folder(system_root)
                    self.window.after(0, self.handle_scan_results, threats_found)
                except Exception as error:
                    self.window.after(0, self.handle_scan_error, str(error))
            
            threading.Thread(target=scanning_job, daemon=True).start()
    
    def handle_scan_results(self, threats):
        """Process and display scan results"""
        self.progress_bar.stop()
        
        if threats:
            self.add_to_log(f"Scan complete! Found {len(threats)} potential threats.")
            for file_path, threat_info in threats:
                self.add_to_log(f"🚨 Threat: {file_path} - {threat_info}")
            
            self.status_message.set(f"Found {len(threats)} threats")
            
            if messagebox.askyesno("Threats detected", f"Found {len(threats)} suspicious files. Move them to quarantine?"):
                self.quarantine_detected_threats(threats)
        else:
            self.add_to_log("✅ Scan complete! Your system appears clean.")
            self.status_message.set("Scan complete - no threats found")
    
    def handle_scan_error(self, error):
        """Display scan errors to user"""
        self.progress_bar.stop()
        self.add_to_log(f"❌ Scan failed: {error}")
        self.status_message.set("Scan failed")
        messagebox.showerror("Scan error", f"Something went wrong during scanning: {error}")
    
    def quarantine_detected_threats(self, threats):
        """Move all detected threats to quarantine"""
        self.add_to_log("Moving threats to quarantine...")
        self.status_message.set("Quarantining files...")
        
        def quarantine_job():
            try:
                successful_quarantines = 0
                for file_path, threat_info in threats:
                    if move_to_quarantine(file_path):
                        successful_quarantines += 1
                        self.window.after(0, self.add_to_log, f"✅ Quarantined: {os.path.basename(file_path)}")
                
                self.window.after(0, self.quarantine_finished, successful_quarantines, len(threats))
            except Exception as error:
                self.window.after(0, self.quarantine_failed, str(error))
        
        threading.Thread(target=quarantine_job, daemon=True).start()
    
    def quarantine_finished(self, success_count, total_count):
        """Notify user when quarantine operation completes"""
        self.add_to_log(f"✅ Quarantine complete: {success_count}/{total_count} files secured")
        self.status_message.set("Quarantine complete")
    
    def quarantine_failed(self, error):
        """Handle quarantine failures"""
        self.add_to_log(f"❌ Quarantine error: {error}")
        self.status_message.set("Quarantine failed")
    
    def enable_startup(self):
        """Enable automatic startup protection"""
        if setup_startup_protection():
            messagebox.showinfo("Success", "byteWatch will now protect you automatically on startup!")
            self.add_to_log("✅ Startup protection enabled")
        else:
            messagebox.showerror("Error", "Couldn't setup automatic startup protection")
            self.add_to_log("❌ Failed to enable startup protection")
    
    def run_auto_quarantine(self):
        """Run a scan that automatically quarantines any threats found"""
        selected_folder = filedialog.askdirectory()
        if selected_folder:
            self.add_to_log(f"Starting auto-quarantine scan of: {selected_folder}")
            self.status_message.set("Auto-quarantine scan running...")
            self.progress_bar.start()
            
            def scanning_job():
                try:
                    scan_results = scan_folder(selected_folder)
                    if scan_results:
                        for file_path, threat_info in scan_results:
                            move_to_quarantine(file_path)
                        self.window.after(0, self.auto_quarantine_finished, len(scan_results))
                    else:
                        self.window.after(0, self.auto_quarantine_finished, 0)
                except Exception as error:
                    self.window.after(0, self.handle_scan_error, str(error))
            
            threading.Thread(target=scanning_job, daemon=True).start()
    
    def auto_quarantine_finished(self, threat_count):
        """Handle completion of auto-quarantine scan"""
        self.progress_bar.stop()
        if threat_count > 0:
            self.add_to_log(f"✅ Auto-quarantine complete: {threat_count} threats removed")
            self.status_message.set(f"Removed {threat_count} threats")
        else:
            self.add_to_log("✅ Auto-quarantine complete: No threats found")
            self.status_message.set("Auto-quarantine complete")
    
    def show_quarantine(self):
        
        quarantine_folder = 'quarantine'
        if os.path.exists(quarantine_folder):
            quarantined_files = os.listdir(quarantine_folder)
            if quarantined_files:
                self.add_to_log("📁 Files in quarantine:")
                for filename in quarantined_files:
                    self.add_to_log(f"   - {filename}")
            else:
                self.add_to_log("📁 Quarantine is empty")
        else:
            self.add_to_log("📁 No quarantine folder found")
    
    def open_restore_dialog(self):
        
        quarantine_folder = 'quarantine'
        if not os.path.exists(quarantine_folder):
            messagebox.showinfo("Information", "No quarantine folder exists yet")
            return
        
        quarantined_files = os.listdir(quarantine_folder)
        if not quarantined_files:
            messagebox.showinfo("Information", "No files in quarantine to restore")
            return
        
        # Create restoration window
        restore_window = tk.Toplevel(self.window)
        restore_window.title("Restore File from Quarantine")
        restore_window.geometry("400x300")
        
        ttk.Label(restore_window, text="Choose file to restore:").pack(pady=10)
        
        file_list = tk.Listbox(restore_window)
        for filename in quarantined_files:
            file_list.insert(tk.END, filename)
        file_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        def restore_chosen_file():
            selected = file_list.curselection()
            if selected:
                chosen_file = file_list.get(selected[0])
                if restore_from_quarantine(chosen_file):
                    messagebox.showinfo("Success", f"Restored {chosen_file}")
                    self.add_to_log(f"✅ Restored: {chosen_file}")
                    restore_window.destroy()
                else:
                    messagebox.showerror("Error", f"Failed to restore {chosen_file}")
        
        ttk.Button(restore_window, text="Restore Selected File", 
                  command=restore_chosen_file).pack(pady=10)


def start_application():
    window = tk.Tk()
    app = ByteWatchAntivirus(window)
    window.mainloop()

if __name__ == "__main__":
    start_application()