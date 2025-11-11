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
    else:
        with open(quarantine_log, 'a') as log:
            log.write(f"{datetime.now()}: quarantined {file_path} to {quarantine_path}\n")

def recover_file():
    recover_file_text = input("what file do you want to recover: ")
    if not recover_file_text:
        print("no file specified")
        return
    
    quarantine_path = os.path.join('quarantine', recover_file_text)
    if os.path.exists(quarantine_path): 
        recovered_path = os.path.join('recovered', recover_file_text)
        os.makedirs('recovered', exist_ok=True)
        shutil.move(quarantine_path, recovered_path)
        print(f"recovered {recover_file_text} to {recovered_path}")
    else:
        print(f"file {recover_file_text} not found in quarantine")

def start_real_time_monitoring():
    file_path = input("enter the file you want to monitor: ")
    if not os.path.exists(file_path):
        print("file does not exist.")
        return
    
    last_modified = os.path.getmtime(file_path)
    print(f"Started monitoring {file_path} for changes.")
    
    try:
        while True:
            time.sleep(2)
            current_modified = os.path.getmtime(file_path)
            if current_modified != last_modified:
                print(f"file {file_path} has been modified.")
                last_modified = current_modified
    except KeyboardInterrupt:
        print("stopped monitoring.")

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
        key = r"software\Microsoft\Windows\CurrentVersion\Run"
        value_name = "antivirus"
        exe_path = os.path.abspath(__file__)
        try:
            import winreg as reg
            with reg.OpenKey(reg.HKEY_CURRENT_USER, key, 0, reg.KEY_SET_VALUE) as registry_key:
                reg.SetValueEx(registry_key, value_name, 0, reg.REG_SZ, exe_path)
            print("byteWatch added to startup!")
        except Exception as e:
            print(f"failed to set startup on boot: {e}")
    else:
        print("startup on boot not implemented for this os.")

def main_menu():
    while True:
        print("\n=== byteWatch ===")
        print("1. scan directory")
        print("2. recover file from quarantine")
        print("3. start real-time monitoring")
        print("4. auto quarantine on scan")
        print("5. enable startup protection")
        print("6. exit")

        choice = input("choose from 1-6: ")
        if choice == '1':
            directory = input("enter directory to scan: ")
            results = scan_directory(directory)
            if results:
                for file_path, threat in results:
                    print(f"found threat: {file_path} - {threat}")
            else:
                print("no threats found.")
        elif choice == '2':
            recover_file()
        elif choice == '3':
            start_real_time_monitoring()
        elif choice == '4': 
            directory = input("enter directory to scan and auto quarantine: ")
            auto_quarantine_on_scan(directory)
        elif choice == '5':
            start_up_on_boot()
        elif choice == '6':
            print("exiting byteWatch.")
            break
        else:
            print("invalid choice. please try again.")

if __name__ == "__main__":
    main_menu()