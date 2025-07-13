import subprocess
import re
import socket
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
from concurrent.futures import ThreadPoolExecutor

class ARPSpoofApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ARP Spoof Tool")
        self.root.geometry("800x650")
        self.root.configure(bg="#f0f0f0")
        
        # Initialize variables
        self.interfaces = []
        self.devices_count = 0
        self.scanning_active = False
        self.scan_start_time = 0
        self.last_scan_duration = 0
        self.estimated_scan_time = 10
        
        # Setup UI
        self.setup_interface()
        self.create_widgets()

    def setup_interface(self):
        """Setup network interface info"""
        try:
            # Get network interfaces
            output = subprocess.check_output("netsh interface show interface", 
                                          shell=True, 
                                          text=True,
                                          encoding='utf-8')
            self.interfaces = []
            for line in output.splitlines():
                if "Enabled" in line or "Connected" in line:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        self.interfaces.append(" ".join(parts[3:]))

            # Get default gateway
            output = subprocess.check_output("route print", 
                                          shell=True,
                                          text=True,
                                          encoding='utf-8')
            match = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", 
                            output,
                            re.MULTILINE)
            self.gateway_ip = match.group(1) if match else ""
            
        except Exception as e:
            messagebox.showerror("Error", f"Initialization failed: {str(e)}")

    def create_widgets(self):
        """Create all GUI components"""
        style = ttk.Style()
        style.configure('TFrame', background="#FFFFFF")
        style.configure('TButton', 
                      font=('Segoe UI', 10),
                      foreground='white',
                      background='#4a8bcf',
                      borderwidth=0,
                      padding=6)
        
        # Main frame
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        tk.Label(main_frame, 
               text="ARP Spoof Tool",
               font=('Segoe UI', 16, 'bold'),
               foreground="#2c3e50",
               background="#f0f0f0").pack(pady=10)

        # Interface selection
        self.interface_var = tk.StringVar()
        if self.interfaces:
            self.interface_var.set(self.interfaces[0])
            
        ttk.Label(main_frame, 
                text="Network Interface:",
                font=('Segoe UI', 9)).pack(anchor=tk.W, padx=10)
                
        interface_menu = ttk.Combobox(main_frame, 
                                     values=self.interfaces,
                                     textvariable=self.interface_var,
                                     state="readonly",
                                     font=('Segoe UI', 9))
        interface_menu.pack(fill=tk.X, padx=10, pady=(0,10))

        # Scan button
        self.scan_btn = ttk.Button(main_frame,
                                 text="Scan Network",
                                 command=self.start_scan)
        self.scan_btn.pack(pady=10)

        # Progress bar
        self.progress = ttk.Progressbar(main_frame,
                                     orient='horizontal',
                                     length=400,
                                     mode='determinate')
        self.progress.pack(fill=tk.X, padx=10, pady=5)
        
        # Status label
        self.status_label = tk.Label(main_frame,
                                   text="Ready to scan",
                                   font=('Segoe UI', 9),
                                   foreground="#2c3e50",
                                   background="#f0f0f0")
        self.status_label.pack(anchor=tk.W, padx=10)

        # Devices treeview
        self.tree = ttk.Treeview(main_frame,
                               columns=("IP", "MAC", "Hostname"),
                               show="headings",
                               height=15)
        
        for col in ("IP", "MAC", "Hostname"):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150, anchor=tk.W)
            
        scrollbar = ttk.Scrollbar(main_frame,
                                orient=tk.VERTICAL,
                                command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Target input
        ttk.Label(main_frame,
                text="Target IP:").pack(anchor=tk.W, padx=10)
                
        self.target_entry = ttk.Entry(main_frame)
        self.target_entry.pack(fill=tk.X, padx=10, pady=(0,10))

        # Gateway input
        ttk.Label(main_frame,
                text="Gateway IP:").pack(anchor=tk.W, padx=10)
                
        self.gateway_entry = ttk.Entry(main_frame)
        self.gateway_entry.pack(fill=tk.X, padx=10)
        
        if self.gateway_ip:
            self.gateway_entry.insert(0, self.gateway_ip)

        # Spoofing controls
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=15)
        
        self.start_spoof_btn = ttk.Button(btn_frame,
                                        text="Start Spoofing",
                                        style='Accent.TButton',
                                        command=self.start_spoofing)
        self.start_spoof_btn.pack(side=tk.LEFT, padx=10)
        
        self.stop_spoof_btn = ttk.Button(btn_frame,
                                       text="Stop Spoofing",
                                       style='Stop.TButton',
                                       state=tk.DISABLED,
                                       command=self.stop_spoofing)
        self.stop_spoof_btn.pack(side=tk.LEFT, padx=10)

    def start_scan(self):
        """Start network scanning process"""
        self.scan_start_time = time.time()
        self.progress['value'] = 0
        self.status_label.config(text="Scanning network...")
        self.scan_btn.config(state=tk.DISABLED)
        
        # Clear previous results
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        threading.Thread(target=self.run_scan, daemon=True).start()
        
    def run_scan(self):
        """Perform network scan in background"""
        self.scanning_active = True
        devices = []
        
        try:
            # Get ARP table
            output = subprocess.check_output("arp -a", shell=True, text=True, encoding='utf-8')
            
            # Parse ARP entries
            arp_entries = []
            for line in output.splitlines():
                line = line.strip()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}\s+([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}\s+\w+", line):
                    parts = line.split()
                    arp_entries.append((parts[0], parts[1].lower()))
            
            # Resolve hostnames in parallel
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for ip, mac in arp_entries:
                    future = executor.submit(self.resolve_hostname, ip)
                    futures.append((ip, mac, future))
                
                for ip, mac, future in futures:
                    try:
                        hostname = future.result(timeout=2)
                        devices.append((ip, mac, hostname))
                        self.devices_count = len(devices)
                        
                        # Update UI periodically
                        if len(devices) % 5 == 0 or len(devices) == len(arp_entries):
                            self.update_scan_progress(len(devices), len(arp_entries))
                            
                    except Exception:
                        devices.append((ip, mac, ""))
                        self.devices_count = len(devices)
                        
            self.last_scan_duration = time.time() - self.scan_start_time
            self.finish_scan(True, devices)
            
        except Exception as e:
            self.finish_scan(False, None, str(e))
            
    def resolve_hostname(self, ip):
        """Resolve hostname for IP address"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return ""
            
    def update_scan_progress(self, current, total):
        """Update progress bar and status"""
        progress = (current / total) * 100
        self.progress['value'] = progress
        
        elapsed = time.time() - self.scan_start_time
        remaining = (elapsed / current) * (total - current) if current > 0 else 0
        
        status = f"Found {current} devices - {remaining:.1f}s remaining"
        self.status_label.config(text=status)
        
        self.root.update()
        
    def finish_scan(self, success, devices=None, error=None):
        """Handle scan completion"""
        self.scanning_active = False
        self.progress['value'] = 100
        
        if success:
            for ip, mac, hostname in devices:
                self.tree.insert("", tk.END, values=(ip, mac, hostname))
                
            self.status_label.config(text=f"Scan complete - Found {len(devices)} devices in {self.last_scan_duration:.1f}s")
        else:
            self.status_label.config(text=f"Scan failed: {error}")
            
        self.scan_btn.config(state=tk.NORMAL)
        
    def start_spoofing(self):
        """Start ARP spoofing"""
        target = self.target_entry.get().strip()
        gateway = self.gateway_entry.get().strip()
        
        if not target or not gateway:
            messagebox.showwarning("Warning", "Please enter both Target IP and Gateway IP")
            return
            
        self.start_spoof_btn.config(state=tk.DISABLED)
        self.stop_spoof_btn.config(state=tk.NORMAL)
        
        # Implement actual spoofing here
        messagebox.showinfo("Status", f"ARP spoofing started:\nTarget: {target}\nGateway: {gateway}")
        
    def stop_spoofing(self):
        """Stop ARP spoofing"""
        self.start_spoof_btn.config(state=tk.NORMAL)
        self.stop_spoof_btn.config(state=tk.DISABLED)
        messagebox.showinfo("Status", "ARP spoofing stopped")

if __name__ == "__main__":
    root = tk.Tk()
    root.iconbitmap("GreenSkull.ico")
    root.minsize(800,640)
    root.maxsize(830,700)
    # Configure styles
    style = ttk.Style()
    style.theme_use('default')

    style.configure('TButton',
                    font=('Segoe UI', 10),
                    foreground='black',
                    background='#d9d9d9',
                    padding=6)

    style.map('TButton',
            background=[('active', '#c0c0c0')],
            foreground=[('disabled', '#a0a0a0')])
    app = ARPSpoofApp(root)
    root.mainloop()
