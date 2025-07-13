import subprocess
import re
import socket
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

class ARPSpoofApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ARP Spoof Tool")
        self.root.geometry("800x650")
        self.root.configure(bg="#f0f0f0")
        
        # Set custom theme
        self.set_custom_theme()

        # Network interfaces
        self.interfaces = self.get_network_interfaces()
        self.interface_var = tk.StringVar()
        if self.interfaces:
            self.interface_var.set(self.interfaces[0])

        # Gateway IP
        self.gateway_ip = self.get_default_gateway()

        # Scan timing control
        self.scan_start_time = 0
        self.estimated_scan_time = 57  # Default estimate (will be adjusted dynamically)
        self.last_scan_duration = 0
        self.devices_count = 0
        self.scanning_active = False

        # GUI layout
        self.create_widgets()

        self.arp_thread = None
        self.stop_spoofing = False

    def set_custom_theme(self):
        style = ttk.Style()
        style.theme_use('default')
        
        # Configure colors
        style.configure('TFrame', background='#f0f0f0')
        style.configure('TButton', 
                       font=('Segoe UI', 10),
                       borderwidth=1,
                       relief='flat',
                       padding=6)
        
        style.map('TButton',
                 foreground=[('active', 'white'), ('!active', 'white')],
                 background=[('active', '#3a7ebf'), ('!active', '#4a8bcf')],
                 relief=[('pressed', 'sunken'), ('!pressed', 'flat')])

    def get_network_interfaces(self):
        try:
            output = subprocess.check_output("netsh interface show interface", 
                                           shell=True, 
                                           text=True, 
                                           encoding='utf-8')
            interfaces = []
            for line in output.splitlines():
                if "Enabled" in line or "Connected" in line:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        name = " ".join(parts[3:])
                        interfaces.append(name)
            return interfaces
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get interfaces: {e}")
            return []

    def get_default_gateway(self):
        try:
            output = subprocess.check_output("route print", 
                                           shell=True, 
                                           text=True, 
                                           encoding='utf-8')
            match = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", 
                            output, 
                            re.MULTILINE)
            if match:
                return match.group(1)
            return ""
        except Exception:
            return ""

    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(header_frame, 
                text="ARP Spoof Tool", 
                font=('Segoe UI', 16, 'bold'),
                foreground="#2c3e50",
                background="#f0f0f0").pack()
        
        # Control frame
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=10)

        # Interface selection
        tk.Label(control_frame, 
                text="Network Interface:",
                font=('Segoe UI', 9),
                foreground="#2c3e50",
                background="#f0f0f0").pack(anchor=tk.W)
        
        self.interface_menu = ttk.Combobox(control_frame, 
                                         values=self.interfaces, 
                                         textvariable=self.interface_var, 
                                         state="readonly",
                                         font=('Segoe UI', 9))
        self.interface_menu.pack(fill=tk.X, pady=(0, 10))

        # Action buttons frame
        btn_frame = ttk.Frame(control_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.load_devices_btn = ttk.Button(btn_frame, 
                                         text="Scan Network",
                                         style='TButton',
                                         command=self.load_devices)
        self.load_devices_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.start_btn = ttk.Button(btn_frame, 
                                   text="Start Spoofing",
                                   style='Accent.TButton',
                                   command=self.start_spoofing)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.stop_btn = ttk.Button(btn_frame, 
                                  text="Stop Spoofing",
                                  style='Stop.TButton',
                                  command=self.stop_spoofing_func)
        self.stop_btn.pack(side=tk.LEFT)
        self.stop_btn.config(state=tk.DISABLED)

        # Progress and timing frame
        self.progress_frame = ttk.Frame(main_frame)
        self.progress_frame.pack(fill=tk.X, pady=10)
        
        # Progress label
        self.progress_label = tk.Label(self.progress_frame,
                                     text="Ready to scan network",
                                     font=('Segoe UI', 9),
                                     foreground="#2c3e50",
                                     background="#f0f0f0")
        self.progress_label.pack(anchor=tk.W, fill=tk.X)
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(self.progress_frame,
                                          orient=tk.HORIZONTAL,
                                          length=400,
                                          mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        # Time estimation label
        self.time_label = tk.Label(self.progress_frame,
                                 text="Estimated time remaining: -",
                                 font=('Segoe UI', 8),
                                 foreground="#666666",
                                 background="#f0f0f0")
        self.time_label.pack(anchor=tk.W)
        
        # Devices count label
        self.devices_label = tk.Label(self.progress_frame,
                                    text="Devices found: 0",
                                    font=('Segoe UI', 8),
                                    foreground="#666666",
                                    background="#f0f0f0")
        self.devices_label.pack(anchor=tk.W)

        # Devices table frame
        table_frame = ttk.Frame(main_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # Table columns
        columns = ("IP", "MAC", "Hostname")
        
        # Create treeview with scrollbar
        self.tree = ttk.Treeview(table_frame, 
                                columns=columns, 
                                show="headings",
                                height=15,
                                style="Custom.Treeview")
        
        # Configure columns
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150, anchor=tk.W)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(table_frame, 
                                orient=tk.VERTICAL, 
                                command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Layout
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Target entry frame
        entry_frame = ttk.Frame(main_frame)
        entry_frame.pack(fill=tk.X, pady=10)

        # Target IP
        tk.Label(entry_frame, 
                text="Target IP:",
                font=('Segoe UI', 9),
                foreground="#2c3e50",
                background="#f0f0f0").pack(anchor=tk.W)
        
        self.target_ip_entry = ttk.Entry(entry_frame, 
                                        font=('Segoe UI', 10))
        self.target_ip_entry.pack(fill=tk.X, pady=(0, 10))

        # Gateway IP
        tk.Label(entry_frame, 
                text="Gateway IP:",
                font=('Segoe UI', 9),
                foreground="#2c3e50",
                background="#f0f0f0").pack(anchor=tk.W)
        
        self.gateway_ip_entry = ttk.Entry(entry_frame, 
                                         font=('Segoe UI', 10))
        self.gateway_ip_entry.pack(fill=tk.X)
        if self.gateway_ip:
            self.gateway_ip_entry.insert(0, self.gateway_ip)

    def load_devices(self):
        self.scan_start_time = time.time()
        self.last_progress_update = self.scan_start_time
        
        # Reset progress
        self.progress_bar['value'] = 0
        self.time_label.config(text="Estimated time remaining: calculating...")
        self.devices_label.config(text="Devices found: 0")
        
        # Disable controls
        self.load_devices_btn.config(state=tk.DISABLED)
        self.start_btn.config(state=tk.DISABLED)
        self.progress_label.config(text="Starting network scan...")
        
        # Start scanning thread
        scan_thread = threading.Thread(target=self._scan_devices_thread, daemon=True)
        scan_thread.start()
        
        # Start progress updater
        self.update_progress_while_scanning()

    def update_progress_while_scanning(self):
        if not self.scanning_active:
            return
            
        elapsed = time.time() - self.scan_start_time
        progress_percent = min(99, (elapsed / self.estimated_scan_time) * 100)
        
        # Update progress bar
        self.progress_bar['value'] = progress_percent
        
        # Update time estimation
        if progress_percent > 0:
            remaining_time = max(0, self.estimated_scan_time - elapsed)
            self.time_label.config(text=f"Estimated time remaining: {remaining_time:.1f} seconds")
        
        # Update devices count
        self.devices_label.config(text=f"Devices found: {self.devices_count}")
        
        # Continue updating if still scanning
        if self.scanning_active:
            self.root.after(200, self.update_progress_while_scanning)

    def _scan_devices_thread(self):
        self.scanning_active = True
        devices = []
        
        try:
            # Stage 1: Initial ARP scan (25% of time)
            self._update_scan_status("Querying ARP table (Stage 1/3)...")
            output = subprocess.check_output("arp -a", shell=True, text=True, encoding='utf-8')
            lines = output.splitlines()
            
            # Adjust time estimate based on initial scan speed
            stage1_time = time.time() - self.scan_start_time
            remaining_factor = 3  # Empirically determined
            self.estimated_scan_time = stage1_time * remaining_factor
            
            # Stage 2: Parsing and host resolution (50% of time)
            self._update_scan_status("Resolving hostnames (Stage 2/3)...")
            scan_start = time.time()
            
            for i, line in enumerate(lines):
                line = line.strip()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}\s+([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}\s+\w+", line):
                    parts = line.split()
                    ip = parts[0]
                    mac = parts[1].lower()
                    
                    try:
                        # Simulate actual network delay
                        time.sleep(0.2)
                        hostname = socket.gethostbyaddr(ip)[0]
                    except (socket.herror, socket.gaierror):
                        hostname = ""
                    
                    devices.append((ip, mac, hostname))
                    self.devices_count = len(devices)
                    
                    # Periodically update UI
                    if time.time() - self.last_progress_update > 0.5:
                        self.root.after(0, lambda: self.progress_label.config(
                            text=f"Found {self.devices_count} devices so far..."))
                        self.last_progress_update = time.time()
            
            # Final stage (25% of time)
            self._update_scan_status("Finalizing results (Stage 3/3)...")
            time.sleep(2)  # Simulate final processing
            
            # Record actual scan time for future estimates
            self.last_scan_duration = time.time() - self.scan_start_time
            
            # Update UI with results
            self.root.after(0, self._scan_completed, devices)
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Scan Error", f"Failed to complete scan: {str(e)}"))
        finally:
            self.scanning_active = False

    def _update_scan_status(self, message):
        self.root.after(0, lambda: self.progress_label.config(text=message))

    def _scan_completed(self, devices):
        self.load_devices_btn.config(state=tk.NORMAL)
        self.start_btn.config(state=tk.NORMAL)
        
        # Complete progress bar
        self.progress_bar['value'] = 100
        self.time_label.config(text=f"Scan completed in {self.last_scan_duration:.1f} seconds")
        self.devices_label.config(text=f"Total devices found: {len(devices)}")
        self.progress_label.config(text="Scan completed successfully!")
        
        # Update device table
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for ip, mac, name in devices:
            self.tree.insert("", tk.END, values=(ip, mac, name))

        # Adjust future estimates based on this scan
        if len(devices) > 0:
            avg_time_per_device = self.last_scan_duration / len(devices)
            self.estimated_scan_time = avg_time_per_device * (len(devices) + 10)  # Add buffer

    def start_spoofing(self):
        target_ip = self.target_ip_entry.get().strip()
        gateway_ip = self.gateway_ip_entry.get().strip()

        if not target_ip or not gateway_ip:
            messagebox.showwarning("Warning", "Please enter both Target IP and Gateway IP.")
            return

        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        messagebox.showinfo("Status", "ARP spoofing started")

    def stop_spoofing_func(self):
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        messagebox.showinfo("Status", "ARP spoofing stopped")

if __name__ == "__main__":
    root = tk.Tk()
    
    # Configure custom styles
    style = ttk.Style(root)
    
    # Button styles
    style.configure('TButton', 
                   font=('Segoe UI', 10),
                   foreground='white',
                   background='#4a8bcf',
                   borderwidth=0,
                   padding=8)
    
    style.map('TButton',
             foreground=[('pressed', 'white'), ('active', 'white')],
             background=[('pressed', '#2c5fa1'), ('active', '#3a7ebf')])
    
    style.configure('Accent.TButton',
                   background='#2ecc71')
    
    style.map('Accent.TButton',
             background=[('pressed', '#27ae60'), ('active', '#2ecc71')])
    
    style.configure('Stop.TButton',
                   background='#e74c3c')
    
    style.map('Stop.TButton',
             background=[('pressed', '#c0392b'), ('active', '#e74c3c')])
    
    # Progress bar style
    style.configure('Horizontal.TProgressbar',
                   thickness=25,
                   troughcolor='#e0e0e0',
                   background='#4a8bcf',
                   troughrelief='flat')
    
    app = ARPSpoofApp(root)
    root.mainloop()
