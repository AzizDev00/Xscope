from scapy.all import sniff, IP, TCP, UDP, DNS
from colorama import Fore, Style, init
init(autoreset=True)

def packet_callback(packet):
    try:
        if IP in packet:
            proto = "OTHER"
            src = packet[IP].src
            dst = packet[IP].dst

            if UDP in packet:
                proto = "UDP"
                print(f"{Fore.CYAN}[{proto}] {src} -> {dst}")

                if packet.haslayer(DNS) and packet[DNS].qr == 0:
                    query = packet[DNS].qd.qname.decode(errors='ignore')
                    print(f"{Fore.YELLOW}[DNS] Query: {query}")

            elif TCP in packet:
                proto = "TCP"
                print(f"{Fore.GREEN}[{proto}] {src} -> {dst}")
            else:
                print(f"{Fore.MAGENTA}[{proto}] {src} -> {dst}")

    except IndexError:
        pass  # Prevent scapy decode errors from crashing the sniffer
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}")

def run():
    print(Fore.MAGENTA + "\n[+] Starting live packet sniffer... (Press Ctrl+C to stop)\n")
    try:
        sniff(prn=packet_callback, store=0)
    except PermissionError:
        print(Fore.RED + "[!] Run the script as root.")
