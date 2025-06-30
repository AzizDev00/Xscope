from colorama import Fore, Style, init
init(autoreset=True)

from packet_sniffer import run as sniff_packets
from network_recon import run as recon_scan
from telegram_tool import run as telegram_tool
from privesc_auditor import run as privesc_scan
from cred_sniffer import run as sniff_creds
from wispy import run as wifi_toolkit

BANNER = Fore.CYAN + r"""
██╗  ██╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
╚██╗██╔╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
 ╚███╔╝ ███████╗██║     ██║   ██║██████╔╝█████╗  
 ██╔██╗ ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
██╔╝ ██╗███████║╚██████╗╚██████╔╝██║     ███████╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
""" + Style.BRIGHT + "              Linux Recon & Exploitation Toolkit [Xscope]" + Style.RESET_ALL

MENU = f"""
{Fore.YELLOW}Choose a tool:{Style.RESET_ALL}
  1. Live Packet Sniffer
  2. Network Recon Scanner
  3. Telegram Tool (.session & Code Reader)
  4. Privilege Escalation Auditor
  5. Credential Sniffer (HTTP, FTP, SMTP, POP3)
  6. Wi-Fi Toolkit (Passive, Deauth, Handshake)
  0. Exit
"""

def main():
    while True:
        print(BANNER)
        print(MENU)
        choice = input(f"{Fore.GREEN}>>> {Style.RESET_ALL}").strip()

        if choice == "1":
            sniff_packets()
        elif choice == "2":
            recon_scan()
        elif choice == "3":
            telegram_tool()
        elif choice == "4":
            privesc_scan()
        elif choice == "5":
            sniff_creds()
        elif choice == "6":
            wifi_toolkit()
        elif choice == "0":
            print(Fore.MAGENTA + "\n[+] Exiting Xscope.\n")
            break
        else:
            print(Fore.RED + "[!] Invalid choice.\n")

        input(Fore.CYAN + "\nPress Enter to return to menu..." + Style.RESET_ALL)

if __name__ == "__main__":
    main()
