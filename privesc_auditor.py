#!/usr/bin/env python3
"""
Privilege Escalation Auditor – Xscope Option 5
Scans for common mis-configs that allow local root escalation.
"""

import os, stat, subprocess, pwd
from colorama import Fore, Style, init
init(autoreset=True)

def check_sudo_l():
    print(Fore.CYAN + "\n[+] Parsing sudo -l (passwordless commands)…")
    try:
        out = subprocess.check_output(["sudo", "-n", "-l"], stderr=subprocess.DEVNULL, text=True)
        if "may run the following commands" in out:
            for line in out.splitlines():
                if line.strip().startswith("("):
                    print(Fore.YELLOW + f"[sudo] {line.strip()}")
        else:
            print("[-] No passwordless sudo commands.")
    except subprocess.CalledProcessError:
        print("[-] User cannot run sudo without password.")

def check_suid_binaries():
    print(Fore.CYAN + "\n[+] Searching for SUID binaries owned by root…")
    for root, _, files in os.walk("/"):
        for f in files:
            path = os.path.join(root, f)
            try:
                st = os.lstat(path)
                if st.st_mode & stat.S_ISUID and st.st_uid == 0:
                    print(Fore.YELLOW + f"[SUID] {path}")
            except: pass

def writable_in_path():
    print(Fore.CYAN + "\n[+] Writable files in directories from $PATH owned by root…")
    for d in os.getenv("PATH", "").split(":"):
        if not os.path.isdir(d): continue
        for f in os.listdir(d):
            path = os.path.join(d, f)
            try:
                st = os.lstat(path)
                if st.st_uid == 0 and os.access(path, os.W_OK):
                    print(Fore.YELLOW + f"[WRITE] {path}")
            except: pass

def cron_world_writable():
    print(Fore.CYAN + "\n[+] World-writable cron scripts…")
    cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly"]
    for cdir in cron_dirs:
        if not os.path.isdir(cdir): continue
        for f in os.listdir(cdir):
            path = os.path.join(cdir, f)
            try:
                if os.access(path, os.W_OK):
                    print(Fore.YELLOW + f"[CRON] {path}")
            except: pass

def run():
    print(Style.BRIGHT + "\n=== Privilege Escalation Auditor ===")
    check_sudo_l()
    check_suid_binaries()
    writable_in_path()
    cron_world_writable()
    print(Style.BRIGHT + "\n[Done]\n")
