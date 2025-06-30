import os
import subprocess
import hashlib

def get_proc_pids():
    return [pid for pid in os.listdir("/proc") if pid.isdigit()]

def get_ps_pids():
    try:
        out = subprocess.check_output(["ps", "-eo", "pid"], text=True)
        return set(out.strip().split("\n")[1:])
    except Exception:
        return set()

def check_hidden_processes():
    print("\n[+] Checking for hidden processes...")
    proc_pids = set(get_proc_pids())
    ps_pids = get_ps_pids()
    hidden = proc_pids - ps_pids

    if hidden:
        for pid in hidden:
            print(f"[!] Hidden process detected: PID {pid}")
    else:
        print("[-] No hidden processes found.")

def list_unusual_modules():
    print("\n[+] Checking kernel modules...")
    try:
        out = subprocess.check_output(["lsmod"], text=True)
        lines = out.strip().split("\n")[1:]
        for line in lines:
            mod = line.split()[0]
            if mod.startswith("hid") or "usb" in mod:
                continue
            if len(mod) > 15 or any(x in mod for x in ['root', 'hack', 'kit']):
                print(f"[!] Suspicious kernel module: {mod}")
    except:
        print("[x] Couldn't list kernel modules.")

def hash_check(filepath, known_hash):
    if not os.path.isfile(filepath):
        return False
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest() == known_hash

def check_binaries():
    print("\n[+] Verifying system binary hashes...")
    # Example known SHA256 hashes (you can replace with actual secure baseline)
    hashes = {
        "/bin/ls": "d41d8cd98f00b204e9800998ecf8427e",  # Replace with real ones
        "/bin/ps": "d41d8cd98f00b204e9800998ecf8427e",
    }
    for path, h in hashes.items():
        if not hash_check(path, h):
            print(f"[!] Tampered binary: {path}")

def find_suspicious_tmp_files():
    print("\n[+] Scanning /tmp and /dev for injected files...")
    suspicious = []
    for directory in ["/tmp", "/dev/shm", "/var/tmp"]:
        try:
            for fname in os.listdir(directory):
                if fname.startswith(".") or fname.endswith(".so") or len(fname) > 20:
                    suspicious.append(f"{directory}/{fname}")
        except:
            pass
    if suspicious:
        for f in suspicious:
            print(f"[!] Suspicious file: {f}")
    else:
        print("[-] No suspicious temp files found.")

def run():
    print("\n=== Rootkit & Hidden Process Detector ===")
    check_hidden_processes()
    list_unusual_modules()
    check_binaries()
    find_suspicious_tmp_files()
