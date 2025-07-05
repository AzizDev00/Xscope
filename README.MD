# 🔍 Xscope — Linux Recon & Exploitation Toolkit

**Xscope** is a powerful modular toolkit built for ethical hackers, cybersecurity researchers, and penetration testers. It provides advanced utilities for network reconnaissance, wireless auditing, privilege escalation analysis, and credential sniffing — optimized for **Linux environments** like Kali Linux.

## ⚙️ Toolkit Overview

| # | Tool                                | Description |
|--:|-------------------------------------|-------------|
| 1 | **Live Packet Sniffer**             | Captures IP/TCP/UDP/ICMP packets using raw sockets with real-time output. |
| 2 | **Network Recon Scanner**           | Uses `nmap` to discover hosts, open ports, services, and basic fingerprinting. |
| 3 | **Telegram Session Manager**        | Creates `.session` files & retrieves 2FA login codes via Telegram API. |
| 4 | **Privilege Escalation Auditor**    | Detects SUID binaries, misconfigured permissions, and writable cron jobs. |
| 5 | **Credential Sniffer**              | Sniffs plaintext HTTP, FTP, SMTP, POP3 credentials from live traffic. |
| 6 | **Wi-Fi Toolkit (WiSpy)**           | Enables monitor mode, scans for APs, captures WPA handshakes, launches deauth attacks. |

> ✅ Root access is required for most tools.  
> ✅ Monitor-mode compatible Wi-Fi adapter is required for Wi-Fi modules.

---

## 🚀 Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/AzizDev00/Xscope.git
cd Xscope
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
````

---

### 2. Run the Toolkit

```bash
sudo python3 main.py
```

---

## 🧰 Toolkit Usage (Menu)

```text
Choose a tool:
  1. Live Packet Sniffer
  2. Network Recon Scanner
  3. Telegram Tool (.session & Code Reader)
  4. Privilege Escalation Auditor
  5. Credential Sniffer (HTTP, FTP, SMTP, POP3)
  6. Wi-Fi Toolkit (Passive, Deauth, Handshake)
  0. Exit
```

---

## 🔐 Telegram Tool Setup

Xscope includes a Telegram automation tool using [Telethon](https://github.com/LonamiWebs/Telethon).

**Steps**:

1. Go to [my.telegram.org](https://my.telegram.org).
2. Create an application → Get **API ID** & **API Hash**.
3. Enter them when prompted.
4. Xscope will save your `.session` file locally.
5. One-time login code will be printed in terminal.

> 🔒 Your session is not stored in the cloud — safe for local usage or bot automation.

---

## 📡 Wi-Fi Toolkit (WiSpy)

WiSpy offers an interactive Wi-Fi attack suite:

| Feature           | Description                              |
| ----------------- | ---------------------------------------- |
| Enable Monitor    | Puts Wi-Fi card into monitor mode        |
| Passive Scan      | Lists visible access points in real-time |
| Capture Handshake | Captures WPA/WPA2 4-way handshakes       |
| Deauth Attack     | Disconnects clients from an AP           |
| Disable Monitor   | Returns interface to managed mode        |

### 🔧 Requirements

* `airmon-ng`, `airodump-ng` (from `aircrack-ng`)
* Compatible adapter in **monitor mode**

---

## 🕵️‍♂️ Credential Sniffer

Captures plaintext credentials from:

* HTTP login forms
* FTP user/pass commands
* SMTP AUTH (login/base64)
* POP3 login sequences

> 🛑 HTTPS traffic is encrypted and will NOT be captured unless using MITM techniques.

---

## 🧪 Example Use Cases

✅ Security labs / CTFs
✅ Network reconnaissance in internal testing
✅ Wi-Fi audits of known devices
✅ Automated `.session` bot deployments for Telegram
✅ Customizable for Red-Team operations

---

## 📦 Dependencies

```bash
pip install -r requirements.txt
```

Or manually install:

```bash
pip install colorama scapy telethon psutil
```

---

## 💻 Compatibility

| OS         | Supported  | Notes                           |
| ---------- | ---------- | ------------------------------- |
| Kali Linux | ✅ Yes      | Fully compatible                |
| Parrot OS  | ✅ Yes      | Fully compatible                |
| Ubuntu     | ⚠️ Partial | May need `sudo` + extra tools   |
| Windows    | ❌ No       | Designed for Linux terminal use |

---

## 🧑‍💻 Author

**Azizbek Sharafutdinov**

* GitHub: [AzizDev00](https://github.com/AzizDev00)
* Telegram: [`@sharafutdinov_azizbek`](https://t.me/sharafutdinov_azizbek)

---

## ⚠️ Disclaimer

> This project is for **educational** and **authorized penetration testing** only.
> The developer is **not responsible** for any misuse or illegal activity.

---

## 🤝 Contributing

Contributions are welcome!
If you have a new tool idea, bug fix, or improvement:

1. Fork the repository
2. Make your changes
3. Submit a pull request

---
