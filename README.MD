
---

````markdown
# Xscope 🔍  
**Linux Recon & Exploitation Toolkit**

Xscope is an advanced, modular toolkit designed for network reconnaissance, Wi-Fi analysis, privilege auditing, and more — tailored for Linux (especially Kali Linux) environments.

---

## 🎯 Features

| Option | Tool Name                                | Description |
|--------|------------------------------------------|-------------|
| 1      | **Live Packet Sniffer**                 | Captures network traffic using raw sockets and displays IP-level metadata. |
| 2      | **Network Recon Scanner**               | Scans hosts, ports, services, and banners across the network using `nmap`. |
| 3      | **Telegram Tool (.session & Code)**     | Generates `.session` files and fetches Telegram login codes from API using `telethon`. |
| 4      | **Privilege Escalation Auditor**        | Scans for common Linux misconfigurations, SUID binaries, writable cron jobs, and sudo rights. |
| 5      | **Credential Sniffer (HTTP, FTP, SMTP)**| Sniffs plaintext credentials over insecure protocols from live traffic. |
| 6      | **Wi-Fi Toolkit (Passive, Deauth, Handshake)** | Launches passive scans, deauthentication attacks, and handshake captures. |

---

## 🛠️ Installation

Clone the repository:
```bash
git clone https://github.com/AzizDev00/Xscope.git
cd Xscope
````

Create and activate a virtual environment (recommended):

```bash
python3 -m venv env
source env/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

> ❗ Some tools like Wi-Fi attacks or credential sniffers require **root privileges** and compatible network interfaces (e.g., monitor mode).

---

## 🚀 Usage

Run the toolkit:

```bash
python3 main.py
```

From the main menu, select a tool by entering its corresponding number.

For example:

```text
>>> 1   # Live Packet Sniffer
>>> 6   # Wi-Fi Toolkit
```

---

## 🔐 Telegram Tool Setup

You’ll need:

* **API ID**
* **API Hash**

You can obtain these from: [https://my.telegram.org](https://my.telegram.org)

The tool will prompt for these and store the `.session` file after login (requires a one-time code sent to your Telegram app).

---

## ⚙️ Requirements

```text
colorama
telethon
scapy
psutil
```

You can install all via:

```bash
pip install -r requirements.txt
```

---

## 💻 System Compatibility

| OS         | Status                                                 |
| ---------- | ------------------------------------------------------ |
| Kali Linux | ✅ Fully supported                                      |
| Parrot OS  | ✅ Supported                                            |
| Ubuntu     | ⚠️ Some modules may not work without extra permissions |
| Windows    | ❌ Not supported (Linux tools only)                     |

---

## 🙌 Contributing

Pull requests and suggestions are welcome! If you find a bug or want to suggest a new module:

* Open an issue
* Fork and improve
* Submit a pull request 🚀

---

## 📫 Contact

* GitHub: [AzizDev00](https://github.com/AzizDev00)
* Telegram: [@sharafutdinov\_azizbek](https://t.me/sharafutdinov_azizbek)

---

## 🛡️ Disclaimer

> This toolkit is provided for **educational** and **ethical penetration testing** purposes only.
> Misuse of this software for illegal or unethical purposes is **strictly prohibited**.

---

