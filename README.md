# 🔥 Firefish — A Lightweight Personal Firewall in Python  

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)  
![Platform](https://img.shields.io/badge/platform-Linux-orange.svg)  
![License](https://img.shields.io/badge/license-MIT-green.svg)  
![Status](https://img.shields.io/badge/status-active-success.svg)  
![Last Commit](https://img.shields.io/github/last-commit/<your-username>/firefish-firewall)

Firefish is a simple yet powerful **rule-based firewall** and **network monitor** built in Python.  
It allows you to define rules for **IP, ports, and protocols**, monitor traffic in real time, and optionally enforce rules with **iptables**.  

---

## ✨ Features
- Rule-based allow/deny for IPs, ports, and protocols  
- Live packet sniffing with [Scapy](https://scapy.net/) for monitoring/logging  
- Optional system-level enforcement using **iptables** (Linux only)  
- Command-line interface (CLI) + optional Tkinter GUI for live view and control  
- Rotating logs and simple **JSON/YAML rule files**  

---

## ⚙️ Requirements (Linux)
- Python **3.8+**  
- [scapy](https://pypi.org/project/scapy/) → `sudo pip install scapy`  
- [pyyaml](https://pypi.org/project/PyYAML/) → `sudo pip install pyyaml` (optional, for YAML configs)  
- Root privileges (needed for packet sniffing and iptables changes)  

---

## 🚀 Usage Examples

### Monitor only (no iptables changes), using default rules file:
```bash
sudo python firefish.py --iface eth0
```

Enforce rules via iptables + monitor:
```bash
sudo python firefish.py --iface eth0 --enforce
```

Use a specific rules file:
```bash
sudo python firefish.py --config /path/to/my_rules.yaml --iface wlan0 --enforce

Launch the GUI:
```bash
sudo python firefish.py --iface eth0 --gui


📜 Rules File Format (YAML)

Example firefish_rules.yaml:

# Default policy if no rules match
default_policy: ALLOW   # or DENY

rules:
  - action: DENY
    direction: IN       # IN | OUT | BOTH
    proto: TCP          # TCP | UDP | ICMP | ANY
    src_ip: ANY
    dst_ip: 192.168.1.100
    dst_port: 22        # block inbound SSH to this host

  - action: DENY
    direction: OUT
    proto: UDP
    dst_port: 53        # block outbound DNS

  - action: ALLOW
    direction: BOTH
    proto: ANY
    dst_ip: 8.8.8.8
    dst_port: 443       # allow traffic to Google DNS over HTTPS

  - action: DENY
    direction: BOTH
    proto: ANY
    src_ip: 10.0.0.0/8  # block private source subnet

  - action: ALLOW
    direction: IN
    proto: TCP
    dst_port: 3389
    label: SUSPICIOUS   # suspicious criteria → logged at WARNING level

👉 Order matters: First matching rule applies. If no rule matches, the default policy applies.

🛠️ Installation
Clone the repo:
```bash
git clone https://github.com/<your-username>/firefish-firewall.git
cd firefish-firewall

Make scripts executable:
```bash
chmod +x scripts/start_firefish.sh scripts/stop_firefish.sh

▶️ Usage (Scripts)
Start Firefish
```bash
./scripts/start_firefish.sh
```
✅ Disables UFW (if running) and starts Firefish.

Stop Firefish
```bash
./scripts/stop_firefish.sh
```
✅ Flushes Firefish rules and re-enables UFW.

⚠️ Disclaimer

Firefish is intended for educational and personal use.

Use responsibly and at your own risk.

Root privileges are required for full functionality.

📌 TODO / Future Improvements

Cross-platform support (Windows/macOS)

Advanced GUI with rule management

Intrusion detection features (anomaly detection, alerts)

## 📖 Full Guide
For a complete beginner-friendly step-by-step usage guide, see:  
👉 [Firefish Full User Guide](docs/FIREFISH_GUIDE.md)

💻 Author:S.Ajans
