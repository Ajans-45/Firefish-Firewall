# 📖 Firefish Full User Guide

Firefish is a small Linux tool (written in Python) that watches your network traffic and filters it based on rules you choose.  
It has two modes:  

- **Monitor (safe)** → just watch & log packets using Scapy.  
- **Enforce (power)** → actually block/allow traffic using Linux iptables.  

It also comes with an optional GUI for live traffic monitoring.  

---

## 🔎 Big Picture (Mental Model)

Every time your computer sends/receives something on the network, it’s a **packet**.  

- Firefish reads each packet, checks it against your rules (like “block TCP port 22”), and decides `ALLOW` or `DENY`.  
- **Monitor mode:** only logs the decision.  
- **Enforce mode:** installs `iptables` rules so the OS blocks/allows the traffic.  

---

## ⚙️ Requirements

- Linux (Ubuntu, Kali, Pop!_OS, etc.)  
- Python **3.8+**  
- Root (sudo) access  
- Python packages:  
  ```bash
  sudo pip install scapy pyyaml
📝 Step 1 — Get Your Network Interface Name
Check your network card name (Wi-Fi/Ethernet):

bash
Copy code
ip -br a
Pick the one that’s UP and has your IP (e.g., wlan0 for Wi-Fi, eth0 for Ethernet).

👀 Step 2 — Run Firefish in “Monitor Only” Mode (Safe)
This just watches and logs—no blocking.

bash
Copy code
sudo python firefish.py --iface wlan0
You’ll see logs like:

rust
Copy code
INFO TCP 192.168.1.50:54321 -> 142.250.183.206:443 => ALLOW
👉 Logs are saved in firefish.log (rotating).

Live view:

bash
Copy code
tail -f firefish.log
📜 Step 3 — Understand the Rule File
Rules are stored in firefish_rules.yaml (auto-created if missing).
Rules are checked top to bottom → first match wins.

If no match: default_policy is applied.

Example:
yaml
Copy code
default_policy: ALLOW

rules:
  - action: DENY
    direction: IN
    proto: TCP
    dst_port: 23          # Block Telnet
    label: SUSPICIOUS

  - action: DENY
    direction: OUT
    proto: UDP
    dst_port: 53          # Block outbound DNS

  - action: ALLOW
    direction: BOTH
    proto: ANY
    dst_ip: 8.8.8.8
    dst_port: 443         # Allow to 8.8.8.8:443
👉 Fields:

action: ALLOW / DENY

direction: IN / OUT / BOTH

proto: TCP, UDP, ICMP, ANY

src_ip / dst_ip: ANY, IP (1.2.3.4), or CIDR (192.168.1.0/24)

src_port / dst_port: ANY, number (443), or range (1000-2000)

label: optional, SUSPICIOUS → logs at WARNING level

🖥️ Step 4 — Try the GUI
bash
Copy code
sudo python firefish.py --iface wlan0 --gui
Start → begin sniffing

Load Rules… → custom YAML/JSON

Enforce with iptables → activate blocking

🚫 Step 5 — Switch to “Enforce” Mode
Block/allow traffic at OS level:

bash
Copy code
sudo python firefish.py --iface wlan0 --enforce
What happens:

Creates chains: FICEF_INPUT, FICEF_OUTPUT

Compiles YAML rules into chains

Adds catch-all rule from default_policy

👉 Peek at installed rules:

bash
Copy code
sudo iptables -S FICEF_INPUT
sudo iptables -S FICEF_OUTPUT
🛡️ Step 6 — Beginner Rule Examples
1) Block outbound DNS

yaml
Copy code
- action: DENY
  direction: OUT
  proto: UDP
  dst_port: 53
  label: SUSPICIOUS
2) Block inbound SSH

yaml
Copy code
- action: DENY
  direction: IN
  proto: TCP
  dst_port: 22
⚠️ Don’t do this on a remote SSH server (you’ll lock yourself out).

3) Allow HTTPS to one IP only

yaml
Copy code
- action: ALLOW
  direction: OUT
  proto: TCP
  dst_ip: 93.184.216.34
  dst_port: 443

- action: DENY
  direction: OUT
  proto: TCP
  dst_port: 443
📂 Step 7 — Logs & Suspicious Tagging
Normal entries → INFO

Rules with label: SUSPICIOUS → log at WARNING

Log file: firefish.log

Live view:

bash
Copy code
tail -f firefish.log
🆘 Step 8 — Safe Recovery & Pitfalls
If network breaks → open GUI and uncheck Enforce, or reboot.

Safer on a laptop than remote VM.

Root is needed for sniffing and iptables.

If no traffic appears → double-check --iface.

🛠️ Handy Commands Cheat Sheet
bash
Copy code
# Install deps
sudo pip install scapy pyyaml

# Monitor only
sudo python firefish.py --iface wlan0

# Enforce rules
sudo python firefish.py --iface wlan0 --enforce

# Launch GUI
sudo python firefish.py --iface wlan0 --gui

# Watch logs live
tail -f firefish.log

# Peek at Firefish iptables chains
sudo iptables -S FICEF_INPUT
sudo iptables -S FICEF_OUTPUT
🚫 What Firefish is NOT
Not an enterprise firewall → personal/educational use only.

Not a VPN or IDS (though suspicious tagging helps spot weird traffic).

Not for Windows/macOS enforcement → Linux only.
