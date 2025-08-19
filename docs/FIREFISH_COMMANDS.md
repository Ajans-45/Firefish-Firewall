🐟 Firefish Firewall – Command Guide
🔹 Basic Run (Required)

Run Firefish with a network interface:

sudo python3 Firefish.py --iface eth0


(replace eth0 with your interface, e.g., wlan0 for Wi-Fi)

🔹 Run with Config File

Use your custom rule file:

sudo python3 Firefish.py --iface eth0 --config firefish_rules.yaml

🔹 Run with Logging

Log output to a file:

sudo python3 Firefish.py --iface eth0 --logfile firefish.log

🔹 Enforcement Mode

Actually apply & enforce the firewall rules:

sudo python3 Firefish.py --if🐟 Firefish Firewall – Command Guide
🔹 Basic Run (Required)
Run Firefish with a network interface:

sudo python3 Firefish.py --iface eth0
(replace eth0 with your interface, e.g., wlan0 for Wi-Fi)

🔹 Run with Config File
Use your custom rule file:

sudo python3 Firefish.py --iface eth0 --config firefish_rules.yaml
🔹 Run with Logging
Log output to a file:

sudo python3 Firefish.py --iface eth0 --logfile firefish.log
🔹 Enforcement Mode
Actually apply & enforce the firewall rules:

sudo python3 Firefish.py --iface eth0 --enforce
🔹 GUI Mode
Start Firefish with GUI:

sudo python3 Firefish.py --iface eth0 --gui
🔹 Silent Mode
No console output (only logs):

sudo python3 Firefish.py --iface eth0 --no-console
🔹 Example Full Command
Enforce rules with config + logging:

sudo python3 Firefish.py --iface wlan0 --config firefish_rules.yaml --logfile firefish.log --enforce
🔥 Pro Tip:

To find your interface name, run:

ip link show
Common names: eth0, wlan0, enp3s0, etc.

ace eth0 --enforce

🔹 GUI Mode

Start Firefish with GUI:

sudo python3 Firefish.py --iface eth0 --gui

🔹 Silent Mode

No console output (only logs):

sudo python3 Firefish.py --iface eth0 --no-console

🔹 Example Full Command

Enforce rules with config + logging:

sudo python3 Firefish.py --iface wlan0 --config firefish_rules.yaml --logfile firefish.log --enforce


🔥 Pro Tip:

To find your interface name, run:

ip link show


Common names: eth0, wlan0, enp3s0, etc.
