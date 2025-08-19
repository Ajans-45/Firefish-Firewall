#!/bin/bash
echo "[*] Flushing Firefish firewall rules..."
sudo iptables -F
sudo iptables -X

echo "[*] Re-enabling UFW..."
sudo ufw enable
