#!/bin/bash
echo "[*] Disabling UFW..."
sudo ufw disable

echo "[*] Starting Firefish Firewall..."
sudo python3 $(dirname "$0")/../firefish.py

