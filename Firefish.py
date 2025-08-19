#!/usr/bin/env python3


from __future__ import annotations
import argparse
import dataclasses
import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
except Exception as e:
    print("[!] Scapy import failed. Install with: pip install scapy", file=sys.stderr)
    raise

try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # We'll support JSON too

APP_NAME = "Firefish"
DEFAULT_RULES_PATH = os.path.abspath("firefish_rules.yaml")
DEFAULT_LOG_PATH = os.path.abspath("firefish.log")

# -----------------------------
# Data Models
# -----------------------------
@dataclasses.dataclass
class Rule:
    action: str  # ALLOW | DENY
    direction: str = "BOTH"  # IN | OUT | BOTH
    proto: str = "ANY"       # TCP | UDP | ICMP | ANY
    src_ip: str = "ANY"
    dst_ip: str = "ANY"
    src_port: str = "ANY"    # can be int or range "1000-2000" or "ANY"
    dst_port: str = "ANY"
    label: Optional[str] = None  # e.g., "SUSPICIOUS"

    def normalized(self) -> "Rule":
        self.action = self.action.upper()
        self.direction = self.direction.upper()
        self.proto = self.proto.upper()
        self.src_ip = self.src_ip.upper()
        self.dst_ip = self.dst_ip.upper()
        self.src_port = str(self.src_port).upper()
        self.dst_port = str(self.dst_port).upper()
        return self

@dataclasses.dataclass
class RuleSet:
    default_policy: str = "ALLOW"  # ALLOW or DENY
    rules: List[Rule] = dataclasses.field(default_factory=list)

# -----------------------------
# Utility: Ports & IP matching
# -----------------------------

def _parse_port_spec(spec: str) -> Tuple[Optional[int], Optional[int]]:
    spec = str(spec).upper()
    if spec == "ANY":
        return None, None
    if "-" in spec:
        a, b = spec.split("-", 1)
        return int(a), int(b)
    return int(spec), int(spec)


def _port_matches(port: Optional[int], spec: str) -> bool:
    if port is None:
        return spec == "ANY"
    lo, hi = _parse_port_spec(spec)
    if lo is None and hi is None:
        return True
    return lo <= port <= hi


def _ip_matches(ip_str: Optional[str], spec: str) -> bool:
    if spec == "ANY" or ip_str is None:
        return True
    # spec may be single IP or CIDR
    try:
        net = ipaddress.ip_network(spec, strict=False)
        return ipaddress.ip_address(ip_str) in net
    except Exception:
        # Fallback to direct equality
        return ip_str == spec

# -----------------------------
# Rule Engine
# -----------------------------

def packet_direction(pkt_iface: str, my_ifaces: List[str]) -> str:
    # Simplified heuristic: if the sniffing interface is the packet's ingress, call it IN; else OUT.
    # Scapy's sniffer gives us iface context; for multi-iface, we mark BOTH.
    if len(my_ifaces) == 1:
        return "IN"  # We can't reliably infer OUT vs IN; treat as IN for evaluation with BOTH matches.
    return "BOTH"


def packet_tuple(pkt) -> Dict[str, Any]:
    d: Dict[str, Any] = {
        "src_ip": None,
        "dst_ip": None,
        "proto": "OTHER",
        "src_port": None,
        "dst_port": None,
    }
    if IP in pkt:
        d["src_ip"] = pkt[IP].src
        d["dst_ip"] = pkt[IP].dst
    elif IPv6 in pkt:
        d["src_ip"] = pkt[IPv6].src
        d["dst_ip"] = pkt[IPv6].dst

    if TCP in pkt:
        d["proto"] = "TCP"
        d["src_port"] = int(pkt[TCP].sport)
        d["dst_port"] = int(pkt[TCP].dport)
    elif UDP in pkt:
        d["proto"] = "UDP"
        d["src_port"] = int(pkt[UDP].sport)
        d["dst_port"] = int(pkt[UDP].dport)
    elif ICMP in pkt:
        d["proto"] = "ICMP"
    return d


def evaluate_rules(rt: RuleSet, pkt_dict: Dict[str, Any], pkt_dir: str) -> Tuple[str, Optional[Rule]]:
    """Return (decision, matched_rule) where decision is 'ALLOW' or 'DENY'."""
    for r in rt.rules:
        r = r.normalized()
        # direction match
        if r.direction != "BOTH" and r.direction != pkt_dir:
            # Allow IN packet to still match BOTH rules. If we can't infer OUT reliably, BOTH is safer.
            if not (pkt_dir == "IN" and r.direction == "BOTH"):
                continue
        # proto match
        if r.proto != "ANY" and r.proto != pkt_dict.get("proto"):
            continue
        # ips
        if not _ip_matches(pkt_dict.get("src_ip"), r.src_ip):
            continue
        if not _ip_matches(pkt_dict.get("dst_ip"), r.dst_ip):
            continue
        # ports
        if not _port_matches(pkt_dict.get("src_port"), r.src_port):
            continue
        if not _port_matches(pkt_dict.get("dst_port"), r.dst_port):
            continue
        # matched
        return r.action, r
    return rt.default_policy.upper(), None

# -----------------------------
# iptables Enforcement
# -----------------------------

def iptables_apply_rule(r: Rule, table: str = "filter") -> List[List[str]]:
    """Translate a Rule into iptables commands (v4 only here) and return list of commands.
    We create matching rules in INPUT/OUTPUT chains based on direction.
    """
    base_cmd = ["iptables", "-A", "CHAIN", "-j", "TARGET"]

    def build(chain: str, target: str) -> List[str]:
        cmd = ["iptables", "-A", chain]
        # proto
        if r.proto != "ANY" and r.proto != "ICMP":
            cmd += ["-p", r.proto.lower()]
        elif r.proto == "ICMP":
            cmd += ["-p", "icmp"]
        # src/dst ip
        if r.src_ip != "ANY":
            cmd += ["-s", r.src_ip]
        if r.dst_ip != "ANY":
            cmd += ["-d", r.dst_ip]
        # ports (only valid if proto TCP/UDP specified)
        if r.proto in ("TCP", "UDP"):
            if r.src_port != "ANY":
                cmd += ["--sport", r.src_port]
            if r.dst_port != "ANY":
                cmd += ["--dport", r.dst_port]
        # target
        cmd += ["-j", "DROP" if r.action == "DENY" else "ACCEPT"]
        return cmd

    cmds: List[List[str]] = []
    if r.direction in ("IN", "BOTH"):
        cmds.append(build("INPUT", "DROP" if r.action == "DENY" else "ACCEPT"))
    if r.direction in ("OUT", "BOTH"):
        cmds.append(build("OUTPUT", "DROP" if r.action == "DENY" else "ACCEPT"))
    return cmds


def iptables_flush_firefish_marks():
    # We tag rules we add with comments if xt_comment is available; simpler approach: keep our own chains.
    chains = ["FICEF_INPUT", "FICEF_OUTPUT"]
    for ch in chains:
        subprocess.run(["iptables", "-F", ch], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["iptables", "-X", ch], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # recreate and attach
    for ch, parent in [("FICEF_INPUT", "INPUT"), ("FICEF_OUTPUT", "OUTPUT")]:
        subprocess.run(["iptables", "-N", ch], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["iptables", "-C", parent, "-j", ch], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if subprocess.call(["iptables", "-C", parent, "-j", ch], stdout=subprocess.PIPE, stderr=subprocess.PIPE) != 0:
            subprocess.run(["iptables", "-A", parent, "-j", ch], stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def iptables_apply_ruleset(rs: RuleSet, logger: logging.Logger) -> None:
    logger.info("Applying iptables rules (IPv4) via Firefish chains…")
    iptables_flush_firefish_marks()

    def add(chain: str, cmd: List[str]):
        full = cmd.copy()
        full[2] = chain  # place into our chain
        subprocess.run(full, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.debug("iptables %s", " ".join(full))

    for r in rs.rules:
        r = r.normalized()
        for cmd in iptables_apply_rule(r):
            if r.direction in ("IN", "BOTH"):
                add("FICEF_INPUT", cmd)
            if r.direction in ("OUT", "BOTH"):
                add("FICEF_OUTPUT", cmd)

    # Default policy emulation: place an ACCEPT/DROP catch-all at end of both chains
    default_target = "ACCEPT" if rs.default_policy.upper() == "ALLOW" else "DROP"
    for ch in ("FICEF_INPUT", "FICEF_OUTPUT"):
        subprocess.run(["iptables", "-A", ch, "-j", default_target], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.debug("iptables -A %s -j %s", ch, default_target)

# -----------------------------
# Config Loading
# -----------------------------

def load_rules(path: str, logger: Optional[logging.Logger] = None) -> RuleSet:
    if not os.path.exists(path):
        # create a default
        default = {
            "default_policy": "ALLOW",
            "rules": [
                {"action": "DENY", "direction": "IN", "proto": "TCP", "dst_port": "23", "label": "SUSPICIOUS"},  # block telnet
                {"action": "DENY", "direction": "OUT", "proto": "UDP", "dst_port": "53", "label": "SUSPICIOUS"}, # block DNS exfil
            ],
        }
        if path.endswith(".json"):
            with open(path, "w", encoding="utf-8") as f:
                json.dump(default, f, indent=2)
        else:
            with open(path, "w", encoding="utf-8") as f:
                f.write("default_policy: ALLOW\n")
                f.write("rules:\n")
                f.write("  - action: DENY\n    direction: IN\n    proto: TCP\n    dst_port: '23'\n    label: SUSPICIOUS\n")
                f.write("  - action: DENY\n    direction: OUT\n    proto: UDP\n    dst_port: '53'\n    label: SUSPICIOUS\n")
        if logger:
            logger.warning("Rules file not found. Created default at %s", path)

    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
        cfg: Dict[str, Any]
        if path.endswith(".json"):
            cfg = json.loads(text)
        else:
            if yaml is None:
                raise RuntimeError("PyYAML not installed. Use a JSON rules file or install pyyaml.")
            cfg = yaml.safe_load(text)

    default_policy = cfg.get("default_policy", "ALLOW")
    rules_list = cfg.get("rules", [])
    rules = [Rule(**{k: v for k, v in r.items() if v is not None}).normalized() for r in rules_list]
    return RuleSet(default_policy=default_policy, rules=rules)

# -----------------------------
# Logging
# -----------------------------

def setup_logger(log_path: str, verbose: bool = True) -> logging.Logger:
    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    rh = RotatingFileHandler(log_path, maxBytes=2 * 1024 * 1024, backupCount=3)
    rh.setFormatter(fmt)
    rh.setLevel(logging.DEBUG)
    logger.addHandler(rh)

    if verbose:
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(fmt)
        ch.setLevel(logging.INFO)
        logger.addHandler(ch)
    return logger

# -----------------------------
# Sniffer
# -----------------------------
class SnifferThread(threading.Thread):
    def __init__(self, iface: str, ruleset: RuleSet, logger: logging.Logger, gui_queue: Optional[queue.Queue] = None):
        super().__init__(daemon=True)
        self.iface = iface
        self.ruleset = ruleset
        self.logger = logger
        self.gui_queue = gui_queue
        self._running = threading.Event()
        self._running.set()

    def stop(self):
        self._running.clear()

    def _handle_packet(self, pkt):
        if not self._running.is_set():
            return False  # stop sniff
        pt = packet_tuple(pkt)
        direction = "IN"  # see packet_direction() notes; simplified
        decision, matched = evaluate_rules(self.ruleset, pt, direction)

        level = logging.INFO
        summary = f"{pt['proto']} {pt['src_ip']}:{pt['src_port']} -> {pt['dst_ip']}:{pt['dst_port']} => {decision}"
        if matched and matched.label and matched.label.upper() == "SUSPICIOUS":
            level = logging.WARNING
        self.logger.log(level, summary)
        if self.gui_queue is not None:
            try:
                self.gui_queue.put_nowait({"summary": summary, "level": level, "rule": dataclasses.asdict(matched) if matched else None})
            except Exception:
                pass

    def run(self):
        self.logger.info("Starting sniffer on %s", self.iface)
        try:
            sniff(iface=self.iface, prn=self._handle_packet, store=False)
        except PermissionError:
            self.logger.error("Permission denied. Run as root (sudo).")
        except Exception as e:
            self.logger.error("Sniffer error: %s", e)

# -----------------------------
# GUI (Tkinter)
# -----------------------------
class FirefishGUI:
    def __init__(self, iface: str, ruleset: RuleSet, logger: logging.Logger):
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox

        self.tk = tk.Tk()
        self.tk.title(f"{APP_NAME} — Live Monitor")
        self.tk.geometry("900x520")
        self.logger = logger
        self.ruleset = ruleset
        self.iface = iface

        self.msg_queue: queue.Queue = queue.Queue(maxsize=1000)
        self.sniffer = SnifferThread(iface=self.iface, ruleset=self.ruleset, logger=self.logger, gui_queue=self.msg_queue)

        # Controls
        top = ttk.Frame(self.tk)
        top.pack(fill="x", padx=10, pady=8)

        self.start_btn = ttk.Button(top, text="Start", command=self.start)
        self.stop_btn = ttk.Button(top, text="Stop", command=self.stop, state="disabled")
        self.load_btn = ttk.Button(top, text="Load Rules…", command=self.load_rules_dialog)
        self.enforce_var = tk.BooleanVar(value=False)
        self.enforce_chk = ttk.Checkbutton(top, text="Enforce with iptables", variable=self.enforce_var, command=self.apply_enforcement)

        for w in (self.start_btn, self.stop_btn, self.load_btn, self.enforce_chk):
            w.pack(side="left", padx=6)

        # Tree
        columns = ("time", "level", "message")
        self.tree = ttk.Treeview(self.tk, columns=columns, show="headings")
        for c in columns:
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=200 if c != "message" else 600, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=10, pady=8)

        self.tk.after(250, self._poll_queue)

        def on_close():
            self.stop()
            self.tk.destroy()
        self.tk.protocol("WM_DELETE_WINDOW", on_close)

    def start(self):
        if not self.sniffer.is_alive():
            self.sniffer = SnifferThread(iface=self.iface, ruleset=self.ruleset, logger=self.logger, gui_queue=self.msg_queue)
            self.sniffer.start()
            self.start_btn["state"] = "disabled"
            self.stop_btn["state"] = "normal"

    def stop(self):
        if self.sniffer.is_alive():
            self.sniffer.stop()
            # scapy sniff stops on False return; give it a moment
            time.sleep(0.3)
            self.start_btn["state"] = "normal"
            self.stop_btn["state"] = "disabled"

    def apply_enforcement(self):
        if self.enforce_var.get():
            try:
                iptables_apply_ruleset(self.ruleset, self.logger)
                self.logger.info("iptables enforcement applied.")
            except Exception as e:
                self.logger.error("Failed to apply iptables rules: %s", e)
                self.enforce_var.set(False)
        else:
            try:
                iptables_flush_firefish_marks()
                self.logger.info("iptables Firefish chains flushed.")
            except Exception as e:
                self.logger.error("Failed to flush iptables chains: %s", e)

    def load_rules_dialog(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(title="Select rules file", filetypes=[("YAML", "*.yaml *.yml"), ("JSON", "*.json"), ("All", "*.*")])
        if not path:
            return
        try:
            self.ruleset = load_rules(path, self.logger)
            self.logger.info("Loaded rules from %s", path)
        except Exception as e:
            self.logger.error("Failed to load rules: %s", e)

    def _poll_queue(self):
        try:
            while True:
                item = self.msg_queue.get_nowait()
                ts = time.strftime("%H:%M:%S")
                lvl = logging.getLevelName(item.get("level", logging.INFO))
                msg = item.get("summary", "")
                self.tree.insert("", "end", values=(ts, lvl, msg))
        except queue.Empty:
            pass
        self.tk.after(250, self._poll_queue)

    def run(self):
        self.tk.mainloop()

# -----------------------------
# CLI
# -----------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=f"{APP_NAME}: Lightweight personal firewall (monitor + optional iptables enforcement)")
    p.add_argument("--iface", required=True, help="Network interface to sniff (e.g., eth0, wlan0)")
    p.add_argument("--config", default=DEFAULT_RULES_PATH, help="Path to YAML or JSON rules file")
    p.add_argument("--logfile", default=DEFAULT_LOG_PATH, help="Path to log file (rotating)")
    p.add_argument("--enforce", action="store_true", help="Apply rules to iptables (requires root)")
    p.add_argument("--gui", action="store_true", help="Launch Tkinter GUI for live monitoring")
    p.add_argument("--no-console", action="store_true", help="Do not log to console (log file only)")
    return p.parse_args()


def main():
    args = parse_args()
    logger = setup_logger(args.logfile, verbose=not args.no_console)

    try:
        rs = load_rules(args.config, logger)
        logger.info("Loaded %d rules. Default policy: %s", len(rs.rules), rs.default_policy)
    except Exception as e:
        logger.error("Failed to load rules: %s", e)
        sys.exit(2)

    if args.enforce:
        try:
            iptables_apply_ruleset(rs, logger)
        except Exception as e:
            logger.error("iptables enforcement failed: %s", e)
            sys.exit(3)

    # Graceful shutdown on Ctrl+C
    stop_event = threading.Event()

    def handle_sigint(sig, frame):
        logger.info("Shutting down…")
        stop_event.set()
    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)

    if args.gui:
        gui = FirefishGUI(args.iface, rs, logger)
        gui.run()
        return

    # CLI mode sniffer
    sniffer = SnifferThread(iface=args.iface, ruleset=rs, logger=logger)
    sniffer.start()

    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    finally:
        sniffer.stop()
        time.sleep(0.3)
        if args.enforce:
            logger.info("Leaving iptables rules in place. Run again without --enforce to flush via GUI toggle if needed.")


if __name__ == "__main__":
    main()
