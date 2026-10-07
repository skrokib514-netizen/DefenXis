#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
   DEFENXIS — Autonomous Anti-Throttling Companion & Identity Sentinel
   Standalone Edition for Local Network Protection & Throttwin Whitelisting
═══════════════════════════════════════════════════════════════════════════════

Runs continuously on client devices (laptops, PCs) and broadcasts authenticated
cryptographic heartbeats across local network subnets. Throttwin instances detect
these signals and automatically whitelist/liberate the device regardless of MAC
address randomization or IP renewals.
"""

import sys
import os
import time
import json
import socket
import struct
import logging
import threading
import argparse
import subprocess
import re
import urllib.request
import webbrowser
import math
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path
from PIL import Image, ImageTk

def run_fast_speed_test(progress_callback=None, duration=4.5) -> Tuple[float, float]:
    """
    Measures live network download speed directly using Netflix's Fast.com Open Connect CDN.
    Falls back to Cloudflare CDN if Fast.com targets are unreachable.
    Returns: (speed_mbps, duration_seconds)
    """
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    # 1. Attempt Fast.com Netflix CDN extraction
    try:
        req = urllib.request.Request("https://fast.com", headers=headers)
        with urllib.request.urlopen(req, timeout=4) as resp:
            html = resp.read().decode("utf-8", errors="ignore")

        m = re.search(r"app-[a-f0-9]+\.js", html)
        if m:
            js_url = "https://fast.com/" + m.group(0)
            with urllib.request.urlopen(urllib.request.Request(js_url, headers=headers), timeout=4) as resp:
                js = resp.read().decode("utf-8", errors="ignore")
            tok_m = re.search(r'token:"([^"]+)"', js)
            if tok_m:
                token = tok_m.group(1)
                api_url = f"https://api.fast.com/netflix/speedtest/v2?https=true&token={token}&urlCount=3"
                with urllib.request.urlopen(urllib.request.Request(api_url, headers=headers), timeout=4) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                targets = [t["url"] for t in data.get("targets", []) if "url" in t]
                if targets:
                    test_url = targets[0]
                    t0 = time.time()
                    total_bytes = 0
                    current_mbps = 0.0
                    with urllib.request.urlopen(urllib.request.Request(test_url, headers=headers), timeout=8) as stream:
                        while True:
                            chunk = stream.read(64 * 1024)
                            if not chunk:
                                break
                            total_bytes += len(chunk)
                            elapsed = time.time() - t0
                            if elapsed > 0:
                                current_mbps = (total_bytes * 8) / (elapsed * 1_000_000)
                                if progress_callback:
                                    progress_callback(current_mbps, elapsed)
                            if elapsed >= duration:
                                break
                    return current_mbps, round(elapsed, 2)
    except Exception as e:
        log.debug(f"Fast.com direct fetch note: {e}")

    # 2. Reliable CDN Fallback (Cloudflare 25MB test stream)
    try:
        cf_url = "https://speed.cloudflare.com/__down?bytes=25000000"
        t0 = time.time()
        total_bytes = 0
        current_mbps = 0.0
        with urllib.request.urlopen(urllib.request.Request(cf_url, headers=headers), timeout=8) as stream:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                total_bytes += len(chunk)
                elapsed = time.time() - t0
                if elapsed > 0:
                    current_mbps = (total_bytes * 8) / (elapsed * 1_000_000)
                    if progress_callback:
                        progress_callback(current_mbps, elapsed)
                if elapsed >= duration:
                    break
        return current_mbps, round(elapsed, 2)
    except Exception as e:
        log.debug(f"Speed test fallback error: {e}")
        return 0.0, 0.0


def get_asset_path(filename: str) -> str:
    """Returns absolute path to an asset file, supporting PyInstaller bundles and local dev."""
    if hasattr(sys, "_MEIPASS"):
        p = os.path.join(sys._MEIPASS, filename)
        if os.path.exists(p):
            return p
    local_p = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    if os.path.exists(local_p):
        return local_p
    cwd_p = os.path.join(os.getcwd(), filename)
    if os.path.exists(cwd_p):
        return cwd_p
    return filename

# Enable High DPI Awareness before Tkinter initializes
def enable_high_dpi():
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                try:
                    ctypes.windll.user32.SetProcessDPIAware()
                except Exception:
                    pass

enable_high_dpi()

# Set AppUserModelID so Windows Taskbar displays custom DefenXis icon instead of generic Python/Tk feather
def setup_windows_app_id():
    if sys.platform == "win32":
        try:
            import ctypes
            myappid = "defenxis.sentinel.identity.protection.v1"
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        except Exception:
            pass

setup_windows_app_id()


def is_admin() -> bool:
    """Returns True if current process has Administrator privileges."""
    if sys.platform == "win32":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0 if hasattr(os, "geteuid") else True


def elevate_to_admin():
    """Auto-elevates the current process to Administrator on Windows via UAC."""
    if sys.platform == "win32" and not is_admin():
        try:
            import ctypes
            if getattr(sys, "frozen", False):
                # Running as compiled standalone executable (PyInstaller)
                exe = sys.executable
                params = " ".join(f'"{a}"' if " " in a else a for a in sys.argv[1:])
            else:
                # Running as Python script
                exe = sys.executable
                script = sys.argv[0]
                params = f'"{script}" ' + " ".join(f'"{a}"' if " " in a else a for a in sys.argv[1:])

            ret = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", exe, params.strip(), None, 1
            )
            if ret > 32:
                sys.exit(0)
        except Exception as e:
            log.warning(f"UAC auto-elevation notice: {e}")


def set_high_priority():
    """Sets process priority class to High Priority on Windows for real-time responsiveness."""
    if sys.platform == "win32":
        try:
            import ctypes
            # HIGH_PRIORITY_CLASS = 0x00000080
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.kernel32.SetPriorityClass(handle, 0x00000080):
                log.info("DefenXis running with HIGH_PRIORITY_CLASS privileges.")
        except Exception as e:
            log.debug(f"Failed to set process priority: {e}")


import license_utils
import integrity_guard

try:
    import auto_activate
except ImportError:
    auto_activate = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("new.defender")

DEFENDER_BEACON_PORT = 58291
DEFENDER_BEACON_PROTOCOL = "THROTTWIN_DEFENDER_V1"
APP_NAME = "Throttwin Defender"


# ═══════════════════════════════════════════════════════════════════════════════
# Network Discovery & Beacon Sender Core
# ═══════════════════════════════════════════════════════════════════════════════

SKIP_KEYWORDS = [
    "loopback", "pseudo", "wan miniport", "bluetooth",
    "tailscale", "openvpn", "wiresock", "tap", "tun",
    "virtualbox", "vbox", "vmware", "vmnet", "hyper-v", "vethernet", "wsl", "vnic",
    "direct virtual", "mobile broadband", "host-only"
]

VIRTUAL_MAC_PREFIXES = (
    "0a:00:27", "08:00:27",  # VirtualBox
    "00:05:69", "00:0c:29", "00:1c:14", "00:50:56",  # VMware
    "00:15:5d",  # Hyper-V / WSL
    "00:ff:", "02:ff:",  # TAP / VPN
    "02:00:4c",  # Tailscale
)


def is_virtual_adapter(name: str, mac: Optional[str] = None, desc: str = "") -> bool:
    """Identifies virtual, VPN, container, or VM host-only adapters."""
    combined = f"{name} {desc}".lower()
    if any(k in combined for k in SKIP_KEYWORDS):
        return True
    if mac and any(mac.lower().startswith(p) for p in VIRTUAL_MAC_PREFIXES):
        return True
    return False


def _get_default_gateway_and_route_ip() -> Tuple[Optional[str], Optional[str]]:
    """
    Resolves the active default gateway and outbound route interface IP using
    Windows routing table and socket route resolution.
    """
    gw = None
    route_ip = None

    if sys.platform == "win32":
        # Fast route table inspection via 'route print 0.0.0.0'
        try:
            out = subprocess.check_output("route print 0.0.0.0", shell=True, stderr=subprocess.DEVNULL, timeout=2).decode()
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    candidate_gw = parts[2]
                    candidate_ip = parts[3]
                    if candidate_gw and candidate_gw != "0.0.0.0":
                        gw = candidate_gw
                    if candidate_ip and not candidate_ip.startswith("127.") and not candidate_ip.startswith("169.254."):
                        route_ip = candidate_ip
                    if gw and route_ip:
                        break
        except Exception:
            pass

        # Fallback to PowerShell route query if needed
        if not gw:
            try:
                cmd = 'powershell -NoProfile -Command "(Get-NetRoute -DestinationPrefix \'0.0.0.0/0\' -ErrorAction SilentlyContinue | Sort-Object { [int]$_.RouteMetric + [int]$_.ifMetric } | Select-Object -First 1).NextHop"'
                pw_gw = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=3).decode().strip()
                if pw_gw and pw_gw != "0.0.0.0":
                    gw = pw_gw
            except Exception:
                pass

    # Socket outbound test to determine kernel-routed interface
    for test_target in ("8.8.8.8", "1.1.1.1", gw):
        if not test_target or test_target == "0.0.0.0":
            continue
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((test_target, 80))
            candidate_ip = s.getsockname()[0]
            s.close()
            if candidate_ip and not candidate_ip.startswith("127.") and not candidate_ip.startswith("169.254."):
                route_ip = candidate_ip
                break
        except Exception:
            pass

    return gw, route_ip


def get_network_details() -> Dict[str, Any]:
    """
    Discovers all local network adapters, identifies the active physical Wi-Fi/Ethernet interface,
    extracts MAC addresses, and calculates subnet broadcast targets while filtering virtual adapters.
    """
    adapters = []
    primary_ip = None
    primary_mac = None
    all_ips = []
    all_macs = []
    broadcast_targets = set()

    primary_gateway, route_ip = _get_default_gateway_and_route_ip()
    if primary_gateway:
        broadcast_targets.add(primary_gateway)

    try:
        import psutil
        if_addrs = psutil.net_if_addrs()
        if_stats = psutil.net_if_stats()

        scored_candidates = []

        for iface_name, addrs in if_addrs.items():
            stats = if_stats.get(iface_name)
            is_up = stats.isup if stats else True

            mac = None
            ipv4 = None
            netmask = None
            broadcast = None

            for a in addrs:
                if a.family == psutil.AF_LINK or (hasattr(socket, "AF_LINK") and a.family == socket.AF_LINK):
                    mac = a.address.replace("-", ":").lower()
                elif a.family == socket.AF_INET:
                    if not a.address.startswith("127.") and not a.address.startswith("169.254."):
                        ipv4 = a.address
                        netmask = a.netmask
                        broadcast = a.broadcast

            if not ipv4:
                continue

            is_virt = is_virtual_adapter(iface_name, mac)

            # Calculate subnet broadcast address if not provided by OS
            if not broadcast and netmask:
                try:
                    import ipaddress
                    net = ipaddress.IPv4Network(f"{ipv4}/{netmask}", strict=False)
                    broadcast = str(net.broadcast_address)
                except Exception:
                    broadcast = "255.255.255.255"

            # Multi-factor score calculation
            score = 0
            if ipv4 == route_ip:
                score += 2000
            if primary_gateway and netmask:
                try:
                    import ipaddress
                    iface_net = ipaddress.IPv4Network(f"{ipv4}/{netmask}", strict=False)
                    if ipaddress.IPv4Address(primary_gateway) in iface_net:
                        score += 1000
                except Exception:
                    pass

            name_lower = iface_name.lower()
            if any(w in name_lower for w in ("wi-fi", "wifi", "wireless", "wlan", "802.11")):
                score += 300
            elif "ethernet" in name_lower and not is_virt:
                score += 200

            if is_virt:
                score -= 2000
            if not is_up:
                score -= 1000

            # Only add to LAN broadcast list and candidate IPs if non-virtual
            if not is_virt:
                all_ips.append(ipv4)
                if mac:
                    all_macs.append(mac)
                if broadcast:
                    broadcast_targets.add(broadcast)

            candidate_info = {
                "name": iface_name,
                "ip": ipv4,
                "mac": mac or "Unknown",
                "broadcast": broadcast or "255.255.255.255",
                "is_virt": is_virt,
                "is_up": is_up,
                "score": score
            }
            adapters.append(candidate_info)
            scored_candidates.append(candidate_info)

        # Select highest-scoring adapter as primary identity
        if scored_candidates:
            scored_candidates.sort(key=lambda x: x["score"], reverse=True)
            best = scored_candidates[0]
            primary_ip = best["ip"]
            primary_mac = best["mac"]

    except Exception as e:
        log.debug(f"psutil network enumeration notice: {e}")

    # Fallbacks if still unresolved
    if not primary_ip:
        primary_ip = route_ip or "127.0.0.1"
    if not primary_mac and sys.platform == "win32":
        try:
            import uuid
            raw_mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8*6, 8)][::-1])
            primary_mac = raw_mac
            if primary_mac not in all_macs:
                all_macs.append(raw_mac)
        except Exception:
            primary_mac = "00:00:00:00:00:00"

    broadcast_targets.add("255.255.255.255")

    return {
        "hostname": socket.gethostname(),
        "primary_ip": primary_ip or "127.0.0.1",
        "primary_mac": primary_mac or "00:00:00:00:00:00",
        "gateway": primary_gateway or "Auto-detected",
        "all_ips": list(set(all_ips)) if all_ips else [primary_ip],
        "all_macs": list(set(all_macs)) if all_macs else [primary_mac],
        "adapters": adapters,
        "broadcast_targets": list(broadcast_targets)
    }


class DefenderBeaconSender:
    """
    Background worker that continuously transmits signed UDP broadcast
    beacons across all local subnets every 1.5 seconds.
    """

    def __init__(self, on_status_change=None):
        self.on_status_change = on_status_change
        self.lock = threading.Lock()
        self.running = False
        self.paused = False
        self._stop_event = threading.Event()
        self._thread = None

        self.machine_code = license_utils.get_machine_code()
        self.license_token = None
        self.license_payload = None
        self.is_licensed = False
        self.license_message = "Checking license..."

        # Live Telemetry
        self.beacons_sent = 0
        self.last_beacon_ts = 0.0
        self.current_network = {}
        self.last_mac = None

        self.refresh_license()

    def refresh_license(self) -> bool:
        """Reloads and cryptographically validates the active license key, with auto-activation fallback."""
        with self.lock:
            is_valid, payload, msg, mc, raw_key = license_utils.check_license_status(app_name=APP_NAME)
            
            # If not licensed, attempt automatic lifetime license generation
            if not is_valid and auto_activate:
                try:
                    if auto_activate.ensure_lifetime_license(app_name=APP_NAME):
                        is_valid, payload, msg, mc, raw_key = license_utils.check_license_status(app_name=APP_NAME)
                except Exception as e:
                    log.debug(f"Auto-activation notice: {e}")

            self.machine_code = mc
            self.is_licensed = is_valid
            self.license_payload = payload
            self.license_message = msg
            self.license_token = raw_key
            return self.is_licensed

    def start(self):
        """Starts the background beacon broadcasting thread and discovery probe listener."""
        with self.lock:
            if self.running:
                return
            self.running = True
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._worker_loop, name="DefenderBeaconThread", daemon=True)
            self._thread.start()
            self._probe_thread = threading.Thread(target=self._probe_listener_loop, name="DefenderProbeListener", daemon=True)
            self._probe_thread.start()

    def stop(self):
        """Stops beacon broadcasting and probe listener."""
        with self.lock:
            if not self.running:
                return
            self.running = False
            self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)
        if hasattr(self, "_probe_thread") and self._probe_thread and self._probe_thread.is_alive():
            self._probe_thread.join(timeout=1.0)

    def pause(self):
        """Pauses signal transmission."""
        with self.lock:
            self.paused = True

    def resume(self):
        """Resumes signal transmission."""
        with self.lock:
            self.paused = False

    def trigger_instant_pulse(self):
        """Triggers an immediate burst of beacons right away."""
        threading.Thread(target=self._send_beacon_pulse, args=(5,), daemon=True).start()

    def _probe_listener_loop(self):
        """Listens on UDP 58291 for on-demand discovery probe broadcasts from Throttwin controllers."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            except Exception:
                pass
            sock.bind(("", DEFENDER_BEACON_PORT))
            sock.settimeout(2.0)
        except Exception as e:
            log.debug(f"Probe listener bind notice: {e}")
            return

        while not self._stop_event.is_set():
            try:
                data, addr = sock.recvfrom(2048)
                if not data:
                    continue
                try:
                    msg = json.loads(data.decode("utf-8", errors="ignore"))
                    if isinstance(msg, dict) and msg.get("protocol") == "THROTTWIN_DEFENDER_DISCOVERY_V1":
                        log.info(f"📡 Received active discovery probe from controller {addr[0]} -> pulsing immediate response.")
                        self.trigger_instant_pulse()
                except Exception:
                    pass
            except socket.timeout:
                continue
            except Exception:
                break
        try:
            sock.close()
        except Exception:
            pass

    def _worker_loop(self):
        """Main loop: broadcasts beacon every 1.5 seconds for instant detection and weak Wi-Fi resilience."""
        while not self._stop_event.is_set():
            if not self.paused:
                self._send_beacon_pulse(burst_count=2)

            # Wait 1.5 seconds or exit early if stopped
            if self._stop_event.wait(1.5):
                break

    def _send_beacon_pulse(self, burst_count: int = 2):
        """Assembles signed beacon payload and broadcasts via UDP socket with multi-destination redundancy."""
        # 1. License Check
        if not self.is_licensed or not self.license_token:
            self.refresh_license()
            if not self.is_licensed:
                return

        # 2. Network Discovery
        net = get_network_details()
        with self.lock:
            self.current_network = net

        current_mac = net.get("primary_mac")
        if self.last_mac and self.last_mac != current_mac:
            log.info(f"🔄 MAC address change detected: {self.last_mac} -> {current_mac} (Triggering fast 5-packet burst)")
            burst_count = max(burst_count, 5)
        self.last_mac = current_mac

        # 3. Assemble Beacon Payload
        client_name = self.license_payload.get("client", "Defender Node") if self.license_payload else "Defender Node"
        beacon = {
            "protocol": DEFENDER_BEACON_PROTOCOL,
            "timestamp": time.time(),
            "machine_id": self.machine_code,
            "client_name": client_name,
            "hostname": net.get("hostname", socket.gethostname()),
            "os": f"Windows ({sys.platform})",
            "primary_ip": net.get("primary_ip"),
            "primary_mac": net.get("primary_mac"),
            "ips": net.get("all_ips", []),
            "macs": net.get("all_macs", []),
            "license_token": self.license_token,
        }

        raw_payload = json.dumps(beacon).encode("utf-8")

        # 4. Transmit UDP Broadcast Datagrams (Simultaneous Multi-Interface Egress)
        targets = set(net.get("broadcast_targets", ["255.255.255.255"]))
        targets.add("255.255.255.255")

        # Gather all physical active adapters for dedicated interface-bound transmission
        physical_adapters = [
            a for a in net.get("adapters", [])
            if not a.get("is_virt", False) and a.get("ip") and a.get("is_up", True)
        ]

        try:
            # A. General Outbound Socket (Default Kernel Route)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(0.5)

            for _ in range(burst_count):
                for target_ip in targets:
                    if not target_ip or target_ip == "0.0.0.0":
                        continue
                    try:
                        sock.sendto(raw_payload, (target_ip, DEFENDER_BEACON_PORT))
                    except Exception:
                        pass
                if burst_count > 1:
                    time.sleep(0.015)  # 15ms mini-burst spacing

            sock.close()

            # B. Interface-Bound Sockets: Transmit specifically through each physical NIC (Wi-Fi 1, Wi-Fi 2, Ethernet)
            for adapter in physical_adapters:
                iface_ip = adapter["ip"]
                iface_broadcast = adapter.get("broadcast", "255.255.255.255")
                try:
                    iface_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    iface_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    iface_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    iface_sock.bind((iface_ip, 0))
                    iface_sock.settimeout(0.5)

                    # Send to interface-specific subnet broadcast and global broadcast
                    for dest in {iface_broadcast, "255.255.255.255"}:
                        try:
                            iface_sock.sendto(raw_payload, (dest, DEFENDER_BEACON_PORT))
                        except Exception:
                            pass
                    iface_sock.close()
                except Exception:
                    pass

            with self.lock:
                self.beacons_sent += burst_count
                self.last_beacon_ts = time.time()

        except Exception as e:
            log.debug(f"Beacon broadcast error: {e}")

        if self.on_status_change:
            try:
                self.on_status_change()
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════════════
# Modern GUI Desktop Application (Tkinter Cyberpunk / Sentinel Theme)
# ═══════════════════════════════════════════════════════════════════════════════

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Color Palette (Cyberpunk Emerald & Slate Dark)
BG_MAIN = "#0b0f19"         # Ultra-deep navy canvas
BG_CARD = "#111827"         # Elevated panel card
BG_CARD_LIGHT = "#1f2937"   # Secondary widget card
BG_INPUT = "#1e293b"        # Inputs
BORDER = "#374151"          # Subtle stroke
BORDER_GLOW = "#10b981"     # Emerald glow

ACCENT_EMERALD = "#10b981"  # Active / Shield green
ACCENT_CYAN = "#06b6d4"     # Cyberpunk cyan
ACCENT_AMBER = "#f59e0b"    # Warning / Paused
ACCENT_RED = "#ef4444"      # Danger / Expired
FG_TITLE = "#f9fafb"        # Pure white
FG_BODY = "#d1d5db"         # Soft slate
FG_MUTED = "#9ca3af"        # Muted caption


def copy_clipboard(text: str):
    try:
        if sys.platform == "win32":
            subprocess.run("clip", input=text, text=True, check=False)
        else:
            subprocess.run(["xclip", "-selection", "clipboard"], input=text.encode(), check=False)
    except Exception:
        pass


class DefenderActivationModal:
    """Activation Dialog for entering or browsing RSA license keys."""

    def __init__(self, parent, beacon_sender: DefenderBeaconSender, on_activated=None):
        self.parent = parent
        self.sender = beacon_sender
        self.on_activated = on_activated

        self.win = tk.Toplevel(parent)
        self.win.title("Activate DefenXis Sentinel")
        self.win.geometry("540x480")
        self.win.configure(bg=BG_MAIN)
        self.win.resizable(False, False)
        self.win.transient(parent)
        self.win.grab_set()

        # Center on parent
        self.win.update_idletasks()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        px, py = parent.winfo_x(), parent.winfo_y()
        w, h = 540, 480
        x = max(0, px + (pw - w) // 2)
        y = max(0, py + (ph - h) // 2)
        ico_path = get_asset_path("icon.ico")
        if os.path.exists(ico_path):
            try:
                self.win.iconbitmap(ico_path)
            except Exception:
                pass

        self._build_ui()

    def _build_ui(self):
        # Header
        header = tk.Frame(self.win, bg=BG_MAIN, padx=24, pady=18)
        header.pack(fill="x")

        lbl_title = tk.Label(header, text="🛡 LICENSE HUB & ACTIVATION", font=("Segoe UI Bold", 13), bg=BG_MAIN, fg=ACCENT_CYAN)
        lbl_title.pack(anchor="w")

        lbl_sub = tk.Label(header, text="Enter or generate signed RSA license to authorize anti-throttling defense.", font=("Segoe UI", 9), bg=BG_MAIN, fg=FG_MUTED)
        lbl_sub.pack(anchor="w", pady=(2, 0))

        # Body Card
        body = tk.Frame(self.win, bg=BG_CARD, padx=20, pady=16, highlightbackground=BORDER, highlightthickness=1)
        body.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Machine Code
        lbl_mc = tk.Label(body, text="Your Machine Hardware ID (HWID):", font=("Segoe UI Semibold", 9), bg=BG_CARD, fg=FG_BODY)
        lbl_mc.pack(anchor="w")

        mc_row = tk.Frame(body, bg=BG_CARD)
        mc_row.pack(fill="x", pady=(4, 12))

        self.ent_mc = tk.Entry(mc_row, font=("JetBrains Mono", 9), bg=BG_INPUT, fg=ACCENT_CYAN, relief="flat", highlightbackground=BORDER, highlightthickness=1)
        self.ent_mc.pack(side="left", fill="x", expand=True, ipady=5)
        self.ent_mc.insert(0, self.sender.machine_code)
        self.ent_mc.configure(state="readonly")

        btn_copy_mc = tk.Button(
            mc_row, text="Copy", font=("Segoe UI Bold", 8), bg=BG_CARD_LIGHT, fg=FG_TITLE,
            activebackground=ACCENT_CYAN, activeforeground="#000", relief="flat", padx=10, cursor="hand2",
            command=self._copy_machine_code
        )
        btn_copy_mc.pack(side="right", padx=(6, 0))

        # Key Input
        lbl_key = tk.Label(body, text="Paste License Key or Token:", font=("Segoe UI Semibold", 9), bg=BG_CARD, fg=FG_BODY)
        lbl_key.pack(anchor="w")

        self.txt_key = tk.Text(body, height=5, font=("JetBrains Mono", 8), bg=BG_INPUT, fg=FG_TITLE, insertbackground=FG_TITLE, relief="flat", highlightbackground=BORDER, highlightthickness=1)
        self.txt_key.pack(fill="x", pady=(4, 10))

        # Buttons Row
        btn_row = tk.Frame(body, bg=BG_CARD)
        btn_row.pack(fill="x", pady=(4, 0))

        btn_browse = tk.Button(
            btn_row, text="📁 Browse .key File", font=("Segoe UI", 9), bg=BG_CARD_LIGHT, fg=FG_TITLE,
            relief="flat", padx=12, pady=6, cursor="hand2", command=self._browse_key_file
        )
        btn_browse.pack(side="left")

        btn_activate = tk.Button(
            btn_row, text="✔ Activate Defense", font=("Segoe UI Bold", 9), bg=ACCENT_EMERALD, fg="#0b0f19",
            activebackground="#059669", activeforeground="#ffffff", relief="flat", padx=16, pady=6, cursor="hand2",
            command=self._do_activate
        )
        btn_activate.pack(side="right")

        self.lbl_status = tk.Label(body, text="", font=("Segoe UI", 9), bg=BG_CARD, fg=ACCENT_AMBER)
        self.lbl_status.pack(anchor="w", pady=(10, 0))

    def _copy_machine_code(self):
        copy_clipboard(self.sender.machine_code)
        self.lbl_status.configure(text="✔ Machine ID copied to clipboard!", fg=ACCENT_EMERALD)

    def _browse_key_file(self):
        p = filedialog.askopenfilename(
            parent=self.win,
            title="Select License Key File",
            filetypes=[("License Files", "*.key;*.lic;*.txt"), ("All Files", "*.*")]
        )
        if p and os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                self.txt_key.delete("1.0", tk.END)
                self.txt_key.insert("1.0", content)
                self.lbl_status.configure(text=f"Loaded key from {os.path.basename(p)}", fg=ACCENT_CYAN)
            except Exception as e:
                self.lbl_status.configure(text=f"Error reading file: {e}", fg=ACCENT_RED)

    def _do_activate(self):
        raw_key = self.txt_key.get("1.0", tk.END).strip()
        if not raw_key:
            self.lbl_status.configure(text="Please paste a license key token.", fg=ACCENT_AMBER)
            return

        is_valid, payload, msg = license_utils.parse_license_token(
            raw_key, target_machine=self.sender.machine_code, expected_app=APP_NAME
        )
        if not is_valid or not payload:
            self.lbl_status.configure(text=f"✖ Activation Failed: {msg}", fg=ACCENT_RED)
            return

        # Save license key
        if not license_utils.save_license_key(raw_key, app_name=APP_NAME):
            self.lbl_status.configure(text="Failed saving license to AppData.", fg=ACCENT_RED)
            return

        self.sender.refresh_license()
        self.sender.trigger_instant_pulse()
        messagebox.showinfo("Activation Successful", f"Defender Activated Successfully!\n\nClient: {payload.get('client')}\nType: {payload.get('license_type')}\nExpires: {payload.get('expires_at')}", parent=self.win)
        if self.on_activated:
            self.on_activated()
        self.win.destroy()


class DefenderGUIApp:
    """Main Cyberpunk Dark Tkinter GUI for DefenXis."""

    def __init__(self, root: tk.Tk, daemon_sender: DefenderBeaconSender, start_minimized: bool = False):
        self.root = root
        self.sender = daemon_sender
        self.start_minimized = start_minimized

        self.root.title("DefenXis — Anti-Throttling Sentinel")
        self.root.geometry("640x595")
        self.root.configure(bg=BG_MAIN)
        self.root.minsize(600, 560)

        # Set Window Icon if present (support Windows native .ico and Tkinter iconphoto)
        ico_path = get_asset_path("icon.ico")
        png_path = get_asset_path("icon.png")
        if os.path.exists(ico_path):
            try:
                self.root.iconbitmap(default=ico_path)
            except Exception:
                try:
                    self.root.iconbitmap(ico_path)
                except Exception as e:
                    log.debug(f"Failed setting iconbitmap: {e}")
        if os.path.exists(png_path):
            try:
                self._app_icon_img = ImageTk.PhotoImage(Image.open(png_path))
                self.root.iconphoto(True, self._app_icon_img)
            except Exception as e:
                log.debug(f"Failed setting iconphoto: {e}")

        # Load Header and Hero Logo Images
        self.photo_hdr = None
        hdr_p = get_asset_path("logo_header_masked.png")
        if os.path.exists(hdr_p):
            try:
                self.photo_hdr = ImageTk.PhotoImage(Image.open(hdr_p))
            except Exception as e:
                log.debug(f"Failed loading header logo: {e}")

        self.photo_hero = None
        hero_p = get_asset_path("logo_hero_masked.png")
        if os.path.exists(hero_p):
            try:
                self.photo_hero = ImageTk.PhotoImage(Image.open(hero_p))
            except Exception as e:
                log.debug(f"Failed loading hero logo: {e}")

        self.pulse_phase = 0.0
        self.radar_angle = 0.0
        self.tray_icon = None
        self._speed_testing = False

        self._build_interface()

        # Connect sender update callback
        self.sender.on_status_change = self._on_telemetry_tick

        # Start periodic GUI updater timer (60ms for smooth 16+ FPS cyber radar & WiFi waves)
        self._gui_tick()

        if self.start_minimized:
            self.root.after(200, self.root.iconify)

    def _build_interface(self):
        # 1. Full-Width Live WiFi Signal & Cyber Sentinel Banner
        banner_frame = tk.Frame(self.root, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        banner_frame.pack(fill="x", padx=20, pady=(16, 10))

        self.canvas_banner = tk.Canvas(banner_frame, width=596, height=138, bg=BG_CARD, highlightthickness=0)
        self.canvas_banner.pack(fill="x", expand=True)

        # 2. Live Telemetry & Network Details Card
        telemetry_card = tk.Frame(self.root, bg=BG_CARD, padx=20, pady=12, highlightbackground=BORDER, highlightthickness=1)
        telemetry_card.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        lbl_sec1 = tk.Label(telemetry_card, text="NETWORK & IDENTITY TELEMETRY", font=("Segoe UI Bold", 9), bg=BG_CARD, fg=ACCENT_CYAN)
        lbl_sec1.pack(anchor="w", pady=(0, 6))

        # Grid of fields
        grid_frame = tk.Frame(telemetry_card, bg=BG_CARD)
        grid_frame.pack(fill="x")
        grid_frame.columnconfigure(1, weight=1)

        fields = [
            ("Device Hostname:", "lbl_val_hostname", "-"),
            ("Protected Local IP:", "lbl_val_ip", "-"),
            ("Active MAC Address:", "lbl_val_mac", "-"),
            ("Default Gateway:", "lbl_val_gw", "-"),
            ("Beacons Broadcasted:", "lbl_val_beacons", "0"),
            ("Last Signal Transmitted:", "lbl_val_last_seen", "Just now"),
        ]

        self.val_labels = {}
        for row_idx, (label_text, var_name, default_val) in enumerate(fields):
            lbl_k = tk.Label(grid_frame, text=label_text, font=("Segoe UI Semibold", 9), bg=BG_CARD, fg=FG_MUTED)
            lbl_k.grid(row=row_idx, column=0, sticky="w", pady=2)

            lbl_v = tk.Label(grid_frame, text=default_val, font=("JetBrains Mono", 9), bg=BG_CARD, fg=FG_TITLE)
            lbl_v.grid(row=row_idx, column=1, sticky="w", padx=(12, 0), pady=2)
            self.val_labels[var_name] = lbl_v

        # 3. WiFi Speed Test Card (Fast.com Integration)
        speed_card = tk.Frame(self.root, bg=BG_CARD, padx=20, pady=12, highlightbackground=BORDER, highlightthickness=1)
        speed_card.pack(fill="x", padx=20, pady=(0, 10))

        speed_hdr = tk.Frame(speed_card, bg=BG_CARD)
        speed_hdr.pack(fill="x", pady=(0, 6))

        lbl_speed_title = tk.Label(speed_hdr, text="⚡ WIFI SPEED TEST (POWERED BY FAST.COM)", font=("Segoe UI Bold", 9), bg=BG_CARD, fg=ACCENT_CYAN)
        lbl_speed_title.pack(side="left")

        lbl_fast_badge = tk.Label(speed_hdr, text="NETFLIX CDN", font=("Segoe UI Bold", 7), bg="#1e293b", fg=FG_MUTED, padx=6, pady=2)
        lbl_fast_badge.pack(side="right")

        speed_body = tk.Frame(speed_card, bg=BG_CARD)
        speed_body.pack(fill="x")

        # Left: Big digital speed meter readout
        speed_left = tk.Frame(speed_body, bg=BG_CARD)
        speed_left.pack(side="left", fill="both", expand=True)

        self.lbl_speed_val = tk.Label(speed_left, text="-- Mbps", font=("JetBrains Mono Bold", 17), bg=BG_CARD, fg=FG_TITLE)
        self.lbl_speed_val.pack(anchor="w")

        self.lbl_speed_status = tk.Label(speed_left, text="Ready to test network download throughput", font=("Segoe UI", 8), bg=BG_CARD, fg=FG_MUTED)
        self.lbl_speed_status.pack(anchor="w")

        # Right: Speed test action buttons
        speed_actions = tk.Frame(speed_body, bg=BG_CARD)
        speed_actions.pack(side="right")

        self.btn_speed_test = tk.Button(
            speed_actions, text="⚡ Test Speed", font=("Segoe UI Bold", 9), bg=ACCENT_CYAN, fg="#0b0f19",
            activebackground="#0891b2", activeforeground="#ffffff", relief="flat", padx=14, pady=7, cursor="hand2",
            command=self._start_speed_test
        )
        self.btn_speed_test.pack(side="left", padx=(0, 8))

        btn_open_fast = tk.Button(
            speed_actions, text="🌐 Open Fast.com", font=("Segoe UI", 9), bg=BG_INPUT, fg=FG_BODY,
            activebackground=BG_CARD_LIGHT, activeforeground="#ffffff", relief="flat", padx=12, pady=7, cursor="hand2",
            command=lambda: webbrowser.open("https://fast.com")
        )
        btn_open_fast.pack(side="left")

        # 4. Bottom Action Controls Bar (Active / Deactive Controls)
        actions_bar = tk.Frame(self.root, bg=BG_MAIN, padx=20, pady=6)
        actions_bar.pack(fill="x")

        # Active / Deactive Toggle Button
        self.btn_toggle = tk.Button(
            actions_bar, text="🟢 ACTIVE  (Click to Deactivate)", font=("Segoe UI Bold", 9),
            bg="#065f46", fg="#ffffff", activebackground="#047857", activeforeground="#ffffff",
            relief="flat", padx=18, pady=9, cursor="hand2", command=self._toggle_defense
        )
        self.btn_toggle.pack(side="left", padx=(0, 10))

        btn_pulse = tk.Button(
            actions_bar, text="⚡ Pulse Signal Now", font=("Segoe UI Bold", 9), bg=BG_CARD_LIGHT, fg=FG_TITLE,
            activebackground=ACCENT_CYAN, activeforeground="#0b0f19", relief="flat", padx=16, pady=9, cursor="hand2",
            command=self._trigger_pulse
        )
        btn_pulse.pack(side="left")

    def _toggle_defense(self):
        if self.sender.paused:
            self.sender.resume()
        else:
            self.sender.pause()
        self._update_all_labels()

    def _trigger_pulse(self):
        self.sender.trigger_instant_pulse()
        self._update_all_labels()

    def _start_speed_test(self):
        if self._speed_testing:
            return
        self._speed_testing = True
        self.btn_speed_test.configure(state="disabled", text="Testing...", bg="#374151")
        self.lbl_speed_val.configure(text="Connecting...", fg=ACCENT_CYAN)
        self.lbl_speed_status.configure(text="Connecting to Fast.com Netflix CDN targets...")

        def _worker():
            def _prog(mbps, elapsed):
                self.root.after(0, lambda: self.lbl_speed_val.configure(text=f"{mbps:.1f} Mbps", fg=ACCENT_CYAN))
                self.root.after(0, lambda: self.lbl_speed_status.configure(text=f"Testing download stream... {elapsed:.1f}s"))

            final_mbps, dur = run_fast_speed_test(progress_callback=_prog, duration=4.5)

            def _done():
                self._speed_testing = False
                self.btn_speed_test.configure(state="normal", text="⚡ Test Speed", bg=ACCENT_CYAN)
                if final_mbps > 0:
                    self.lbl_speed_val.configure(text=f"{final_mbps:.1f} Mbps", fg=ACCENT_EMERALD)
                    self.lbl_speed_status.configure(text=f"Fast.com Verified Speed • Completed in {dur}s")
                else:
                    self.lbl_speed_val.configure(text="Error", fg=ACCENT_RED)
                    self.lbl_speed_status.configure(text="Could not reach Fast.com CDN. Check Internet connection.")

            self.root.after(0, _done)

        threading.Thread(target=_worker, name="FastSpeedTestThread", daemon=True).start()

    def _on_telemetry_tick(self):
        # Called from background sender thread
        self.root.after(0, self._update_all_labels)

    def _update_all_labels(self):
        net = self.sender.current_network or get_network_details()

        # Update telemetry labels
        self.val_labels["lbl_val_hostname"].configure(text=net.get("hostname", socket.gethostname()))
        self.val_labels["lbl_val_ip"].configure(text=net.get("primary_ip", "-"), fg=ACCENT_CYAN)

        mac_val = net.get("primary_mac", "-")
        self.val_labels["lbl_val_mac"].configure(text=mac_val)
        self.val_labels["lbl_val_gw"].configure(text=net.get("gateway", "Auto-detected"))
        self.val_labels["lbl_val_beacons"].configure(text=f"{self.sender.beacons_sent:,} beacons")

        if self.sender.last_beacon_ts > 0:
            diff = max(0.0, time.time() - self.sender.last_beacon_ts)
            self.val_labels["lbl_val_last_seen"].configure(text=f"{diff:.1f}s ago")
        else:
            self.val_labels["lbl_val_last_seen"].configure(text="Waiting for first pulse...")

        # Update Active / Deactive button
        if self.sender.paused or not self.sender.is_licensed:
            self.btn_toggle.configure(
                text="🔴 DEACTIVE  (Click to Activate)",
                bg="#991b1b",
                activebackground="#dc2626"
            )
        else:
            self.btn_toggle.configure(
                text="🟢 ACTIVE  (Click to Deactivate)",
                bg="#065f46",
                activebackground="#047857"
            )

    def _gui_tick(self):
        # Update animation phases
        self.pulse_phase = (self.pulse_phase + 0.035) % 1.0
        self.radar_angle = (self.radar_angle + 6.0) % 360.0

        c = self.canvas_banner
        c.delete("all")
        cx, cy = 64, 69
        is_active = (not self.sender.paused) and self.sender.is_licensed

        # Dynamic horizontal position shifted towards right border as requested
        canv_w = c.winfo_width() if c.winfo_width() > 100 else 596
        text_x = max(205, canv_w - 385)

        if not is_active:
            # ─── DEACTIVE STATE (RED / OFFLINE) ───
            # Static indicator rings
            c.create_oval(cx-44, cy-44, cx+44, cy+44, outline="#ef4444", width=2)
            c.create_oval(cx-36, cy-36, cx+36, cy+36, outline="#7f1d1d", width=1)

            # Center Hero Shield Logo
            if self.photo_hero:
                c.create_image(cx, cy, image=self.photo_hero)
            else:
                c.create_text(cx, cy, text="🛡", font=("Segoe UI Emoji", 26), fill="#ef4444")

            # Red Deactive badge at bottom-right of shield
            c.create_oval(cx+22, cy+22, cx+38, cy+38, fill=ACCENT_RED, outline="#0b0f19", width=2)
            c.create_text(cx+30, cy+30, text="✖", fill="#ffffff", font=("Segoe UI Bold", 8))

            # 5-Bar WiFi Signal Meter (Offline state)
            for bar_idx in range(5):
                bx = text_x + bar_idx * 7
                bh = 4 + bar_idx * 3
                b_color = "#ef4444" if bar_idx == 0 else "#374151"
                c.create_rectangle(bx, 126 - bh, bx + 4, 126, fill=b_color, outline="")
            c.create_text(text_x + 43, 120, text="WIFI SENTINEL: DISCONNECTED", font=("Segoe UI Bold", 8), fill=ACCENT_RED, anchor="w")

            # Status pill badge (Deactive)
            c.create_rectangle(text_x, 62, text_x + 160, 87, fill="#7f1d1d", outline=ACCENT_RED, width=1)
            c.create_text(text_x + 80, 74, text="✖ STATUS: DEACTIVE", font=("Segoe UI Bold", 9), fill="#ffffff")

            # Info text
            c.create_text(text_x, 98, text="Beacon broadcasts paused • Local network controllers may shape this PC", font=("Segoe UI", 8), fill="#fca5a5", anchor="w")

        else:
            # ─── ACTIVE STATE (LIVE RADIATING WIFI SIGNAL WAVES) ───
            # 1. Parabolic expanding WiFi signal arcs radiating outward across the banner
            for i in range(4):
                phase_off = (self.pulse_phase + i * 0.25) % 1.0
                wave_r = 38 + phase_off * 75
                # Fading color progression
                wave_col = "#10b981" if i % 2 == 0 else "#06b6d4"
                c.create_arc(cx - wave_r, cy - wave_r, cx + wave_r, cy + wave_r, start=-45, extent=90, outline=wave_col, width=2, style="arc")

            # Leftward subtle antenna back-scatter arcs
            for i in range(2):
                wave_r = 36 + ((self.pulse_phase + i * 0.5) % 1.0) * 26
                c.create_arc(cx - wave_r, cy - wave_r, cx + wave_r, cy + wave_r, start=140, extent=80, outline="#059669", width=1, style="arc")

            # 2. Dual rotating cyber radar arcs around shield
            a1 = self.radar_angle
            c.create_arc(cx-44, cy-44, cx+44, cy+44, start=a1, extent=75, outline=ACCENT_CYAN, width=2, style="arc")
            c.create_arc(cx-44, cy-44, cx+44, cy+44, start=(a1 + 180) % 360, extent=60, outline=ACCENT_EMERALD, width=2, style="arc")

            # 3. Inner neon cyan boundary ring
            c.create_oval(cx-36, cy-36, cx+36, cy+36, outline="#06b6d4", width=1)

            # 4. Orbiting satellite scanner blip
            rad = math.radians(a1)
            bx = cx + 44 * math.cos(rad)
            by = cy + 44 * math.sin(rad)
            c.create_oval(bx-3, by-3, bx+3, by+3, fill=ACCENT_CYAN, outline="")

            # 5. Centered Futuristic Cyber Shield Logo
            if self.photo_hero:
                c.create_image(cx, cy, image=self.photo_hero)
            else:
                c.create_text(cx, cy, text="🛡", font=("Segoe UI Emoji", 26), fill=ACCENT_EMERALD)

            # 6. Active green badge at bottom-right of shield
            c.create_oval(cx+22, cy+22, cx+38, cy+38, fill=ACCENT_EMERALD, outline="#0b0f19", width=2)
            c.create_text(cx+30, cy+30, text="●", fill="#ffffff", font=("Segoe UI", 7))

            # 7. 5-Bar WiFi Signal Meter (Full Active green bars)
            for bar_idx in range(5):
                bx = text_x + bar_idx * 7
                bh = 4 + bar_idx * 3
                c.create_rectangle(bx, 126 - bh, bx + 4, 126, fill=ACCENT_EMERALD, outline="")
            c.create_text(text_x + 43, 120, text="LIVE WIFI SENTINEL LINK: 100% (STABLE)", font=("Segoe UI Bold", 8), fill=ACCENT_EMERALD, anchor="w")

            # Status pill badge (Active)
            c.create_rectangle(text_x, 62, text_x + 160, 87, fill="#064e3b", outline=ACCENT_EMERALD, width=1)
            c.create_text(text_x + 80, 74, text="● STATUS: ACTIVE", font=("Segoe UI Bold", 9), fill="#ffffff")

            # Info text
            c.create_text(text_x, 98, text="Broadcasting Authenticated Beacons • UDP Port 58291 • Whitelisted", font=("Segoe UI", 8), fill="#cbd5e1", anchor="w")

        # Top Header Brand Typography on Canvas (Shifted to text_x, ends near right border)
        c.create_text(text_x, 23, text="DEFENXIS SENTINEL", font=("Segoe UI Bold", 15), fill=FG_TITLE, anchor="w")
        c.create_text(text_x, 43, text="Autonomous Network Identity Beacon • Anti-Throttling Guard", font=("Segoe UI", 8), fill=FG_MUTED, anchor="w")

        # 60ms smooth animation tick (~16 FPS)
        self.root.after(60, self._gui_tick)




# ═══════════════════════════════════════════════════════════════════════════════
# Entry Point & CLI Support
# ═══════════════════════════════════════════════════════════════════════════════

def hide_console():
    """Hides the attached Win32 console window immediately."""
    if sys.platform == "win32":
        try:
            import ctypes
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE = 0
        except Exception:
            pass


def show_console():
    """Restores/shows the attached Win32 console window."""
    if sys.platform == "win32":
        try:
            import ctypes
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 5)  # SW_SHOW = 5
                ctypes.windll.user32.SetForegroundWindow(hwnd)
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(
        description="DefenXis — Anti-Throttling Companion & Identity Sentinel",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--cli", "--headless", action="store_true", help="Run as headless background daemon in terminal")
    parser.add_argument("--minimized", action="store_true", help="Start minimized to taskbar/tray")
    parser.add_argument("--activate", metavar="KEY", help="Activate license key via command-line")
    parser.add_argument("--status", action="store_true", help="Print defender status, network, and license info")
    args = parser.parse_args()

    # Hide console window immediately if running in GUI mode
    if not (args.cli or args.status or args.activate):
        hide_console()

    # Enable UTF-8 for console output if possible
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    # CLI License Activation
    if args.activate:
        key_input = args.activate.strip()
        mc = license_utils.get_machine_code()
        is_valid, payload, msg = license_utils.parse_license_token(key_input, target_machine=mc, expected_app=APP_NAME)
        if is_valid and payload:
            license_utils.save_license_key(key_input, app_name=APP_NAME)
            print("[OK] Defender activated successfully!")
            print(f"     Client : {payload.get('client')}")
            print(f"     Type   : {payload.get('license_type')}")
            print(f"     Expires: {payload.get('expires_at')}")
            sys.exit(0)
        else:
            print(f"[ERROR] Activation failed: {msg}")
            sys.exit(1)

    # Status Inspection
    if args.status:
        mc = license_utils.get_machine_code()
        is_valid, payload, msg, _, _ = license_utils.check_license_status(app_name=APP_NAME)
        net = get_network_details()
        print("=" * 60)
        print("            DEFENXIS — SYSTEM STATUS")
        print("=" * 60)
        print(f" Machine ID    : {mc}")
        print(f" License Status: {'[LICENSED OK]' if is_valid else '[UNLICENSED]'} ({msg})")
        if is_valid and payload:
            print(f" Client Name   : {payload.get('client')}")
            print(f" License Type  : {payload.get('license_type')}")
            print(f" Expires At    : {payload.get('expires_at')}")
        print("-" * 60)
        print(f" Hostname      : {net.get('hostname')}")
        print(f" Primary IP    : {net.get('primary_ip')}")
        print(f" Primary MAC   : {net.get('primary_mac')}")
        print(f" Gateway       : {net.get('gateway')}")
        print(f" All Local IPs : {net.get('all_ips')}")
        print(f" Broadcast Dst : {net.get('broadcast_targets')}")
        print("=" * 60)
        sys.exit(0)

    # 1. Enforce Administrator Privileges for priority execution and network access
    elevate_to_admin()

    # 2. Elevate Process Scheduling Priority to HIGH_PRIORITY_CLASS
    set_high_priority()

    # Start Beacon Sender Core
    sender = DefenderBeaconSender()
    sender.start()

    # Headless / CLI Daemon Mode
    if args.cli:
        print("=" * 65)
        print("        [DEFENXIS] SENTINEL RUNNING")
        print("=" * 65)
        print(f" Machine Code  : {sender.machine_code}")
        print(f" License Status: {sender.license_message}")
        print(f" Privileges    : {'[ADMINISTRATOR]' if is_admin() else '[STANDARD]'}")
        print(f" Priority      : HIGH_PRIORITY_CLASS (Real-time beacon scheduling)")
        if sender.is_licensed:
            print(f" Licensed To   : {sender.license_payload.get('client')}")
        print(f" Broadcasting  : UDP Port {DEFENDER_BEACON_PORT} (Every 1.5s, 2-packet burst)")
        print(" Press Ctrl+C to terminate sentinel.")
        print("-" * 65)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping DefenXis sentinel...")
            sender.stop()
            sys.exit(0)

    # Desktop GUI Mode
    try:
        setup_windows_app_id()
        root = tk.Tk()
        app = DefenderGUIApp(root, sender, start_minimized=args.minimized)
        root.mainloop()
    except Exception as e:
        import traceback
        err_msg = f"DefenXis encountered a startup error:\n\n{e}\n\n{traceback.format_exc()}"
        try:
            messagebox.showerror("DefenXis Error", err_msg)
        except Exception:
            print(err_msg, file=sys.stderr)
    finally:
        sender.stop()


if __name__ == "__main__":
    main()
