import subprocess
import base64
import json
import sys
import os
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple, Dict, Any
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization

# ═══════════════════════════════════════════════════════════════════════════════
# Developer Asymmetric Public Key (RSA-2048) for digital signature verification.
# Only the developer holds developer_private_key.pem to issue valid licenses.
# ═══════════════════════════════════════════════════════════════════════════════
_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuVl/5ZDwh/d7Bu+TN1v8
u7WHV4uqx0vI8F8rUrDFU62ENfKRRmea84nFL9nxFeajF4kfnXukLsNidXF2anfO
F+G3CwqYbLTe345T06u69x7QZ8+waK/1qY3YdwuzeLzi6Y7YB6C0iqavKOCFUX8o
AsvRM+krpF78k02H1k86CTPB5aj04vc//Qg2rl/i6dbFHeAHvBtDF1G5B+m0hjJf
5mh1SLeJwbvnSwcxesG4aag/NpkvGFMoEszfaAv9kCJvpfhdYOaQY8J61v9B2Rk3
PbkAsLolpAAXqHNuo4Z2FCa3mIB0MpsJUSqeCh88zujOgWBLvhiXZ04ar4LTmGKr
XQIDAQAB
-----END PUBLIC KEY-----"""

APP_NAME = "Throttwin"
ALLOWED_APPS = (
    "Throttwin",
    "Throttwin Defender",
    "Throttwin Suite",
    "Throttwin Pro",
    "Throttwin All-in-One",
    "Throttwin Suite (All Products)",
    "Throttwin Defender (Companion)",
    "Throttwin (Limiter Engine)",
    "Throttwin Sentinel",
)


def normalize_app_name(app_name: Optional[str]) -> str:
    """Normalizes application product names and UI aliases to canonical forms."""
    if not app_name:
        return "Throttwin"
    cleaned = str(app_name).strip()
    cleaned_lower = cleaned.lower()
    if any(k in cleaned_lower for k in ("suite", "all-in-one", "all products")):
        return "Throttwin Suite"
    if any(k in cleaned_lower for k in ("defender", "companion", "sentinel")):
        return "Throttwin Defender"
    if any(k in cleaned_lower for k in ("throttwin", "limiter", "pro", "engine")):
        return "Throttwin"
    return cleaned


def get_machine_code() -> str:
    """Retrieves a unique machine code based on hardware UUID."""
    machine_uuid = None

    # Method 1: Windows Registry MachineGuid (Fast, reliable, standard across Windows 10/11)
    if sys.platform == 'win32':
        try:
            import winreg
            registry_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            )
            value, _ = winreg.QueryValueEx(registry_key, "MachineGuid")
            winreg.CloseKey(registry_key)
            if value and len(value.strip()) > 10:
                machine_uuid = value.strip()
        except Exception:
            pass

        # Method 2: PowerShell Get-CimInstance fallback (modern Windows WMI replacement)
        if not machine_uuid:
            try:
                cmd = 'powershell -NoProfile -Command "(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID"'
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=5).decode().strip()
                if output and len(output) > 20:
                    machine_uuid = output
            except Exception:
                pass

        # Method 3: WMIC (Legacy Windows fallback)
        if not machine_uuid:
            try:
                cmd = "wmic csproduct get uuid"
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=5).decode().strip()
                for line in output.splitlines():
                    line = line.strip()
                    if line and "UUID" not in line and len(line) > 20:
                        machine_uuid = line
                        break
            except Exception:
                pass

    # Method 4: macOS (ioreg)
    if not machine_uuid and sys.platform == 'darwin':
        try:
            cmd = "ioreg -d2 -c IOPlatformExpertDevice | awk -F\\\" '/IOPlatformUUID/{print $(NF-1)}'"
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
            if output:
                machine_uuid = output
        except Exception:
            pass

    # Method 5: Linux (machine-id)
    if not machine_uuid and sys.platform.startswith('linux'):
        try:
            for p in ['/etc/machine-id', '/var/lib/dbus/machine-id']:
                if os.path.exists(p):
                    with open(p, 'r') as f:
                        machine_uuid = f.read().strip()
                    if machine_uuid:
                        break
        except Exception:
            pass

    if not machine_uuid:
        import socket
        machine_uuid = socket.gethostname()

    return machine_uuid.strip()


def get_app_data_path(app_folder: str = "Throttwin") -> str:
    """Returns a writable directory for application data."""
    home = os.path.expanduser("~")

    if sys.platform == 'win32':
        base_path = os.environ.get('APPDATA', os.path.join(home, 'AppData', 'Roaming'))
    elif sys.platform == 'darwin':
        base_path = os.path.join(home, 'Library', 'Application Support')
    else:
        base_path = home
        app_folder = f".{app_folder.lower().replace(' ', '')}"

    full_path = os.path.join(base_path, app_folder)
    if not os.path.exists(full_path):
        os.makedirs(full_path, exist_ok=True)

    return full_path


def get_license_file_path(app_folder: str = "Throttwin") -> str:
    """Returns the primary path where the activated license key is saved."""
    return os.path.join(get_app_data_path(app_folder), "license.key")


# ═══════════════════════════════════════════════════════════════════════════════
# Clock Rollback & Tamper Detection
# ═══════════════════════════════════════════════════════════════════════════════

def _check_and_update_clock_integrity(current_utc_ts: float, app_folder: str = "Throttwin") -> bool:
    """Detect if system clock has been wound backwards into the past to bypass expiration."""
    state_file = os.path.join(get_app_data_path(app_folder), ".lic_state")
    last_seen = 0.0
    try:
        if os.path.exists(state_file):
            with open(state_file, "r", encoding="utf-8") as f:
                raw = f.read().strip()
            if raw:
                last_seen = float(base64.b64decode(raw.encode()).decode())
    except Exception:
        last_seen = 0.0

    # Allow up to 10 minutes drift tolerance for NTP adjustments
    if last_seen > 0 and (current_utc_ts < last_seen - 600):
        return False  # Clock rolled back!

    # Update state file with maximum observed timestamp
    new_ts = max(last_seen, current_utc_ts)
    try:
        with open(state_file, "w", encoding="utf-8") as f:
            f.write(base64.b64encode(str(new_ts).encode()).decode())
    except Exception:
        pass

    return True


# ═══════════════════════════════════════════════════════════════════════════════
# Cryptographic License Verification (RSA-PSS SHA-256 + Time/HWID Validation)
# ═══════════════════════════════════════════════════════════════════════════════

def parse_license_token(
    token: str,
    target_machine: Optional[str] = None,
    expected_app: Optional[str] = None,
    ignore_machine_match: bool = False,
) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """
    Decodes and cryptographically verifies an RSA-signed license token.
    Checks HWID machine binding, application scope, and expiration down to the exact second.
    """
    token = token.strip()
    if not token:
        return False, None, "Empty license key provided."

    if target_machine is None and not ignore_machine_match:
        target_machine = get_machine_code()

    # 1. Base64 unbundle
    try:
        bundle_json = base64.b64decode(token.encode("ascii")).decode("utf-8")
        bundle = json.loads(bundle_json)
        data_bytes = base64.b64decode(bundle["data"].encode("ascii"))
        sig_bytes = base64.b64decode(bundle["sig"].encode("ascii"))
    except Exception as e:
        return False, None, f"Malformed license token: {e}"

    # 2. Asymmetric RSA-PSS signature verification
    try:
        pub_key = serialization.load_pem_public_key(_PUBLIC_KEY_PEM)
        pub_key.verify(
            sig_bytes,
            data_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    except Exception:
        return False, None, "Digital signature verification failed. License is invalid or has been tampered with."

    # 3. Parse JSON payload
    try:
        payload = json.loads(data_bytes.decode("utf-8"))
    except Exception as e:
        return False, None, f"Invalid license payload structure: {e}"

    # 4. Verify application scope
    raw_app = payload.get("app", APP_NAME)
    norm_app = normalize_app_name(raw_app)
    if expected_app:
        norm_expected = normalize_app_name(expected_app)
        # Throttwin Suite / All-in-One grants access to all products (Engine + Defender)
        # Throttwin grants access to Engine and Defender
        # Throttwin Defender grants access to Defender
        if norm_app != norm_expected:
            if norm_app in ("Throttwin Suite", "Throttwin All-in-One"):
                pass  # Suite unlocks everything
            elif norm_expected == "Throttwin Defender" and norm_app in ("Throttwin", "Throttwin Pro"):
                pass  # Core Throttwin license covers Defender sentinel
            else:
                return False, payload, f"License is for '{raw_app}', not {expected_app}."
    else:
        if raw_app not in ALLOWED_APPS and norm_app not in ("Throttwin", "Throttwin Defender", "Throttwin Suite", "Throttwin Pro", "Throttwin All-in-One"):
            return False, payload, f"License is for '{raw_app}', which is not recognized."

    # 5. Verify HWID binding
    if not ignore_machine_match and target_machine and target_machine != "*":
        lic_machine = str(payload.get("machine_id", "")).strip().lower()
        local_machine = str(target_machine).strip().lower()
        if lic_machine != local_machine:
            return False, payload, (
                f"License is locked to a different PC.\n"
                f"Licensed Machine ID: {payload.get('machine_id')}\n"
                f"Current Machine ID : {target_machine}"
            )


    # 6. Verify Expiration Time & Clock Integrity
    now_utc = datetime.now(timezone.utc)
    now_ts = now_utc.timestamp()

    # Clock rollback anti-tampering check
    if not _check_and_update_clock_integrity(now_ts):
        return False, payload, "System clock tampering detected. Please synchronize your system date and time."

    expires_ts = payload.get("expires_timestamp", 0)
    expires_at_str = payload.get("expires_at", "never")

    if expires_at_str == "never" or expires_ts == 0:
        # Lifetime License
        payload["is_lifetime"] = True
        payload["is_expired"] = False
        payload["days_left"] = 99999
        payload["hours_left"] = 999999
        return True, payload, "Lifetime License (Never expires)."

    # Time-based expiration check
    if now_ts > expires_ts:
        payload["is_lifetime"] = False
        payload["is_expired"] = True
        payload["days_left"] = 0
        payload["hours_left"] = 0
        return False, payload, f"License expired on {expires_at_str}. Please renew your subscription."

    # Calculate remaining duration
    rem_seconds = max(0, int(expires_ts - now_ts))
    days_left = rem_seconds // 86400
    hours_left = (rem_seconds % 86400) // 3600
    mins_left = (rem_seconds % 3600) // 60

    payload["is_lifetime"] = False
    payload["is_expired"] = False
    payload["days_left"] = days_left
    payload["hours_left"] = hours_left
    payload["minutes_left"] = mins_left

    # 7. Verify Remote Revocation via Cloudflare DNS over HTTPS (DoH)
    rev_cfg = payload.get("revocation_cfg")
    if rev_cfg and isinstance(rev_cfg, dict) and rev_cfg.get("enabled"):
        is_revoked, rev_msg = check_doh_revocation(payload)
        if is_revoked:
            payload["is_revoked"] = True
            return False, payload, rev_msg

    if days_left > 0:
        time_msg = f"{days_left}d {hours_left}h remaining"
    elif hours_left > 0:
        time_msg = f"{hours_left}h {mins_left}m remaining"
    else:
        time_msg = f"{mins_left}m remaining"

    return True, payload, f"Valid license ({time_msg} - expires {expires_at_str})."


# ═══════════════════════════════════════════════════════════════════════════════
# Cloudflare DNS-over-HTTPS (DoH) Revocation Client
# ═══════════════════════════════════════════════════════════════════════════════

_DOH_CACHE: Dict[str, Tuple[float, bool, str]] = {}  # {lookup_hash: (timestamp, is_revoked, message)}

def check_doh_revocation(payload: Dict[str, Any], timeout: float = 3.0) -> Tuple[bool, str]:
    """
    Queries Cloudflare DoH to verify whether the embedded license identifier has been revoked.
    Includes local in-memory caching to avoid redundant queries on rapid checks.
    """
    rev_cfg = payload.get("revocation_cfg")
    if not rev_cfg or not isinstance(rev_cfg, dict) or not rev_cfg.get("enabled"):
        return False, "Offline license (DoH check skipped)"

    domain = str(rev_cfg.get("domain", "")).strip().strip(".")
    lookup_hash = str(rev_cfg.get("lookup_hash", "")).strip()
    doh_endpoint = str(rev_cfg.get("doh_provider", "https://cloudflare-dns.com/dns-query")).strip()

    if not domain or not lookup_hash:
        return False, "Revocation config incomplete (Skipping DoH)"

    # Check cache (15-minute TTL)
    now = time.time()
    if lookup_hash in _DOH_CACHE:
        cached_ts, cached_rev, cached_msg = _DOH_CACHE[lookup_hash]
        if now - cached_ts < 900:
            return cached_rev, cached_msg

    full_query = f"{lookup_hash}.{domain}"
    url = f"{doh_endpoint}?name={full_query}&type=TXT"
    headers = {"Accept": "application/dns-json"}

    try:
        import requests
        res = requests.get(url, headers=headers, timeout=timeout)
        if res.status_code == 200:
            data = res.json()
            answers = data.get("Answer", [])
            for ans in answers:
                txt_data = str(ans.get("data", "")).strip('"')
                if "REVOKED" in txt_data.upper():
                    msg = f"License has been remotely revoked by administrator: {txt_data}"
                    _DOH_CACHE[lookup_hash] = (now, True, msg)
                    return True, msg
            _DOH_CACHE[lookup_hash] = (now, False, "Active")
            return False, "Active"
        return False, f"DoH returned HTTP {res.status_code}"
    except Exception as e:
        # Offline resilience: allow local valid license during transient network drops
        return False, f"DoH check skipped (offline): {e}"


def validate_license(machine_code: str, input_key: str, app_name: Optional[str] = None) -> bool:
    """
    Validates RSA-2048 time-based license key against machine code and expiration.
    Returns True if valid and active, False if expired or invalid.
    """
    if not input_key or not machine_code:
        return False

    input_key = input_key.strip()
    is_valid, _, _ = parse_license_token(input_key, target_machine=machine_code, expected_app=app_name)
    return is_valid


def get_license_details(machine_code: str, input_key: str, app_name: Optional[str] = None) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """
    Returns full license audit information:
    (is_valid: bool, payload: Optional[dict], status_message: str)
    """
    if not input_key or not machine_code:
        return False, None, "No license provided."

    input_key = input_key.strip()
    return parse_license_token(input_key, target_machine=machine_code, expected_app=app_name)


def get_active_license_key(app_name: str = "Throttwin") -> Optional[str]:
    """Scans standard file locations for an existing activated license key for this machine."""
    candidates = [
        get_license_file_path(app_name),
        get_license_file_path("Throttwin Defender"),
        get_license_file_path("Throttwin"),
        get_license_file_path("ThrottwinDefender"),
        os.path.join(os.path.dirname(sys.executable), "license.key"),
        os.path.join(os.getcwd(), "license.key"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "license.key"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "license.key"),
    ]
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        candidates.append(os.path.join(getattr(sys, "_MEIPASS"), "license.key"))

    seen_paths = set()
    found_keys = []
    current_mc = get_machine_code()

    for p in candidates:
        norm_p = os.path.normpath(p)
        if norm_p in seen_paths:
            continue
        seen_paths.add(norm_p)

        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                if content:
                    valid, _, _ = parse_license_token(content, target_machine=current_mc, expected_app=app_name)
                    if valid:
                        return content
                    found_keys.append(content)
            except Exception:
                pass

    return found_keys[0] if found_keys else None


def save_license_key(key_text: str, app_name: str = "Throttwin") -> bool:
    """Saves the license key strictly to AppData directory for persistence."""
    key_text = key_text.strip()
    if not key_text:
        return False
    try:
        path = get_license_file_path(app_name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(key_text)

        # Cross-activate generic Throttwin AppData if activating Defender or Suite
        try:
            generic_path = get_license_file_path("Throttwin")
            if os.path.normpath(generic_path) != os.path.normpath(path):
                os.makedirs(os.path.dirname(generic_path), exist_ok=True)
                with open(generic_path, "w", encoding="utf-8") as f:
                    f.write(key_text)
        except Exception:
            pass

        return True
    except Exception:
        return False


def check_license_status(app_name: str = "Throttwin") -> Tuple[bool, Optional[Dict[str, Any]], str, str, Optional[str]]:
    """
    Checks the active license status for the current machine.
    Returns: (is_valid, payload, status_message, machine_code, raw_key)
    """
    machine_code = get_machine_code()
    key = get_active_license_key(app_name=app_name)
    if not key:
        return False, None, "No license key found. Activation required.", machine_code, None

    is_valid, payload, msg = get_license_details(machine_code, key, app_name=app_name)
    return is_valid, payload, msg, machine_code, key


# ═══════════════════════════════════════════════════════════════════════════════
# Developer License Key Generation (RSA-PSS SHA-256)
# ═══════════════════════════════════════════════════════════════════════════════

def generate_license_token(
    client_name: str,
    machine_code: str,
    days: int = -1,
    hours: int = 0,
    minutes: int = 0,
    expiry_dt: Optional[datetime] = None,
    app_name: str = "Throttwin",
    private_key_obj_or_pem: Optional[Any] = None,
    revocation_cfg: Optional[Dict[str, Any]] = None,
) -> Tuple[str, Dict[str, Any]]:
    """
    Generates and cryptographically signs an RSA-2048 time-based license token.
    Can be called by CLI, GUI studio, or automation scripts.
    """
    client_name = (client_name or "User").strip()
    machine_code = machine_code.strip()
    app_name = normalize_app_name(app_name or APP_NAME)


    # Load private key
    private_key = None
    if private_key_obj_or_pem is not None:
        if isinstance(private_key_obj_or_pem, bytes):
            private_key = serialization.load_pem_private_key(private_key_obj_or_pem, password=None)
        else:
            private_key = private_key_obj_or_pem
    else:
        # Check current dir or project dir for developer_private_key.pem
        candidates = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "developer_private_key.pem"),
            os.path.join(os.getcwd(), "developer_private_key.pem"),
        ]
        for p in candidates:
            if os.path.exists(p):
                with open(p, "rb") as f:
                    private_key = serialization.load_pem_private_key(f.read(), password=None)
                break

    if private_key is None:
        raise FileNotFoundError(
            "Developer private key ('developer_private_key.pem') not found. "
            "Run generate_license.py to create or load the private signing key."
        )

    now = datetime.now(timezone.utc)
    now_str = now.strftime("%Y-%m-%d %H:%M:%S UTC")

    # Determine expiration
    if days == -1 and not expiry_dt and hours == 0 and minutes == 0:
        expires_at_str = "never"
        expires_ts = 0
        license_type = "Lifetime License"
    elif expiry_dt:
        if expiry_dt.tzinfo is None:
            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
        else:
            expiry_dt = expiry_dt.astimezone(timezone.utc)
        expires_at_str = expiry_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        expires_ts = int(expiry_dt.timestamp())
        total_seconds = max(0, int((expiry_dt - now).total_seconds()))
        calc_days = total_seconds // 86400
        license_type = f"Custom Expiration ({calc_days} Days)"
    else:
        delta = timedelta(days=max(0, days), hours=max(0, hours), minutes=max(0, minutes))
        expiry_dt = now + delta
        expires_at_str = expiry_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        expires_ts = int(expiry_dt.timestamp())

        parts = []
        if days > 0:
            parts.append(f"{days}-Day")
        if hours > 0:
            parts.append(f"{hours}-Hour")
        if minutes > 0:
            parts.append(f"{minutes}-Min")
        duration_desc = " ".join(parts) if parts else "0-Day"
        license_type = f"{duration_desc} Subscription"

    payload = {
        "app": app_name or APP_NAME,
        "client": client_name,
        "machine_id": machine_code,
        "issued_at": now_str,
        "expires_at": expires_at_str,
        "expires_timestamp": expires_ts,
        "license_type": license_type,
    }

    if revocation_cfg and isinstance(revocation_cfg, dict):
        payload["revocation_cfg"] = revocation_cfg

    # Canonical JSON serialization for tamper-proof digital signing
    canonical_json = json.dumps(payload, sort_keys=True).encode("utf-8")

    # RSA-PSS SHA-256 digital signature
    signature = private_key.sign(
        canonical_json,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    bundle = {
        "data": base64.b64encode(canonical_json).decode("ascii"),
        "sig": base64.b64encode(signature).decode("ascii"),
    }

    token = base64.b64encode(json.dumps(bundle).encode("utf-8")).decode("ascii")
    return token, payload
