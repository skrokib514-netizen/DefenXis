"""
Developer License Generator for Throttwin Bandwidth Limiter.
Run this tool on your developer machine to issue cryptographically signed (RSA-2048),
Hardware-ID locked, time-based license keys for clients.
"""

import os
import sys
import json
import base64
import argparse
import subprocess
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import license_utils

ROOT_DIR = Path(__file__).resolve().parent
PRIVATE_KEY_FILE = ROOT_DIR / "developer_private_key.pem"


def sync_public_key_to_codebase(private_key) -> bool:
    """Ensures _PUBLIC_KEY_PEM in license_utils.py matches the active private key."""
    import re
    derived_pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii").strip()

    target_files = [
        ROOT_DIR / "license_utils.py",
    ]

    updated = False
    pattern = r'_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----"""'
    replacement = f'_PUBLIC_KEY_PEM = b"""{derived_pub_pem}"""'

    for target in target_files:
        if target.exists():
            try:
                content = target.read_text(encoding="utf-8")
                new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)
                if new_content != content:
                    target.write_text(new_content, encoding="utf-8")
                    updated = True
            except Exception as e:
                print(f"[WARN] Failed updating public key in {target.name}: {e}")

    if updated or license_utils._PUBLIC_KEY_PEM != derived_pub_pem.encode("ascii"):
        license_utils._PUBLIC_KEY_PEM = derived_pub_pem.encode("ascii")
        print("[OK] Synchronized _PUBLIC_KEY_PEM across application modules.")
    return updated


def ensure_private_key():
    """Load or generate the developer RSA private key."""
    if PRIVATE_KEY_FILE.exists():
        with open(PRIVATE_KEY_FILE, "rb") as f:
            pk = serialization.load_pem_private_key(f.read(), password=None)
            sync_public_key_to_codebase(pk)
            return pk

    print("[INFO] Generating new RSA 2048-bit Developer Private Key for Throttwin...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(pem_private)

    print(f"[OK] Private key saved to: {PRIVATE_KEY_FILE.name}")
    print("[IMPORTANT] Keep developer_private_key.pem safe and private. Never distribute it!")
    sync_public_key_to_codebase(private_key)
    return private_key


def generate_license(
    client_name: str,
    machine_id: str,
    days: int = -1,
    hours: int = 0,
    minutes: int = 0,
    expiry_dt: Optional[datetime] = None,
    app_name: str = "Throttwin Suite",
    output_file: Optional[str] = "license.key",
    revocation_cfg: Optional[Dict[str, Any]] = None,
) -> Tuple[str, Dict[str, Any]]:
    """Generate and cryptographically sign a machine-locked time-based license."""
    private_key = ensure_private_key()
    token, payload = license_utils.generate_license_token(
        client_name=client_name,
        machine_code=machine_id,
        days=days,
        hours=hours,
        minutes=minutes,
        expiry_dt=expiry_dt,
        app_name=app_name,
        private_key_obj_or_pem=private_key,
        revocation_cfg=revocation_cfg,
    )

    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(token, encoding="utf-8")
        print(f"\n[OK] License file saved to: {out_path.resolve()}")

    return token, payload



def copy_to_clipboard(text: str) -> bool:
    """Copy text to system clipboard."""
    try:
        if sys.platform == "win32":
            subprocess.run("clip", input=text, text=True, check=True)
            return True
        elif sys.platform == "darwin":
            subprocess.run("pbcopy", input=text.encode("utf-8"), check=True)
            return True
        else:
            subprocess.run(["xclip", "-selection", "clipboard"], input=text.encode("utf-8"), check=True)
            return True
    except Exception:
        return False


def interactive_mode():
    print("=" * 70)
    print("        Throttwin Bandwidth Limiter - Developer License Generator")
    print("=" * 70)

    client_name = input("\nEnter Client Name / Organization: ").strip()
    while not client_name:
        client_name = input("Client Name cannot be empty. Please enter: ").strip()

    local_hwid = license_utils.get_machine_code()
    print(f"\nDetected Local Machine ID: {local_hwid}")
    machine_id = input(f"Enter Client Machine Code (UUID / Hardware Code) [Default: local]: ").strip()
    if not machine_id:
        machine_id = local_hwid

    print("\nSelect Product Scope:")
    print("  [1] Throttwin Suite (All Products — Limiter Engine + Defender Sentinel) [Default]")
    print("  [2] Throttwin Defender (Companion Sentinel Node only)")
    print("  [3] Throttwin (Bandwidth Limiter Engine only)")

    prod_choice = input("\nEnter product scope [1-3] (default: 1): ").strip() or "1"
    if prod_choice == "2":
        app_name = "Throttwin Defender"
    elif prod_choice == "3":
        app_name = "Throttwin"
    else:
        app_name = "Throttwin Suite"

    print("\nSelect Validity Period (Days & Time):")
    print("  [1] 1 Day Trial (24 Hours)")
    print("  [2] 7 Days (1 Week)")
    print("  [3] 14 Days (2 Weeks)")
    print("  [4] 30 Days (1 Month)")
    print("  [5] 90 Days (Quarterly)")
    print("  [6] 365 Days (1 Year)")
    print("  [7] Lifetime (Never expires)")
    print("  [8] Custom Days, Hours & Minutes")
    print("  [9] Specific Expiration Date & Time (YYYY-MM-DD HH:MM)")

    choice = input("\nEnter choice [1-9] (default: 4): ").strip() or "4"

    days = -1
    hours = 0
    minutes = 0
    expiry_dt = None

    if choice == "1":
        days = 1
    elif choice == "2":
        days = 7
    elif choice == "3":
        days = 14
    elif choice == "4":
        days = 30
    elif choice == "5":
        days = 90
    elif choice == "6":
        days = 365
    elif choice == "7":
        days = -1
    elif choice == "8":
        try:
            d_str = input("Enter number of Days (e.g. 15): ").strip() or "0"
            h_str = input("Enter number of Hours (e.g. 12): ").strip() or "0"
            m_str = input("Enter number of Minutes (e.g. 30): ").strip() or "0"
            days = int(d_str)
            hours = int(h_str)
            minutes = int(m_str)
        except ValueError:
            print("[WARN] Invalid input. Defaulting to 30 Days.")
            days = 30
    elif choice == "9":
        dt_str = input("Enter Expiration Date & Time (YYYY-MM-DD HH:MM) [UTC]: ").strip()
        try:
            expiry_dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
        except ValueError:
            try:
                expiry_dt = datetime.strptime(dt_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                print("[WARN] Invalid date format. Defaulting to 30 Days.")
                days = 30
    else:
        days = 30

    sanitized_machine = machine_id.replace("-", "_").replace("{", "").replace("}", "")[:16]
    out_name = f"license_{sanitized_machine}.key"
    token, payload = generate_license(
        client_name=client_name,
        machine_id=machine_id,
        days=days,
        hours=hours,
        minutes=minutes,
        expiry_dt=expiry_dt,
        app_name=app_name,
        output_file=out_name,
    )

    print("\n" + "=" * 70)
    print("               LICENSE GENERATED SUCCESSFULLY")
    print("=" * 70)
    print(f" Application   : {payload.get('app', 'Throttwin')}")
    print(f" Client Name   : {payload['client']}")
    print(f" Machine Code  : {payload['machine_id']}")
    print(f" Issued At     : {payload['issued_at']}")
    print(f" Expires At    : {payload['expires_at']}")
    print(f" License Type  : {payload['license_type']}")
    print("-" * 70)
    print("LICENSE KEY (Send this key or the generated .key file to the client):")
    print("-" * 70)
    print(token)
    print("-" * 70)

    if copy_to_clipboard(token):
        print("\n[COPIED TO CLIPBOARD] The License Key has been copied to your clipboard!")
        print("  You can now simply press Ctrl+V to send it to the client.")

    print(f"[SAVED] Saved to file: {out_name}")
    print("\nInstructions for Client:")
    print("1. Open Throttwin on the client PC.")
    print("2. Paste this License Key into the Activation window and click 'Activate'.")
    print(f"   (Or place the file as 'license.key' in the application directory or {license_utils.get_app_data_path()}).")
    print("=" * 70)
    try:
        input("\nPress Enter to exit...")
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="Generate cryptographically signed machine-locked license for Throttwin & Throttwin Defender.")
    parser.add_argument("--client", help="Client name or organization")
    parser.add_argument("--machine", help="Target PC Hardware Machine Code (UUID)")
    parser.add_argument("--app", default="Throttwin Suite", help="Product scope (Throttwin Suite, Throttwin Defender, Throttwin)")
    parser.add_argument("--days", type=int, default=None, help="Validity duration in days (-1 for Lifetime)")
    parser.add_argument("--hours", type=int, default=0, help="Additional validity hours")
    parser.add_argument("--minutes", type=int, default=0, help="Additional validity minutes")
    parser.add_argument("--expiry", help="Specific expiration date & time ('YYYY-MM-DD HH:MM')")
    parser.add_argument("--lifetime", action="store_true", help="Set lifetime validity (never expires)")
    parser.add_argument("--out", default="license.key", help="Output key file path (default: license.key)")
    parser.add_argument("--cli", action="store_true", help="Run in interactive CLI terminal mode")
    parser.add_argument("--gui", action="store_true", help="Launch the GUI Studio (default when no args provided)")

    args = parser.parse_args()

    if args.client and args.machine:
        expiry_dt = None
        if args.expiry:
            try:
                expiry_dt = datetime.strptime(args.expiry, "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
            except ValueError:
                expiry_dt = datetime.strptime(args.expiry, "%Y-%m-%d").replace(tzinfo=timezone.utc)

        days = -1 if args.lifetime else (args.days if args.days is not None else 30)
        token, payload = generate_license(
            client_name=args.client,
            machine_id=args.machine,
            days=days,
            hours=args.hours,
            minutes=args.minutes,
            expiry_dt=expiry_dt,
            app_name=args.app,
            output_file=args.out,
        )
        print(f"[OK] Generated {payload['license_type']} for '{args.client}' (Product: {payload.get('app')}, Machine: {args.machine})")
        print(f"Expires: {payload['expires_at']}")
        print("\nLicense Key:")
        print(token)
        copy_to_clipboard(token)

    elif args.cli:
        interactive_mode()
    else:
        # Default: Launch GUI Studio
        try:
            from generate_license_gui import run_gui
            run_gui()
        except Exception as e:
            print(f"[WARN] Failed to launch GUI ({e}). Falling back to interactive CLI mode.")
            interactive_mode()


if __name__ == "__main__":
    main()
