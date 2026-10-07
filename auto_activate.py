#!/usr/bin/env python3
"""
Auto-Activator for DefenXis.
Generates and registers an authentic, cryptographically-signed RSA Lifetime License
for the local machine so the Defender is active out of the box.
"""

import sys
import os
import logging
from pathlib import Path

import license_utils

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("auto_activate")

def ensure_lifetime_license(client_name: str = "Defender Sentinel", app_name: str = "Throttwin Defender") -> bool:
    """Checks if current machine has a valid license; if not, generates and saves a signed Lifetime license."""
    mc = license_utils.get_machine_code()
    is_valid, payload, msg, _, current_key = license_utils.check_license_status(app_name=app_name)
    
    if is_valid and payload and not payload.get("is_expired", False):
        log.info(f"Machine {mc} is already activated: {payload.get('license_type')} (Client: {payload.get('client')})")
        return True

    log.info(f"No active lifetime license found for Machine ID: {mc}. Generating signed RSA token...")
    try:
        token, p = license_utils.generate_license_token(
            client_name=client_name,
            machine_code=mc,
            days=-1,  # Lifetime
            app_name=app_name
        )
        
        # Save to both standard app paths
        license_utils.save_license_key(token, app_name=app_name)
        license_utils.save_license_key(token, app_name="Throttwin")
        
        # Also save local license.key file in working directory
        try:
            with open("license.key", "w", encoding="utf-8") as f:
                f.write(token)
        except Exception:
            pass

        log.info(f"Lifetime License successfully generated and saved for {client_name}!")
        return True
    except Exception as e:
        log.error(f"Failed to auto-generate license: {e}")
        return False

if __name__ == "__main__":
    success = ensure_lifetime_license()
    if success:
        print("[SUCCESS] Machine is now fully licensed with Lifetime Protection!")
    else:
        print("[ERROR] Activation failed.")
        sys.exit(1)
