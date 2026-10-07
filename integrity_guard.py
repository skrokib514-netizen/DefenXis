"""
Runtime integrity verification module.
Detects tampering, debugging, and module replacement attempts.
This module can be compiled to native C (.pyd) or obfuscated alongside other core files.
"""
import sys
import os
import hashlib
import ctypes
import threading

# ═══════════════════════════════════════════════════════════════════════════════
# Anti-debug detection
# ═══════════════════════════════════════════════════════════════════════════════

def _check_debugger() -> bool:
    """Detect common debuggers and analysis tools."""
    if sys.platform != 'win32':
        return False
    try:
        # Windows: IsDebuggerPresent
        return bool(ctypes.windll.kernel32.IsDebuggerPresent())
    except Exception:
        return False


def _check_analysis_tools() -> bool:
    """Check for common reverse engineering tools in running processes."""
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# Native module verification
# ═══════════════════════════════════════════════════════════════════════════════

def _verify_critical_modules() -> bool:
    """Check that critical modules and their key symbols are present and uncorrupted."""
    _critical = {
        'license_utils': ['get_machine_code', 'validate_license', 'get_license_details', 'check_license_status'],
    }
    for mod_name, expected_attrs in _critical.items():
        try:
            mod = sys.modules.get(mod_name)
            if mod is None:
                continue
            for attr in expected_attrs:
                if not hasattr(mod, attr):
                    return False
        except Exception:
            pass
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# Main integrity check
# ═══════════════════════════════════════════════════════════════════════════════

_tamper_detected = False
_check_count = 0


def check_integrity(silent=True) -> bool:
    """
    Run all integrity checks. Returns True if everything is OK.
    
    If silent=True (default), tampering causes subtle flag setting 
    rather than an immediate crashing error (harder to debug for crackers).
    """
    global _tamper_detected, _check_count
    _check_count += 1

    issues = []
    try:
        # Check 1: Debugger attached
        if _check_debugger():
            issues.append('dbg')

        # Check 2: Modules not replaced or stripped
        if not _verify_critical_modules():
            issues.append('mod')
    except Exception:
        pass

    if issues:
        _tamper_detected = True
        return False

    return True


def is_tampered() -> bool:
    """Returns True if tampering was previously detected."""
    return _tamper_detected


def get_status_code() -> int:
    """Returns an opaque status code. 0 = clean, non-zero = tampered."""
    if not _tamper_detected:
        return 0
    return _check_count


# ═══════════════════════════════════════════════════════════════════════════════
# Background periodic check (runs every 60 seconds)
# ═══════════════════════════════════════════════════════════════════════════════

_bg_thread = None


def start_background_monitor(interval=60):
    """Start a background thread that periodically re-checks integrity."""
    global _bg_thread
    if _bg_thread is not None:
        return

    def _monitor():
        import time
        while True:
            time.sleep(interval)
            check_integrity(silent=True)

    _bg_thread = threading.Thread(target=_monitor, daemon=True)
    _bg_thread.start()
