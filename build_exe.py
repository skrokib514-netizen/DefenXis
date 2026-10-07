#!/usr/bin/env python3
"""
Build script to compile New Defender into a standalone single-file Windows executable (.exe).
Does not require Python on the target machine.
"""

import sys
import os
import shutil
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent

def build():
    print("=" * 60)
    print("        DEFENXIS — STANDALONE EXE BUILDER")
    print("=" * 60)

    # Check PyInstaller
    try:
        import PyInstaller
        print(f"[OK] PyInstaller detected: {PyInstaller.__version__}")
    except ImportError:
        print("[INFO] Installing PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    # Ensure icon exists
    icon_arg = []
    if (ROOT_DIR / "icon.ico").exists():
        icon_arg = [f"--icon={str(ROOT_DIR / 'icon.ico')}"]

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=DefenXis",
        "--onefile",
        "--windowed",
        "--uac-admin",
        "--clean",
        "--add-data=icon.ico;." if (ROOT_DIR / "icon.ico").exists() else "",
        "--add-data=icon.png;." if (ROOT_DIR / "icon.png").exists() else "",
        "--add-data=logo_hero_masked.png;." if (ROOT_DIR / "logo_hero_masked.png").exists() else "",
        "--add-data=logo_header_masked.png;." if (ROOT_DIR / "logo_header_masked.png").exists() else "",
        "--hidden-import=psutil",
        "--hidden-import=cryptography",
        "--hidden-import=license_utils",
        "--hidden-import=integrity_guard",
        "--hidden-import=auto_activate",
        "--hidden-import=PIL",
        "--hidden-import=PIL.Image",
        "--hidden-import=PIL.ImageTk",
        "--hidden-import=tkinter",
        "--hidden-import=tkinter.ttk",
        "--hidden-import=tkinter.messagebox",
        "--hidden-import=tkinter.filedialog",
        str(ROOT_DIR / "defender.py")
    ]

    # Filter out empty arguments
    cmd = [c for c in cmd if c]
    if icon_arg:
        cmd.extend(icon_arg)

    print("\n[INFO] Compiling executable with PyInstaller...")
    print(f"Command: {' '.join(cmd)}\n")
    
    ret = subprocess.call(cmd, cwd=str(ROOT_DIR))
    if ret == 0:
        dist_exe = ROOT_DIR / "dist" / "DefenXis.exe"
        if dist_exe.exists():
            root_exe = ROOT_DIR / "DefenXis.exe"
            try:
                shutil.copy2(dist_exe, root_exe)
            except Exception:
                pass
            print("\n" + "=" * 60)
            print(f"[SUCCESS] Standalone EXE created successfully!")
            print(f"Location: {root_exe}")
            print(f"Size: {root_exe.stat().st_size / (1024 * 1024):.2f} MB")
            print("=" * 60)
        else:
            print("\n[ERROR] Build finished but DefenXis.exe was not found in dist/")
    else:
        print(f"\n[ERROR] PyInstaller build failed with exit code: {ret}")

if __name__ == "__main__":
    build()
