# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:\\Users\\Asus\\OneDrive\\Desktop\\New folder\\NEW DEFENDER\\defender.py'],
    pathex=[],
    binaries=[],
    datas=[('icon.ico', '.'), ('icon.png', '.'), ('logo_hero_masked.png', '.'), ('logo_header_masked.png', '.')],
    hiddenimports=['psutil', 'cryptography', 'license_utils', 'integrity_guard', 'auto_activate', 'PIL', 'PIL.Image', 'PIL.ImageTk', 'tkinter', 'tkinter.ttk', 'tkinter.messagebox', 'tkinter.filedialog'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='DefenXis',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
    icon=['C:\\Users\\Asus\\OneDrive\\Desktop\\New folder\\NEW DEFENDER\\icon.ico'],
)
