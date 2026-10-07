# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build description for wifi-scanner.

Build with:  python build.py        (or: python -m PyInstaller wifi_scanner.spec)

Produces a single-file console executable in dist/ (wifi-scanner.exe on
Windows, wifi-scanner elsewhere).  oui.csv is bundled when it sits next to
this spec file, so the executable can resolve vendors offline; the file is
copied next to the executable on first run and refreshed with --update-oui.
"""

from pathlib import Path

ROOT = Path(SPECPATH).resolve()

datas = []
_oui = ROOT / "oui.csv"
if _oui.is_file():
    datas.append((str(_oui), "."))

a = Analysis(
    [str(ROOT / "wifi_scanner.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Modules the script never imports; keeps the executable a few MB smaller.
    excludes=["tkinter", "unittest", "pydoc", "doctest", "sqlite3", "test"],
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
    name="wifi-scanner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # packed executables trip more AV heuristics than they save bytes
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=str(ROOT / "version_info.txt"),
)
