#!/usr/bin/env python3
"""Build the standalone wifi-scanner executable with PyInstaller.

    python build.py

Output: dist/wifi-scanner.exe (Windows) or dist/wifi-scanner (Linux/macOS).
Extra arguments are forwarded to PyInstaller, e.g. `python build.py --log-level WARN`.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parent


def main(argv: List[str]) -> int:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print(
            "PyInstaller is not installed; run: "
            "python -m pip install -r requirements-build.txt",
            file=sys.stderr,
        )
        return 1
    if not (ROOT / "oui.csv").is_file():
        print(
            "note: oui.csv not found, building without a bundled OUI registry "
            "(the executable still works; vendor names appear after "
            "--update-oui)",
            file=sys.stderr,
        )
    return subprocess.call(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            *argv,
            str(ROOT / "wifi_scanner.spec"),
        ],
        cwd=str(ROOT),
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
