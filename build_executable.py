#!/usr/bin/env python3
"""Build standalone executables (Windows .exe, macOS .app/binary, Linux binary) via PyInstaller."""

from __future__ import annotations

import argparse
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _ensure_pyinstaller() -> None:
    if importlib.util.find_spec("PyInstaller") is None:
        print(
            "PyInstaller is not installed in the current Python environment.\n"
            f"Install it with:\n  {sys.executable} -m pip install pyinstaller",
            file=sys.stderr,
        )
        raise SystemExit(1)


def _run_pyinstaller(entry: Path, name: str, windowed: bool, onedir: bool) -> None:
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--name",
        name,
        "--paths",
        str(ROOT),
        "--hidden-import",
        "port_scanner.gui_tk",
        "--hidden-import",
        "port_scanner.gui_web",
        "--onedir" if onedir else "--onefile",
        "--windowed" if windowed else "--console",
        str(entry),
    ]
    print(f"[build] Running: {' '.join(cmd)}")
    subprocess.run(cmd, cwd=str(ROOT), check=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compile Async Port Scanner into standalone native executables."
    )
    parser.add_argument(
        "--mode",
        choices=["all", "gui", "cli"],
        default="all",
        help="Which executable(s) to build (default: all).",
    )
    parser.add_argument(
        "--onedir",
        action="store_true",
        help="Build --onedir bundles instead of single-file (--onefile) executables.",
    )
    parser.add_argument(
        "--clean-build",
        action="store_true",
        help="Remove previous build/ and dist/ directories before compiling.",
    )
    args = parser.parse_args()

    _ensure_pyinstaller()

    if args.clean_build:
        for folder in (ROOT / "build", ROOT / "dist"):
            if folder.exists():
                shutil.rmtree(folder)

    if args.mode in ("all", "cli"):
        _run_pyinstaller(
            entry=ROOT / "scanner.py",
            name="port-scanner",
            windowed=False,
            onedir=args.onedir,
        )

    if args.mode in ("all", "gui"):
        _run_pyinstaller(
            entry=ROOT / "gui_main.py",
            name="PortScanner-GUI",
            windowed=True,
            onedir=args.onedir,
        )

    dist_dir = ROOT / "dist"
    print(f"\n[build] Done! Artifacts in {dist_dir}:")
    if dist_dir.exists():
        for item in sorted(dist_dir.iterdir()):
            print(f"  - {item.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
