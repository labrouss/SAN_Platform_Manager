#!/usr/bin/env python3
"""
build.py - Cross-platform build for SAN Management Platform.

Produces a single self-contained executable:
  Linux/macOS:  dist/san-platform
  Windows:      dist/san-platform.exe

Usage:
  python build.py                  # build for current OS
  python build.py --install-deps   # install pip deps first, then build
  python build.py --clean          # wipe dist/ and build/ first
  python build.py --all-checks     # environment check only, no build
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT  = Path(__file__).parent.resolve()
DIST  = ROOT / "dist"
BUILD = ROOT / "build"


# -- Colour helpers -----------------------------------------------------------

def _no_colour():
    if platform.system() == "Windows":
        return not os.environ.get("WT_SESSION") and not os.environ.get("TERM")
    return False

def _c(code, text):
    return text if _no_colour() else "\033[{}m{}\033[0m".format(code, text)

def green(t):  return _c("32", t)
def yellow(t): return _c("33", t)
def red(t):    return _c("31", t)
def bold(t):   return _c("1",  t)


# -- Helpers ------------------------------------------------------------------

def run(cmd, **kwargs):
    display = " ".join(str(c) for c in cmd)
    print("\n  $ {}\n".format(display))
    result = subprocess.run(cmd, **kwargs)
    return result.returncode


def pip(*packages):
    return run([sys.executable, "-m", "pip", "install", "--upgrade"] + list(packages))


def read_file(path):
    return Path(path).read_text(encoding="utf-8")


def write_file(path, content):
    Path(path).write_text(content, encoding="utf-8")


# -- Environment checks -------------------------------------------------------

def check_python():
    v = sys.version_info
    if v < (3, 9):
        print(red("  Python 3.9+ required, found {}.{}".format(v.major, v.minor)))
        sys.exit(1)
    print(green("  Python {}.{}.{}  OK".format(v.major, v.minor, v.micro)))


def check_import(module, pip_name=None):
    try:
        __import__(module)
        print(green("  {}  OK".format(module)))
        return True
    except ImportError:
        print(yellow("  {}  MISSING  (pip install {})".format(module, pip_name or module)))
        return False


def check_environment():
    print(bold("\nEnvironment"))
    print("  OS:     {} {}".format(platform.system(), platform.release()))
    print("  Arch:   {}".format(platform.machine()))
    print("  Python: {}".format(sys.executable))
    check_python()
    ok = all([
        check_import("PyQt5"),
        check_import("PyQt5.QtWebEngineWidgets", "PyQtWebEngine"),
        check_import("PyQt5.QtWebChannel"),
        check_import("PyQt5.QtWebEngineCore", "PyQtWebEngine"),
        check_import("requests"),
        check_import("PyInstaller", "pyinstaller"),
    ])
    return ok


# -- Runtime hook (injected into frozen bundle) --------------------------------

RUNTIME_HOOK = """\
import sys, os
from pathlib import Path
if hasattr(sys, '_MEIPASS'):
    sys.path.insert(0, sys._MEIPASS)
"""


def write_runtime_hook():
    hook = ROOT / "_runtime_hook.py"
    hook.write_text(RUNTIME_HOOK, encoding="utf-8")
    return hook


# -- PyInstaller arguments ----------------------------------------------------

def get_pyinstaller_args(hook_path):
    system = platform.system()
    sep    = ";" if system == "Windows" else ":"
    src    = ROOT / "src"

    args = [
        sys.executable, "-m", "PyInstaller",
        "--clean",
        "--noconfirm",
        "--name=san-platform",
        "--onefile",
        "--windowed",
        "--log-level=WARN",
        "--runtime-hook={}".format(hook_path),
        # Bundle the HTML app and qwebchannel.js
        "--add-data={}{}src".format(src / "app.html",       sep),
        "--add-data={}{}src".format(src / "qwebchannel.js", sep),
        # Required hidden imports
        "--hidden-import=PyQt5",
        "--hidden-import=PyQt5.QtCore",
        "--hidden-import=PyQt5.QtGui",
        "--hidden-import=PyQt5.QtWidgets",
        "--hidden-import=PyQt5.QtWebEngineWidgets",
        "--hidden-import=PyQt5.QtWebEngineCore",
        "--hidden-import=PyQt5.QtWebChannel",
        "--hidden-import=PyQt5.sip",
        "--hidden-import=sqlite3",
        "--hidden-import=json",
        "--hidden-import=hashlib",
        "--hidden-import=threading",
        "--hidden-import=uuid",
        "--hidden-import=pathlib",
        "--hidden-import=datetime",
        "--hidden-import=contextlib",
        "--hidden-import=db",
        "--hidden-import=db.database",
        "--hidden-import=services",
        "--hidden-import=services.mds_client",
        "--hidden-import=services.mds_simulator",
        "--hidden-import=services.client_factory",
        "--hidden-import=workers",
        "--hidden-import=workers.poller",
        "--hidden-import=bridge",
        "--hidden-import=requests",
        "--hidden-import=urllib3",
        "--hidden-import=certifi",
        "--hidden-import=charset_normalizer",
        "--hidden-import=idna",
        # Strip unused heavy packages
        "--exclude-module=matplotlib",
        "--exclude-module=tkinter",
        "--exclude-module=IPython",
        "--exclude-module=PIL",
        "--exclude-module=cv2",
        "--exclude-module=pandas",
        "--exclude-module=sklearn",
        "--exclude-module=numpy",
        "--exclude-module=pyqtgraph",
        "--exclude-module=PyQt5.QtQuick",
        "--exclude-module=PyQt5.QtQuick3D",
        "--exclude-module=PyQt5.QtDesigner",
    ]

    # Platform icons
    ico  = ROOT / "assets" / "icon.ico"
    icns = ROOT / "assets" / "icon.icns"
    if system == "Windows" and ico.exists():
        args.append("--icon={}".format(ico))
    if system == "Darwin" and icns.exists():
        args.append("--icon={}".format(icns))
    if system == "Darwin":
        args.append("--osx-bundle-identifier=com.sanplatform.app")

    args.append(str(ROOT / "main.py"))
    return args


# -- Build --------------------------------------------------------------------

def clean():
    for d in (DIST, BUILD):
        if d.exists():
            shutil.rmtree(d)
            print(green("  Removed {}".format(d)))


def build():
    system = platform.system()
    print(bold("\nBuilding for {} ({})".format(system, platform.machine())))

    hook = write_runtime_hook()
    args = get_pyinstaller_args(hook)

    rc = run(args, cwd=str(ROOT))

    # Clean up temp hook
    hook.unlink(missing_ok=True)

    if rc != 0:
        print(red("\n  Build FAILED (exit code {})".format(rc)))
        return False

    exe_name = "san-platform.exe" if system == "Windows" else "san-platform"
    exe_path = DIST / exe_name
    app_path = DIST / "san-platform.app"

    if exe_path.exists():
        size_mb = exe_path.stat().st_size / 1_000_000
        print(green("\n  Build successful!"))
        print("  Output: {}".format(exe_path))
        print("  Size:   {:.1f} MB".format(size_mb))
    elif app_path.exists():
        print(green("\n  Build successful!"))
        print("  Output: {}".format(app_path))
    else:
        contents = list(DIST.iterdir()) if DIST.exists() else []
        print(yellow("\n  Build finished but no exe found in {}".format(DIST)))
        print("  Contents: {}".format(contents))

    if system == "Darwin":
        print(yellow("\n  macOS tip: if blocked by Gatekeeper, run:"))
        print("    xattr -cr {}".format(exe_path if exe_path.exists() else app_path))
    elif system == "Windows":
        print(yellow("\n  Windows tip: Defender may scan on first run -- this is normal."))
    elif system == "Linux":
        print(yellow("\n  Linux tip: make executable with:"))
        print("    chmod +x {}".format(exe_path))

    return True


# -- Entry point --------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Build SAN Platform as a standalone executable",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--install-deps", action="store_true",
                        help="Install/upgrade pip dependencies before building")
    parser.add_argument("--clean", action="store_true",
                        help="Remove dist/ and build/ before building")
    parser.add_argument("--all-checks", action="store_true",
                        help="Environment check only -- no build")
    args = parser.parse_args()

    print(bold("\n+--------------------------------------+"))
    print(bold("|  SAN Platform -- Build Script        |"))
    print(bold("+--------------------------------------+"))

    if args.all_checks:
        ok = check_environment()
        sys.exit(0 if ok else 1)

    if args.clean:
        print(bold("\nCleaning"))
        clean()

    if args.install_deps:
        print(bold("\nInstalling dependencies"))
        rc = pip("PyQt5", "PyQtWebEngine", "requests", "pyinstaller")
        if rc != 0:
            print(red("  Install failed"))
            sys.exit(1)

    if not check_environment():
        print(red("\n  Missing dependencies. Run with --install-deps to fix."))
        sys.exit(1)

    success = build()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
