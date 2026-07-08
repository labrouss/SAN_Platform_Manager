"""
path_setup.py - Must be imported before any local module.
Ensures the app directory is always first on sys.path,
regardless of working directory or frozen state.
"""
import sys
import os
from pathlib import Path

# The directory containing THIS file is the app root
APP_ROOT = Path(__file__).resolve().parent

# When frozen by PyInstaller, _MEIPASS contains extracted files
if hasattr(sys, '_MEIPASS'):
    _roots = [Path(sys._MEIPASS), APP_ROOT]
else:
    _roots = [APP_ROOT]

for root in _roots:
    root_str = str(root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)

# Also set PYTHONPATH env var so subprocesses inherit it
os.environ['PYTHONPATH'] = os.pathsep.join(
    [str(r) for r in _roots] + 
    [os.environ.get('PYTHONPATH', '')]
).strip(os.pathsep)
