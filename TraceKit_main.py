"""PyInstaller entry point: builds TraceKit.exe.

Keep this file at the project root and outside the package so the frozen
bootloader finds `tracekit` as a top level package.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tracekit.gui import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
