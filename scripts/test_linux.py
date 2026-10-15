#!/usr/bin/env python3
"""Check the Linux package and open its GUI under Xvfb (no installed WARP needed)."""

import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tarfile
import tempfile
import time


def run(*args):
    return subprocess.check_output(list(map(str, args)), text=True, stderr=subprocess.STDOUT, timeout=15)


def main():
    with tempfile.TemporaryDirectory() as directory:
        exe = Path(directory) / "warp-sni-patcher"
        with tarfile.open(sys.argv[1]) as archive:
            if archive.getnames() != [exe.name] or not archive.getmember(exe.name).isfile():
                raise RuntimeError("The Linux package must contain one executable")
            archive.extractall(directory, filter="data")
        needed = re.findall(r"Shared library: \[(.*?)\]", run("readelf", "-d", exe))
        if any(name.startswith(("libfltk", "libpng", "libjpeg")) for name in needed):
            raise RuntimeError("FLTK must be bundled and the icon must not require image libraries")
        if "not found" in run("ldd", exe):
            raise RuntimeError("A required system library is missing")
        if "inspect|patch|restore" not in run(exe, "--help") or "FLTK project" not in run(exe, "--licenses"):
            raise RuntimeError("The packaged CLI or FLTK notice is missing")
        print("Shared system libraries: " + ", ".join(needed), flush=True)
        app = subprocess.Popen([str(exe), "--gui", "--target", str(Path(directory) / "uninstalled-warp")],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if app.poll() is not None:
                    raise RuntimeError("GUI exited before opening: " + app.communicate()[1])
                window = subprocess.run(["xdotool", "search", "--onlyvisible", "--class", "^warp-sni-patcher$"],
                                        capture_output=True, text=True, timeout=5)
                if window.returncode == 0:
                    # Escape closes the window before a separate key-up can reach it.
                    run("xdotool", "keydown", "--window", window.stdout.splitlines()[0], "Escape")
                    _, errors = app.communicate(timeout=10)
                    if app.returncode != 0:
                        raise RuntimeError("GUI did not close cleanly: " + errors)
                    print("PASS: bundled FLTK, packaged CLI, GUI startup and close", flush=True)
                    return
                time.sleep(0.1)
            raise RuntimeError("GUI window did not appear")
        finally:
            if app.poll() is None:
                os.killpg(app.pid, signal.SIGKILL)
                app.communicate()


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.exit(error.output)
