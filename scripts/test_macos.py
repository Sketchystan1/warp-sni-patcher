#!/usr/bin/env python3
"""Install, patch, connect, and restore real WARP on a disposable macOS Actions runner."""

import hashlib
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

from download import Package, download_package

VERSION = "2026.8.2110.0"
SHA256 = "cc654394ed16d3d0e3905eaa32dc2d7d97d1de0d29f455972087b0a6779588e7"
RESOURCES = Path("/Applications/Cloudflare WARP.app/Contents/Resources")
DAEMON = RESOURCES / "CloudflareWARP"
CLI = RESOURCES / "warp-cli"
PATCHER = Path(".cache/native/warp-sni-patcher").resolve()


def run(*args, check=True, timeout=60, show=False):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True,
                            errors="replace", timeout=timeout)
    if show:
        print(result.stdout + result.stderr, flush=True)
    if check and result.returncode:
        raise RuntimeError(f"{Path(str(args[0])).name} {args[1]} failed ({result.returncode}): "
                           + result.stdout + result.stderr)
    return result


def cli(*args, **kwargs):
    return run(CLI, "--accept-tos", *args, **kwargs)


def wait_ready():
    for _ in range(30):
        result = cli("status", check=False, timeout=5)
        if result.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError("Installed WARP daemon did not answer warp-cli")


def connected(phase):
    cli("connect")
    deadline = time.monotonic() + 60
    status = ""
    while time.monotonic() < deadline:
        status = cli("status", check=False, timeout=5).stdout
        if "Connected" in status and "Disconnected" not in status:
            trace = run("curl", "--silent", "--show-error", "--max-time", "10",
                        "https://www.cloudflare.com/cdn-cgi/trace", check=False, timeout=15)
            if "warp=on" in trace.stdout or "warp=plus" in trace.stdout:
                print(f"{phase}: tunnel connected; HTTPS trace confirms WARP routing", flush=True)
                return
        time.sleep(2)
    raise RuntimeError(f"{phase}: tunnel did not carry HTTPS traffic; {status.strip()}")


def registration_diagnostics():
    # Report known error markers only, never registration records, tokens or IPs.
    print("Console user: " + run("stat", "-f", "%Su", "/dev/console").stdout.strip(), flush=True)
    logs = run("sudo", "tail", "-n", "2000",
               "/Library/Application Support/Cloudflare/warp-svc.log", check=False).stdout
    for marker in ("Failed to load Registration", "Error reading reg cache file",
                   "Failed to store active registration to cache", "Failed to open key for mTLS",
                   "Failed to get certificate from identity", "Keychain not found",
                   "unable to determine the last active user", "Local config file missing or corrupted"):
        if marker in logs:
            print("Daemon diagnostic: " + marker, flush=True)


def signature():
    run("codesign", "--verify", "--strict", "--all-architectures", DAEMON)
    return run("codesign", "--display", "--verbose=4", DAEMON).stderr


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if sys.platform != "darwin" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("This destructive integration test requires a disposable macOS Actions runner")
    print(f"Testing WARP {VERSION} on macOS {platform.mac_ver()[0]} {platform.machine()}", flush=True)
    package, _ = download_package(Package("macos", VERSION, "pkg",
        f"https://downloads.cloudflareclient.com/v1/download/macos/version/{VERSION}"), Path(".cache"), False)
    if digest(package) != SHA256:
        raise RuntimeError("Official WARP package checksum mismatch")
    run("sudo", "installer", "-pkg", package, "-target", "/", timeout=180, show=True)
    original = digest(DAEMON)
    backup = Path(str(DAEMON) + ".bak")
    try:
        if "TeamIdentifier=68WVV388M8" not in signature():
            raise RuntimeError("Unexpected original daemon signer")
        wait_ready()
        cli("registration", "new", timeout=90)
        cli("tunnel", "protocol", "set", "MASQUE")
        connected("Original")
        run("sudo", "launchctl", "kickstart", "-k",
            "system/com.cloudflare.1dot1dot1dot1.macos.warp.daemon")
        wait_ready()
        connected("Original after restart")
        cli("disconnect")
        cli("registration", "delete")
        run("sudo", PATCHER, "patch", timeout=120, show=True)
        if digest(backup) != original or digest(DAEMON) == original:
            raise RuntimeError("Patch or original backup is incorrect")
        signed = signature()
        if "Signature=adhoc" not in signed or "TeamIdentifier=not set" not in signed:
            raise RuntimeError("Expected an ad-hoc signature without Cloudflare's signing identity")
        wait_ready()
        cli("registration", "new", timeout=90)
        connected("Patched")
        run("sudo", PATCHER, "restore", timeout=120, show=True)
        if digest(DAEMON) != original or backup.exists():
            raise RuntimeError("Restore did not recover the exact original daemon")
        if "TeamIdentifier=68WVV388M8" not in signature():
            raise RuntimeError("Restore did not recover Cloudflare's signature")
        connected("Restored")
        print("PASS: registration, MASQUE tunnel, ad-hoc signing, and exact signed restore", flush=True)
    except Exception:
        registration_diagnostics()
        raise
    finally:
        cli("disconnect", check=False)
        if backup.exists():
            run("sudo", PATCHER, "restore", timeout=120, show=True, check=False)
        cli("registration", "delete", check=False)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"FAIL: {error}", file=sys.stderr, flush=True)
        sys.exit(1)
