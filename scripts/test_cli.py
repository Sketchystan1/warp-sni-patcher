#!/usr/bin/env python3
"""Minimal cross-platform test suite for WARP SNI Patcher."""

import os
import platform
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def pe_fixture():
    data = bytearray(0xA00)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x22)
    struct.pack_into("<H", data, 0x98, 0x20B)
    struct.pack_into("<Q", data, 0x98 + 24, 0x140000000)
    struct.pack_into(
        "<8sIIIIIIHHI",
        data,
        0x188,
        b".rdata",
        0x800,
        0x1000,
        0x800,
        0x200,
        0,
        0,
        0,
        0,
        0x40000040,
    )

    def put(offset, value):
        data[offset : offset + len(value)] = value

    def va(offset):
        return 0x140001000 + offset - 0x200

    put(0x200, b"zt-masque.cloudflareclient.com\0")
    struct.pack_into("<QQ", data, 0x500, va(0x200), 30)
    endpoints = [
        (0x300, b"api.cloudflareclient.com."),
        (0x380, b"api.devices.cloudflare.com."),
        (0x400, b"api.devices.fed.cloudflare.com."),
    ]
    for offset, hostname in endpoints:
        put(offset, hostname)
        struct.pack_into(
            "<QQQ",
            data,
            offset + 32,
            0xFFFFFFFFFFFFFFFF,
            va(offset),
            len(hostname),
        )
    struct.pack_into(
        "<QQQ", data, 0x580, *(len(host) for _, host in endpoints)
    )
    struct.pack_into(
        "<QQQ", data, 0x598, *(va(offset) for offset, _ in endpoints)
    )
    return bytes(data)


class PatcherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        exe_name = (
            "warp-sni-patcher.exe" if os.name == "nt" else "warp-sni-patcher"
        )
        candidates = [
            Path(".cache/windows/MinSizeRel") / exe_name,
            Path(".cache/native/MinSizeRel") / exe_name,
            Path(".cache/native") / exe_name,
            Path("build") / "MinSizeRel" / exe_name,
            Path("build") / exe_name,
            Path(exe_name),
        ]
        override = os.environ.get("WARP_PATCHER_EXE")
        if override:
            cls.cli = Path(override).resolve()
            if not cls.cli.is_file():
                raise RuntimeError(f"Executable not found: {cls.cli}")
            return
        cls.cli = None
        for c in candidates:
            if c.is_file():
                cls.cli = c.resolve()
                break
        if not cls.cli:
            cls._tmp_dir = tempfile.TemporaryDirectory()
            if os.name == "nt":
                import zipfile
                for zc in sorted(Path("build").glob("warp-sni-patcher*.zip"), reverse=True):
                    if zc.is_file():
                        with zipfile.ZipFile(zc, "r") as z:
                            if exe_name in z.namelist():
                                z.extract(exe_name, cls._tmp_dir.name)
                                cls.cli = Path(cls._tmp_dir.name) / exe_name
                                break
            else:
                import tarfile
                for tc in sorted(Path("build").glob("warp-sni-patcher*.tar*"), reverse=True):
                    if tc.is_file():
                        with tarfile.open(tc, "r") as t:
                            if exe_name in t.getnames():
                                t.extract(exe_name, cls._tmp_dir.name)
                                cls.cli = Path(cls._tmp_dir.name) / exe_name
                                cls.cli.chmod(0o755)
                                break
            if not cls.cli or not cls.cli.is_file():
                cls._tmp_dir.cleanup()
                cls._tmp_dir = None

        if not cls.cli:
            raise unittest.SkipTest(f"Executable {exe_name} or archive not found; run build.bat first.")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "_tmp_dir", None):
            cls._tmp_dir.cleanup()

    def run_cli(self, *args, expected=0):
        cmd = [str(self.cli), *map(str, args)]
        p = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace", timeout=30
        )
        self.assertEqual(
            p.returncode,
            expected,
            f"Command {cmd} failed with exit code {p.returncode}:\n{p.stdout}\n{p.stderr}",
        )
        return p.stdout + p.stderr

    def test_help_and_argument_validation(self):
        out = self.run_cli("--help")
        self.assertIn("inspect|patch|restore", out)

        for bad in [
            ("bad-subcommand",),
            ("patch", "--unknown-opt"),
            ("patch", "--sni"),
            ("patch", "--reg-api"),
            ("restore", "--sni", "example.com"),
            ("inspect", "--sni", "example.com"),
        ]:
            with self.subTest(args=bad):
                self.run_cli(*bad, expected=2)

    def test_malformed_input_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            target = tmpdir / "malformed"
            target.write_bytes(b"\x7fELF" + b"\0" * 20)
            cmd = [str(self.cli), "patch", "--target", str(target)]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(p.returncode, 0)

    def test_invalid_hostname_preserves_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "warp-svc"
            original = pe_fixture()
            target.write_bytes(original)
            for hostname in ("https://example.com", "bad..host", "-bad.com", "has space"):
                with self.subTest(hostname=hostname):
                    self.run_cli("patch", "--target", target, "--sni", hostname, expected=1)
                    self.assertEqual(target.read_bytes(), original)
                    self.assertFalse(Path(str(target) + ".bak").exists())

    def test_restore_missing_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "warp-svc"
            backup = Path(str(target) + ".bak")
            original = pe_fixture()
            backup.write_bytes(original)
            self.run_cli("restore", "--target", target)
            self.assertEqual(target.read_bytes(), original)
            self.assertFalse(backup.exists())

    def test_failed_restore_keeps_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "warp-svc"
            target.mkdir()  # A directory cannot be replaced by the service executable.
            backup = Path(str(target) + ".bak")
            original = pe_fixture()
            backup.write_bytes(original)
            self.run_cli("restore", "--target", target, expected=1)
            self.assertTrue(target.is_dir())
            self.assertEqual(backup.read_bytes(), original)
            self.assertFalse(Path(str(target) + ".tmp").exists())

    @unittest.skipUnless(os.name == "nt", "Windows PE tests")
    def test_pe_inspect_patch_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            target = tmpdir / "warp-svc.exe"
            original = pe_fixture()
            target.write_bytes(original)
            backup = tmpdir / "warp-svc.exe.bak"

            # Inspect
            out = self.run_cli("inspect", "--target", target)
            self.assertIn("PE", out)

            # Patch MASQUE SNI only
            self.run_cli(
                "patch",
                "--target",
                target,
                "--sni",
                "speed.cloudflare.com",
            )
            self.assertTrue(backup.exists())
            self.assertEqual(backup.read_bytes(), original)
            patched = target.read_bytes()
            self.assertIn(b"speed.cloudflare.com", patched)
            self.assertIn(b"api.devices.cloudflare.com.", patched)
            self.assertNotEqual(patched, original)

            # Patch Registration API only
            self.run_cli(
                "patch",
                "--target",
                target,
                "--reg-api",
                "api.devices.cloudflare.com",
            )
            patched2 = target.read_bytes()
            self.assertIn(b"api.devices.cloudflare.com.", patched2)

            # Real restore
            self.run_cli("restore", "--target", target)
            self.assertEqual(target.read_bytes(), original)
            self.assertFalse(backup.exists())

    @unittest.skipUnless(os.name == "nt", "Windows PE tests")
    def test_pe_patch_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            target = tmpdir / "warp-svc.exe"
            original = pe_fixture()
            target.write_bytes(original)

            self.run_cli(
                "patch",
                "--target",
                target,
                "--sni",
                "speed.cloudflare.com",
                "--reg-api",
                "api.devices.cloudflare.com",
            )
            patched = target.read_bytes()
            self.assertIn(b"speed.cloudflare.com", patched)
            self.assertIn(b"api.devices.cloudflare.com.", patched)
            self.assertNotEqual(patched, original)

            self.run_cli("restore", "--target", target)
            self.assertEqual(target.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
