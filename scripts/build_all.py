#!/usr/bin/env python3
"""Build Windows, Linux, and universal macOS packages from Windows + WSL."""

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

from prepare_release import release_entry

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".cache"
OUTPUT = ROOT / "build"
VERSION = release_entry((ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))[0]
CAPSTONE_VERSION = "5.0.7"
CAPSTONE_SHA256 = "6427a724726d161d1e05fb49fff8cd0064f67836c04ffca3c11d6d859e719caa"


def run(*args, **kwargs):
    print("+ " + " ".join(map(str, args)), flush=True)
    return subprocess.run(list(map(str, args)), check=True, cwd=ROOT, **kwargs)


def require(*programs):
    for program in programs:
        if not shutil.which(program):
            raise RuntimeError(f"Required tool not found: {program}")


def cross_tools():
    require("cmake", "ctest", "cpack", "make", "g++", "fltk-config")
    candidates = [os.environ.get("OSXCROSS_BIN"), "/opt/osxcross/bin",
                  str(Path.home() / "osxcross/target/bin"), "/usr/local/osxcross/bin"]
    compiler = shutil.which("o64-clang++")
    if compiler:
        candidates.insert(1, str(Path(compiler).parent))
    for candidate in filter(None, candidates):
        directory = Path(candidate).resolve()
        if all((directory / name).is_file() for name in ("o64-clang++", "oa64-clang++", "lipo")):
            os.environ["PATH"] = str(directory) + os.pathsep + os.environ["PATH"]
            os.environ["OSXCROSS_BIN"] = str(directory)
            return directory
    raise RuntimeError("Install OSXCross with x86_64 and arm64 tools, or set OSXCROSS_BIN to its bin directory.")


def configure(directory, *options, source=ROOT):
    run("cmake", "-S", source, "-B", directory, "-DCMAKE_BUILD_TYPE=MinSizeRel", *options)


def build(directory, jobs, *, test=True, package=True):
    run("cmake", "--build", directory, "--config", "MinSizeRel", "--parallel", jobs)
    if test:
        run("ctest", "--test-dir", directory, "-C", "MinSizeRel", "--output-on-failure")
    if package:
        run("cpack", "--config", directory / "CPackConfig.cmake", "-C", "MinSizeRel", "-B", directory)


def capstone_source(cache):
    archive = cache / f"capstone-{CAPSTONE_VERSION}.tar.gz"
    if not archive.exists():
        url = f"https://github.com/capstone-engine/capstone/archive/refs/tags/{CAPSTONE_VERSION}.tar.gz"
        print(f"Downloading Capstone {CAPSTONE_VERSION}...", flush=True)
        partial = archive.with_suffix(".part")
        with urllib.request.urlopen(url, timeout=60) as response, partial.open("wb") as output:
            shutil.copyfileobj(response, output)
        if hashlib.sha256(partial.read_bytes()).hexdigest() != CAPSTONE_SHA256:
            raise RuntimeError("Capstone download checksum mismatch")
        partial.replace(archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != CAPSTONE_SHA256:
        raise RuntimeError(f"Cached Capstone checksum mismatch: {archive}")
    source = cache / f"capstone-{CAPSTONE_VERSION}"
    if not (source / "CMakeLists.txt").is_file():
        with tarfile.open(archive) as bundle:
            bundle.extractall(cache, filter="data")
    return source


def build_macos(jobs):
    """Build the same small universal package on either macOS runner architecture."""
    CACHE.mkdir(exist_ok=True)
    source = capstone_source(CACHE)
    decoder = CACHE / "capstone-universal"
    architectures = "-DCMAKE_OSX_ARCHITECTURES=arm64;x86_64"
    configure(decoder, architectures, "-DCAPSTONE_BUILD_MACOS_THIN=ON",
              "-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF", "-DCAPSTONE_ARM64_SUPPORT=ON",
              "-DCAPSTONE_X86_SUPPORT=ON", "-DCAPSTONE_BUILD_DIET=ON",
              "-DBUILD_SHARED_LIBS=OFF", "-DBUILD_STATIC_LIBS=ON",
              "-DCAPSTONE_BUILD_TESTS=OFF", "-DCAPSTONE_BUILD_CSTOOL=OFF",
              "-DCAPSTONE_BUILD_CSTEST=OFF", "-DCAPSTONE_INSTALL=OFF", source=source)
    run("cmake", "--build", decoder, "--target", "capstone_static", "--parallel", jobs)
    app = CACHE / "native"
    configure(app, architectures, f"-DWARP_CAPSTONE_INCLUDE_DIR={source / 'include'}",
              f"-DWARP_CAPSTONE_LIBRARY={decoder / 'libcapstone.a'}")
    build(app, jobs)
    run("lipo", app / "warp-sni-patcher", "-verify_arch", "x86_64", "arm64")
    run("codesign", "--verify", "--strict", "--all-architectures", app / "warp-sni-patcher")


def build_posix(jobs):
    tools = cross_tools()
    # Keep caches and packaging on a Linux filesystem: drvfs can report all files as 0777.
    workspace = hashlib.sha256(str(ROOT).encode()).hexdigest()[:12]
    cache = Path(os.environ.get("WARP_BUILD_CACHE", Path.home() / ".cache/warp-sni-patcher-builds")) / workspace
    cache.mkdir(parents=True, exist_ok=True)
    linux = cache / "linux"
    configure(linux, "-DWARP_GUI=ON", "-DWARP_ALL_FORMATS=OFF", "-DBUILD_TESTING=ON")
    build(linux, jobs)
    source = capstone_source(cache)
    slices = []
    for arch in ("x86_64", "arm64"):
        toolchain = [f"-DCMAKE_TOOLCHAIN_FILE={ROOT / 'cmake/osxcross.cmake'}",
                     f"-DOSXCROSS_BIN={tools}", f"-DOSXCROSS_ARCH={arch}"]
        decoder = cache / f"capstone-{arch}"
        configure(decoder, *toolchain, "-DCAPSTONE_BUILD_MACOS_THIN=ON",
                  "-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF", "-DCAPSTONE_ARM64_SUPPORT=ON",
                  "-DCAPSTONE_X86_SUPPORT=ON", "-DCAPSTONE_BUILD_DIET=ON",
                  "-DBUILD_SHARED_LIBS=OFF", "-DBUILD_STATIC_LIBS=ON",
                  "-DCAPSTONE_BUILD_TESTS=OFF", "-DCAPSTONE_BUILD_CSTOOL=OFF",
                  "-DCAPSTONE_BUILD_CSTEST=OFF", "-DCAPSTONE_INSTALL=OFF", source=source)
        run("cmake", "--build", decoder, "--target", "capstone_static", "--parallel", jobs)
        app = cache / f"macos-{arch}"
        configure(app, *toolchain, "-DWARP_GUI=ON", "-DWARP_ALL_FORMATS=OFF",
                  "-DBUILD_TESTING=OFF", "-DWARP_CAPSTONE=ON",
                  f"-DWARP_CAPSTONE_INCLUDE_DIR={source / 'include'}",
                  f"-DWARP_CAPSTONE_LIBRARY={decoder / 'libcapstone.a'}")
        build(app, jobs, test=False, package=False)
        run("cmake", "--install", app, "--prefix", app / "package")
        slices.append(app / "package/warp-sni-patcher")
    universal = cache / "warp-sni-patcher"
    run(tools / "lipo", "-create", *slices, "-output", universal)
    run(tools / "lipo", universal, "-verify_arch", "x86_64", "arm64")
    mac_package = cache / f"warp-sni-patcher-v{VERSION}-macos.zip"
    with zipfile.ZipFile(mac_package, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        info = zipfile.ZipInfo("warp-sni-patcher")
        info.create_system = 3
        info.external_attr = 0o100755 << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        bundle.writestr(info, universal.read_bytes())
    staging = CACHE / "packages"
    staging.mkdir(parents=True, exist_ok=True)
    for package in (linux / f"warp-sni-patcher-v{VERSION}-linux.tar.gz", mac_package):
        shutil.copyfile(package, staging / package.name)
    print("macOS x86_64 + arm64 compiled with Capstone; macOS runtime tests require a Mac.", flush=True)


def publish(packages):
    # build/ is reserved for final packages; clean it only after every build succeeds.
    if OUTPUT.resolve() != ROOT / "build":
        raise RuntimeError("build/ must be a directory inside the workspace, not a link")
    OUTPUT.mkdir(exist_ok=True)
    for package in packages:
        shutil.copyfile(package, OUTPUT / package.name)
    names = {package.name for package in packages}
    for path in OUTPUT.iterdir():
        if path.name not in names:
            if path.is_dir() and not path.is_symlink():
                if not path.resolve().is_relative_to(OUTPUT):
                    raise RuntimeError(f"Refusing to remove a directory outside build/: {path}")
                shutil.rmtree(path)
            else:
                path.unlink()


def main():
    if sys.version_info < (3, 12):
        raise RuntimeError("Python 3.12 or newer is required on Windows and in WSL.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=min(4, os.cpu_count() or 1))
    parser.add_argument("--wsl", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--macos", action="store_true", help="Build and test a universal package on macOS")
    parser.add_argument("--check", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-pause", "-nopause", "--batch", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    if args.macos:
        if sys.platform != "darwin":
            parser.error("--macos requires macOS")
        build_macos(args.jobs)
        return
    if args.wsl:
        if os.name == "nt":
            parser.error("--wsl is an internal Linux-only mode")
        if args.check:
            cross_tools()
        else:
            build_posix(args.jobs)
        return
    if os.name != "nt":
        parser.error("Run build.bat on Windows; use CMake directly for native builds.")
    require("cmake", "ctest", "cpack", "wsl.exe")
    posix_root = subprocess.check_output(["wsl.exe", "--exec", "wslpath", "-u", str(ROOT)], text=True, encoding="utf-8").strip()
    command = ["wsl.exe", "--exec", "env"]
    for name in ("OSXCROSS_BIN", "WARP_BUILD_CACHE"):
        if name in os.environ:
            command.append(f"{name}={os.environ[name]}")
    command += ["python3", f"{posix_root}/scripts/build_all.py", "--wsl", "--jobs", str(args.jobs)]
    run(*command, "--check")
    windows = CACHE / "windows"
    configure(windows, "-DWARP_GUI=ON", "-DWARP_ALL_FORMATS=OFF", "-DBUILD_TESTING=ON")
    build(windows, args.jobs)
    run(*command)
    packages = [windows / f"warp-sni-patcher-v{VERSION}-windows.zip",
                CACHE / "packages" / f"warp-sni-patcher-v{VERSION}-linux.tar.gz",
                CACHE / "packages" / f"warp-sni-patcher-v{VERSION}-macos.zip"]
    publish(packages)
    print("\nBuilt all packages:", flush=True)
    for package in packages:
        print(OUTPUT / package.name)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Build failed: {error}", file=sys.stderr)
        sys.exit(1)
