# WARP SNI Patcher

Change Cloudflare WARP's MASQUE SNI and registration API hostname on Windows, Linux, and macOS.

## Use

1. Download and extract your platform's package from [Releases](https://github.com/Sketchystan1/warp-sni-patcher/releases/latest).
2. Open the executable on Windows, or run `./warp-sni-patcher --gui` on Linux/macOS. Linux requires FLTK.
3. Enter hostnames and click **Patch**. Use **Restore** to recover the original file from its `.bak` backup.

Modifying installed WARP requires administrator/root privileges. For CLI options, run with `--help`.

Patching invalidates WARP's signature; updates may undo patches. Releases have no trusted publisher signature.

The macOS patcher does not re-sign the daemon; working tunnel operation is unverified. Bundled dependency notices are available with `--licenses`.

## Build

Run `build.bat` on Windows. Requirements:

- Windows: Visual Studio C++ tools, CMake, Python 3.12+.
- WSL: CMake, Make, g++, Python 3.12+, FLTK development files.
- OSXCross in WSL with an Apple SDK and both Intel/ARM64 toolchains.

After a successful build, `build/` contains only the Windows ZIP, Linux TAR.GZ, and universal macOS ZIP. Other contents are removed. Build caches stay outside `build/`; Python utilities live in [scripts/](scripts/).

## Releases

One GitHub workflow builds and tests all platforms. Push a new [changelog](CHANGELOG.md) version to `master`/`main`, push its matching version tag, or run the workflow manually to publish. Pull requests only build and test.

Each release includes three platform packages, with notes from the changelog. GitHub displays their SHA-256 hashes and adds source archives. The CI macOS package targets the runner's architecture; `build.bat` produces a universal Intel/ARM64 package.
