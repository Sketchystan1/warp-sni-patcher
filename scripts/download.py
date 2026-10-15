#!/usr/bin/env python3
"""Download official Cloudflare WARP packages, without installing or executing them."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import platform
import re
import shlex
import shutil
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional


DOWNLOAD_PAGE = (
    "https://developers.cloudflare.com/cloudflare-one/team-and-resources/"
    "devices/cloudflare-one-client/download/"
)
DOWNLOAD_BASE = "https://downloads.cloudflareclient.com/v1/download"
HEADERS = {
    # Cloudflare's documentation endpoint rejects urllib's default User-Agent.
    "User-Agent": "Mozilla/5.0 (compatible; warp-sni-patcher-downloader/1.0)",
    "Accept-Encoding": "identity",
}
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){3}\Z")
PLATFORM_RE = re.compile(r"[a-z][a-z0-9]*-(?:arm|intel)\Z")
MAGIC = {"deb": b"!<arch>\n", "rpm": b"\xed\xab\xee\xdb", "pkg": b"xar!",
         "msi": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"}


class DownloadError(Exception):
    """An actionable download or selection failure."""


@dataclass
class Catalog:
    linux: dict[str, dict[str, int]] = field(default_factory=dict)
    macos: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class Package:
    platform: str
    version: str
    kind: str
    url: str
    expected_size: Optional[int] = None

    @property
    def filename(self) -> str:
        # Construct names locally: do not trust Content-Disposition as a path.
        if self.platform == "macos":
            return "Cloudflare_WARP_{}.pkg".format(self.version)
        return "cloudflare-warp-{}-{}.{}".format(self.version, self.platform, self.kind)


class DownloadPageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.catalog = Catalog()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attributes = dict(attrs)
        if tag == "warp-download":
            version = attributes.get("data-version", "") or ""
            raw_platforms = attributes.get("data-platforms", "[]") or "[]"
            if not VERSION_RE.fullmatch(version):
                return
            try:
                entries = json.loads(raw_platforms)
            except (TypeError, ValueError) as exc:
                raise DownloadError("The official download page contains invalid platform data.") from exc
            if not isinstance(entries, list):
                raise DownloadError("The official download page has an unexpected platform format.")
            for entry in entries:
                if not isinstance(entry, list) or len(entry) != 2:
                    raise DownloadError("The official download page has an unexpected platform entry.")
                name, size = entry
                if not isinstance(name, str) or not PLATFORM_RE.fullmatch(name):
                    continue
                if type(size) is not int or size <= 0:
                    raise DownloadError("The official download page contains an invalid package size.")
                versions = self.catalog.linux.setdefault(version, {})
                if name in versions and versions[name] != size:
                    raise DownloadError("The official download page lists conflicting package sizes.")
                versions[name] = size
        elif tag == "a":
            href = attributes.get("href") or ""
            match = re.fullmatch(re.escape(DOWNLOAD_BASE) + r"/macos/version/([0-9.]+)/?", href)
            if match and VERSION_RE.fullmatch(match.group(1)):
                self.catalog.macos.add(match.group(1))


def parse_catalog(html: str) -> Catalog:
    parser = DownloadPageParser()
    parser.feed(html)
    parser.close()
    if not parser.catalog.linux and not parser.catalog.macos:
        raise DownloadError("No packages were found on the official download page; its format may have changed.")
    return parser.catalog


def require_https(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise DownloadError("Refusing a download or redirect that does not use HTTPS: {}".format(url))


class HTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        require_https(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_https(url: str):
    require_https(url)
    request = urllib.request.Request(url, headers=HEADERS)
    response = urllib.request.build_opener(HTTPSRedirectHandler()).open(request, timeout=60)
    try:
        require_https(response.geturl())
        if response.status != 200:
            raise DownloadError("The server returned HTTP {} for {}".format(response.status, url))
        if response.headers.get("Content-Encoding", "identity").lower() != "identity":
            raise DownloadError("The server returned an unexpected encoded response.")
    except Exception:
        response.close()
        raise
    return response


def fetch_catalog() -> Catalog:
    with open_https(DOWNLOAD_PAGE) as response:
        limit = 4 * 1024 * 1024
        raw = response.read(limit + 1)
    if len(raw) > limit:
        raise DownloadError("The official download page exceeds the expected size limit.")
    try:
        return parse_catalog(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise DownloadError("The official download page is not valid UTF-8.") from exc


def read_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    """Read os-release as data; never source or evaluate shell expressions."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise DownloadError("Cannot read {}. Select Linux explicitly with --distro (see --list).".format(path)) from exc
    values = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z_][A-Z_0-9]*", name):
            continue
        try:
            fields = shlex.split(value, comments=True, posix=True)
        except ValueError as exc:
            raise DownloadError("Malformed value in {}: {}".format(path, name)) from exc
        if len(fields) > 1:
            raise DownloadError("Malformed value in {}: {}".format(path, name))
        values[name] = fields[0] if fields else ""
    return values


def detect_distro(values: dict[str, str]) -> str:
    distro = values.get("ID", "").lower()
    version = values.get("VERSION_ID", "")
    major = version.split(".")[0]
    if distro == "ubuntu":
        codename = values.get("VERSION_CODENAME") or values.get("UBUNTU_CODENAME")
        codename = codename or {"20.04": "focal", "22.04": "jammy", "24.04": "noble", "26.04": "resolute"}.get(version)
        if codename and re.fullmatch(r"[a-z][a-z0-9]*", codename):
            return codename
    if distro == "debian":
        codename = values.get("VERSION_CODENAME") or {"11": "bullseye", "12": "bookworm", "13": "trixie"}.get(major)
        if codename and re.fullmatch(r"[a-z][a-z0-9]*", codename):
            return codename
    if major.isdigit():
        if distro in ("rhel", "rocky", "almalinux"):
            return "almalinux" + major
        if distro in ("fedora", "centos"):
            return distro + major
    raise DownloadError("Unsupported Linux distribution: {} {}. Use --list and select a compatible --distro explicitly.".format(distro or "unknown", version))


def normalize_arch(arch: str) -> str:
    aliases = {"x86_64": "intel", "amd64": "intel", "x64": "intel", "intel": "intel", "arm64": "arm", "aarch64": "arm", "arm": "arm"}
    try:
        return aliases[arch.lower()]
    except KeyError as exc:
        raise DownloadError("Unsupported architecture: {}. Supported architectures are x86_64 and arm64.".format(arch)) from exc


def sorted_versions(versions) -> list[str]:
    return sorted(versions, key=lambda value: tuple(int(part) for part in value.split(".")), reverse=True)


def select_package(catalog: Catalog, operating_system: str, distro: Optional[str], arch: str, version: str) -> Package:
    available = catalog.macos if operating_system == "macos" else catalog.linux
    if not available:
        raise DownloadError("No {} packages were found on the official download page.".format(operating_system))
    selected = sorted_versions(available)[0] if version == "latest" else version
    if selected not in available:
        raise DownloadError("Version {} is not listed for {}; run --list for available releases.".format(selected, operating_system))
    if operating_system == "macos":
        url = DOWNLOAD_BASE + "/macos/" + ("ga" if version == "latest" else "version/" + selected)
        return Package("macos", selected, "pkg", url)
    package_platform = "{}-{}".format(distro, normalize_arch(arch))
    platforms = catalog.linux[selected]
    if package_platform not in platforms:
        raise DownloadError("Version {} has no {} package. Run --list and choose an available --distro, --arch, or --version.".format(selected, package_platform))
    kind = "rpm" if distro and distro.startswith(("almalinux", "centos", "fedora", "rhel", "rocky")) else "deb"
    return Package(package_platform, selected, kind, DOWNLOAD_BASE + "/" + package_platform + "/version/" + selected, platforms[package_platform])


def publish_file(staged: Path, destination: Path, force: bool) -> None:
    if force:
        os.replace(staged, destination)
    else:
        # A hard link commits the completed file atomically and fails if a file
        # appeared after our initial existence check, avoiding silent overwrite.
        os.link(staged, destination)
        staged.unlink()


def download_package(package: Package, output_dir: Path, force: bool = False) -> tuple[Path, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / package.filename
    checksum_path = output_dir / (package.filename + ".sha256")
    metadata_path = output_dir / (package.filename + ".json")
    targets = (destination, checksum_path, metadata_path)
    for target in targets:
        if os.path.lexists(target):
            if not force:
                raise DownloadError("File already exists: {}. Use --force to replace it.".format(target))
            if not stat.S_ISREG(target.lstat().st_mode):
                raise DownloadError("Refusing to replace a non-regular file or symbolic link: {}".format(target))

    staged_files = []
    published = []
    previous_sidecars = {}
    recovery_files = set()

    def stage() -> tuple[int, Path]:
        descriptor, filename = tempfile.mkstemp(prefix=".warp-download-", suffix=".part", dir=str(output_dir))
        path = Path(filename)
        staged_files.append(path)
        return descriptor, path

    try:
        with open_https(package.url) as response:
            final_url = response.geturl()
            resolved = re.search(r"/version/([0-9.]+)(?:[/?#]|$)", final_url)
            if resolved and resolved.group(1) != package.version:
                raise DownloadError("The latest release changed while downloading; run the command again.")
            header_size = response.headers.get("Content-Length")
            if header_size is not None and not re.fullmatch(r"[0-9]+", header_size):
                raise DownloadError("The server returned an invalid Content-Length.")
            content_length = int(header_size) if header_size is not None else None
            if package.expected_size is not None and content_length is not None and package.expected_size != content_length:
                raise DownloadError("Package size disagrees with the official download page ({} vs {} bytes).".format(content_length, package.expected_size))
            expected = package.expected_size if package.expected_size is not None else content_length
            if expected is None or expected <= 0:
                raise DownloadError("The server did not provide a valid package size; download was not saved.")

            descriptor, package_temp = stage()
            digest = hashlib.sha256()
            count = 0
            prefix = b""
            with os.fdopen(descriptor, "wb") as stream:
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    if len(prefix) < 8:
                        prefix = (prefix + block)[:8]
                    count += len(block)
                    if count > expected:
                        raise DownloadError("Downloaded package is larger than its expected size.")
                    if len(prefix) >= len(MAGIC[package.kind]) and not prefix.startswith(MAGIC[package.kind]):
                        raise DownloadError("The response is not a valid {} package (unexpected file signature).".format(package.kind))
                    stream.write(block)
                    digest.update(block)
                if count != expected:
                    raise DownloadError("Incomplete download: expected {} bytes, received {}.".format(expected, count))
                if not prefix.startswith(MAGIC[package.kind]):
                    raise DownloadError("The downloaded file has an invalid package signature.")
                stream.flush()
                os.fsync(stream.fileno())

        sha256 = digest.hexdigest()
        metadata = {
            "filename": package.filename,
            "platform": package.platform,
            "version": package.version,
            "size": count,
            "sha256": sha256,
            "source_page": DOWNLOAD_PAGE,
            "requested_url": package.url,
            "resolved_url": final_url,
            "downloaded_at": datetime.now(timezone.utc).isoformat(),
        }
        descriptor, checksum_temp = stage()
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write("{}  {}\n".format(sha256, package.filename))
        descriptor, metadata_temp = stage()
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(metadata, stream, indent=2)
            stream.write("\n")
        if force:
            for target in targets:
                if os.path.lexists(target) and not stat.S_ISREG(target.lstat().st_mode):
                    raise DownloadError("Refusing to replace a non-regular file or symbolic link: {}".format(target))
            # Keep sidecar snapshots until the final package rename succeeds.
            # The package is published last, so a failed rename leaves its old
            # contents intact and these snapshots restore its matching records.
            for target in (checksum_path, metadata_path):
                previous_sidecars[target] = None
                if target.exists():
                    descriptor, snapshot = stage()
                    with os.fdopen(descriptor, "wb") as saved, target.open("rb") as original:
                        shutil.copyfileobj(original, saved)
                    shutil.copystat(target, snapshot, follow_symlinks=False)
                    previous_sidecars[target] = snapshot
        # Publish the package last, once both records are ready.
        for staged, target in ((checksum_temp, checksum_path), (metadata_temp, metadata_path), (package_temp, destination)):
            publish_file(staged, target, force)
            published.append(target)
        return destination, sha256
    except BaseException as failure:
        recovery_errors = []
        for path in reversed(published):
            snapshot = previous_sidecars.get(path)
            try:
                if force and snapshot is not None:
                    os.replace(snapshot, path)
                else:
                    path.unlink(missing_ok=True)
            except OSError as recovery:
                if snapshot is not None:
                    recovery_files.add(snapshot)
                recovery_errors.append("{} (saved copy: {}): {}".format(path, snapshot, recovery))
        if recovery_errors:
            raise DownloadError("Download failed; could not restore metadata: " + "; ".join(recovery_errors)) from failure
        raise
    finally:
        for path in staged_files:
            if path not in recovery_files:
                path.unlink(missing_ok=True)


def print_catalog(catalog: Catalog, operating_system: Optional[str], distro: Optional[str], arch: Optional[str], version: str) -> None:
    rows = []
    selected_arch = normalize_arch(arch) if arch else None
    if operating_system in (None, "linux"):
        for release in sorted_versions(catalog.linux):
            if version != "latest" and release != version:
                continue
            for name, size in sorted(catalog.linux[release].items()):
                distribution, cpu = name.rsplit("-", 1)
                if distro and distro != distribution:
                    continue
                if selected_arch and selected_arch != cpu:
                    continue
                rows.append("linux  {:16} {:22} {:>10} bytes".format(release, name, size))
    if operating_system in (None, "macos") and not distro:
        for release in sorted_versions(catalog.macos):
            if version == "latest" or release == version:
                rows.append("macos  {:16} macos (Intel / Apple silicon)".format(release))
    if not rows:
        raise DownloadError("No official packages match these filters; try --list without filters.")
    print("\n".join(rows))


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--os", choices=("linux", "macos", "windows"), help="target OS (default: this computer)")
    parser.add_argument("--distro", help="Linux package distribution, e.g. noble, bookworm, almalinux9, fedora44")
    parser.add_argument("--arch", help="x86_64 or arm64 (default: this computer; macOS package supports both)")
    parser.add_argument("--version", default="latest", help="official release version (default: latest)")
    parser.add_argument("--output-dir", type=Path, default=Path("downloads"), help="download directory (default: downloads)")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--list", action="store_true", help="list available official versions/platforms, optionally filtered by OS/distro/architecture/version")
    actions.add_argument("--print-url", action="store_true", help="print the selected official URL without downloading")
    parser.add_argument("--force", action="store_true", help="replace an existing package and its checksum/metadata files")
    args = parser.parse_args(argv)
    try:
        if args.version != "latest" and not VERSION_RE.fullmatch(args.version):
            raise DownloadError("Use --version latest or a four-part version such as 2026.8.2110.0.")
        if args.distro and not re.fullmatch(r"[a-z][a-z0-9]*", args.distro):
            raise DownloadError("Invalid --distro; use a platform name from --list without its -arm/-intel suffix.")
        if args.os in ("macos", "windows") and args.distro:
            raise DownloadError("--distro applies only to Linux packages.")
        if args.arch:
            normalize_arch(args.arch)
        operating_system = args.os or {"Linux": "linux", "Darwin": "macos", "Windows": "windows"}.get(platform.system())
        if not operating_system:
            raise DownloadError("Cannot detect a supported OS. Select --os linux, macos, or windows explicitly.")

        if operating_system == "windows":
            win_url = "https://1111-releases.cloudflareclient.com/windows/Cloudflare_WARP_Release-x64.msi"
            package = Package("windows-x64", "latest", "msi", win_url)
        else:
            catalog = fetch_catalog()
            if args.list:
                print_catalog(catalog, args.os, args.distro, args.arch, args.version)
                return 0
            distro = args.distro
            if operating_system == "linux" and not distro:
                distro = detect_distro(read_os_release())
            arch = args.arch or platform.machine()
            normalize_arch(arch)
            package = select_package(catalog, operating_system, distro, arch, args.version)

        if args.print_url:
            print(package.url)
            return 0
        print("Downloading WARP {} ({}) from Cloudflare...".format(package.version, package.platform), file=sys.stderr)
        destination, digest = download_package(package, args.output_dir, args.force)
        print("Saved: {}".format(destination))
        print("SHA256: {}".format(digest))
        print("Checksum and source metadata: {}.sha256, {}.json".format(destination, destination))
        return 0
    except (DownloadError, OSError, urllib.error.URLError, http.client.HTTPException) as exc:
        print("Error: {}".format(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Download cancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    if sys.version_info < (3, 9):
        sys.exit("Error: Python 3.9 or newer is required.")
    sys.exit(main())
