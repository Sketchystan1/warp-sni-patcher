#!/usr/bin/env python3
"""Validate a release against the current changelog and write GitHub outputs."""

import os
from pathlib import Path
import re
import subprocess

VERSION = r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?"
HEADER = re.compile(rf"^## \[({VERSION})\][^\n]*$", re.MULTILINE)


def release_entry(changelog):
    headers = list(HEADER.finditer(changelog))
    if not headers:
        raise ValueError("CHANGELOG.md needs a version heading such as ## [1.2.0].")
    first = headers[0]
    end = headers[1].start() if len(headers) > 1 else len(changelog)
    notes = changelog[first.end():end].strip()
    if not notes:
        raise ValueError("The latest changelog entry has no release notes.")
    return first[1], notes


def release_plan(version, event, ref_type, ref_name, requested_tag, prerelease, existing_sha, head_sha):
    tag = ref_name if ref_type == "tag" else requested_tag.strip() or f"v{version}"
    if tag != f"v{version}":
        raise ValueError(f"Requested tag {tag!r} does not match the latest changelog version v{version}.")
    explicit = ref_type == "tag" or event == "workflow_dispatch"
    if explicit and existing_sha and existing_sha != head_sha:
        raise ValueError(f"Tag {tag} belongs to another commit; refusing to replace its release assets.")
    return {
        "should_release": str(explicit or not existing_sha).lower(),
        "tag": tag,
        "title": f"Release {tag}",
        "is_prerelease": str(prerelease or "-" in version).lower(),
    }


def main():
    version, notes = release_entry(Path("CHANGELOG.md").read_text(encoding="utf-8"))
    tag = f"v{version}"
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    existing = subprocess.run(["git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"],
                              capture_output=True, text=True)
    plan = release_plan(version, os.environ.get("GITHUB_EVENT_NAME", ""),
                        os.environ.get("GITHUB_REF_TYPE", ""), os.environ.get("GITHUB_REF_NAME", ""),
                        os.environ.get("REQUESTED_TAG", ""), os.environ.get("REQUESTED_PRERELEASE") == "true",
                        existing.stdout.strip() if existing.returncode == 0 else None, head)
    Path("release_notes.md").write_text(notes + "\n", encoding="utf-8")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        for name, value in plan.items():
            output.write(f"{name}={value}\n")
    print(f"Release {plan['tag']}: {plan['should_release']}")


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        raise SystemExit(str(error))
