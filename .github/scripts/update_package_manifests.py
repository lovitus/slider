#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


REPO = "lovitus/slider"
PROJECT = "slider"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Update Homebrew and Scoop manifests.")
    parser.add_argument("--version", required=True)
    parser.add_argument("--checksums", required=True, type=Path)
    return parser.parse_args()


def version_key(version: str) -> tuple[int, ...]:
    key: list[int] = []
    for part in re.split(r"[.-]", version):
        if not part.isdigit():
            break
        key.append(int(part))
    return tuple(key)


def current_scoop_version(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    version = data.get("version")
    return version if isinstance(version, str) else None


def should_update(target_version: str, scoop_path: Path) -> bool:
    current = current_scoop_version(scoop_path)
    if not current:
        return True
    return version_key(target_version) >= version_key(current)


def load_checksums(path: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        checksum, filename = fields
        checksums[filename] = checksum
    return checksums


def checksum(checksums: dict[str, str], filename: str) -> str:
    try:
        return checksums[filename]
    except KeyError as exc:
        raise SystemExit(f"missing checksum for {filename}") from exc


def archive(version: str, goos: str, goarch: str, ext: str) -> str:
    return f"{PROJECT}_{version}_{goos}_{goarch}.{ext}"


def release_url(version: str, filename: str) -> str:
    return f"https://github.com/{REPO}/releases/download/v{version}/{filename}"


def write_homebrew_formula(version: str, checksums: dict[str, str], path: Path) -> None:
    darwin_arm64 = archive(version, "darwin", "arm64", "tar.gz")
    darwin_amd64 = archive(version, "darwin", "amd64", "tar.gz")
    linux_arm64 = archive(version, "linux", "arm64", "tar.gz")
    linux_amd64 = archive(version, "linux", "amd64", "tar.gz")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'''class Slider < Formula
  desc "Forward proxy with multiple protocol support, DNS forwarding, and ipset management"
  homepage "https://github.com/{REPO}"
  version "{version}"
  license "GPL-3.0-only"

  on_macos do
    on_arm do
      url "{release_url(version, darwin_arm64)}"
      sha256 "{checksum(checksums, darwin_arm64)}"
    end

    on_intel do
      url "{release_url(version, darwin_amd64)}"
      sha256 "{checksum(checksums, darwin_amd64)}"
    end
  end

  on_linux do
    on_arm do
      url "{release_url(version, linux_arm64)}"
      sha256 "{checksum(checksums, linux_arm64)}"
    end

    on_intel do
      url "{release_url(version, linux_amd64)}"
      sha256 "{checksum(checksums, linux_amd64)}"
    end
  end

  def install
    bin.install "slider"
  end

  test do
    assert_match version.to_s, shell_output("#{{bin}}/slider --version")
  end
end
''',
        encoding="utf-8",
    )


def scoop_arch(version: str, checksums: dict[str, str], goarch: str) -> dict[str, object]:
    filename = archive(version, "windows", goarch, "zip")
    return {
        "url": release_url(version, filename),
        "hash": checksum(checksums, filename),
        "bin": "slider.exe",
    }


def scoop_autoupdate_arch(goarch: str) -> dict[str, object]:
    filename = f"{PROJECT}_$version_windows_{goarch}.zip"
    return {
        "url": f"https://github.com/{REPO}/releases/download/v$version/{filename}",
        "hash": {
            "url": "$baseurl/slider_$version_checksums.txt",
            "regex": f"$sha256\\s+slider_$version_windows_{goarch}\\.zip",
        },
        "bin": "slider.exe",
    }


def write_scoop_manifest(version: str, checksums: dict[str, str], path: Path) -> None:
    data = {
        "version": version,
        "description": "Forward proxy with multiple protocol support, DNS forwarding, and ipset management.",
        "homepage": f"https://github.com/{REPO}",
        "license": "GPL-3.0-only",
        "architecture": {
            "64bit": scoop_arch(version, checksums, "amd64"),
            "arm64": scoop_arch(version, checksums, "arm64"),
        },
        "checkver": {
            "github": f"https://github.com/{REPO}",
        },
        "autoupdate": {
            "architecture": {
                "64bit": scoop_autoupdate_arch("amd64"),
                "arm64": scoop_autoupdate_arch("arm64"),
            },
        },
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
    args = parse_args()
    scoop_path = Path("bucket/slider.json")
    if not should_update(args.version, scoop_path):
        print(f"package manifests already point to a newer version than {args.version}; skipping")
        return

    checksums = load_checksums(args.checksums)
    write_homebrew_formula(args.version, checksums, Path("Formula/slider.rb"))
    write_scoop_manifest(args.version, checksums, scoop_path)


if __name__ == "__main__":
    main()
