#!/usr/bin/env python3
"""
fetch_ssh_keys

Fetch SSH public keys from common providers and print them in authorized_keys format.

Usage examples:
  python fetch_ssh_keys github torvalds
  python fetch_ssh_keys gitlab gitlab-org
  python fetch_ssh_keys local ~/.ssh/id_rsa.pub ~/.ssh/another_key.pub
  echo "ssh-ed25519 AAAA... user@host" | python fetch_ssh_keys stdin

This script avoids external dependencies and uses urllib from the stdlib.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from typing import List

try:
    # Python 3
    from urllib.request import urlopen, Request
    from urllib.error import URLError, HTTPError
except Exception:
    print("Error importing urllib; this script requires Python 3.")
    raise

SSH_KEY_RE = re.compile(r"^(?P<type>ssh-[a-z0-9-]+|ecdsa-sha2-nistp\d+)\s+(?P<body>[A-Za-z0-9+/=]+)(\s+(?P<comment>.*))?$")


def is_valid_pubkey(line: str) -> bool:
    return bool(SSH_KEY_RE.match(line.strip()))


def fetch_url(url: str, timeout: int = 10) -> str:
    req = Request(url, headers={"User-Agent": "fetch-ssh-keys/1.0"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except HTTPError as e:
        raise RuntimeError(f"HTTP error {e.code} when fetching {url}") from e
    except URLError as e:
        raise RuntimeError(f"URL error when fetching {url}: {e.reason}") from e


def fetch_github(username: str, timeout: int = 10) -> List[str]:
    """Fetch public keys from GitHub's /<user>.keys endpoint."""
    url = f"https://github.com/{username}.keys"
    data = fetch_url(url, timeout=timeout)
    lines = [l.strip() for l in data.splitlines() if l.strip()]
    return [l for l in lines if is_valid_pubkey(l)]


def fetch_gitlab(username: str, timeout: int = 10) -> List[str]:
    """Fetch public keys from GitLab's public API.

    Steps:
      1) GET /api/v4/users?username=<username> to find user id
      2) GET /api/v4/users/<id>/keys to obtain keys
    """
    search_url = f"https://gitlab.com/api/v4/users?username={username}"
    data = fetch_url(search_url, timeout=timeout)
    try:
        users = json.loads(data)
    except json.JSONDecodeError as e:
        raise RuntimeError("Failed to decode GitLab user search response") from e
    if not isinstance(users, list) or not users:
        raise RuntimeError(f"GitLab: user '{username}' not found")
    user_id = users[0].get("id")
    if not user_id:
        raise RuntimeError("GitLab: couldn't determine user id")

    keys_url = f"https://gitlab.com/api/v4/users/{user_id}/keys"
    data = fetch_url(keys_url, timeout=timeout)
    try:
        keys = json.loads(data)
    except json.JSONDecodeError as e:
        raise RuntimeError("Failed to decode GitLab keys response") from e
    out: List[str] = []
    for k in keys:
        key = k.get("key") if isinstance(k, dict) else None
        if key and is_valid_pubkey(key):
            out.append(key.strip())
    return out


def read_local(paths: List[str]) -> List[str]:
    out: List[str] = []
    for p in paths:
        # expand user and globs
        expanded = glob.glob(os.path.expanduser(p))
        if not expanded:
            # maybe p is a directory: read *.pub
            if os.path.isdir(os.path.expanduser(p)):
                expanded = glob.glob(os.path.join(os.path.expanduser(p), "*.pub"))
        if not expanded:
            # if no match, treat p literally
            expanded = [os.path.expanduser(p)]

        for fp in expanded:
            if os.path.isdir(fp):
                # read *.pub inside
                for sub in glob.glob(os.path.join(fp, "*.pub")):
                    out.extend(read_file_lines(sub))
                continue
            out.extend(read_file_lines(fp))
    # filter
    return [l for l in (x.strip() for x in out) if l and is_valid_pubkey(l)]


def read_file_lines(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [ln.rstrip("\n") for ln in f]
    except FileNotFoundError:
        return []


def read_stdin() -> List[str]:
    data = sys.stdin.read()
    return [l.strip() for l in data.splitlines() if l.strip() and is_valid_pubkey(l.strip())]


def format_for_authorized_keys(lines: List[str], source: str | None = None) -> List[str]:
    # Return only the valid key lines. Do not include comment lines or empty lines.
    return [l for l in (line.strip() for line in lines) if l and not l.startswith("#")]


def update_authorized_keys_section(path: str, section_name: str, key_lines: List[str], source: str | None = None) -> None:
    """Replace or insert a named section in an authorized_keys file.

    The section is delimited by comment markers exactly matching:
      # BEGIN fetch_ssh_keys:SECTION_NAME
      ... keys ...
      # END fetch_ssh_keys:SECTION_NAME

    If the section exists it will be replaced. If it does not exist the section
    will be appended to the end of the file (creating it if necessary).
    """
    start_marker = f"# BEGIN fetch_ssh_keys:{section_name}"
    end_marker = f"# END fetch_ssh_keys:{section_name}"

    try:
        orig_lines = read_file_lines(path)
    except Exception:
        orig_lines = []

    # Build the replacement section
    new_section: List[str] = [start_marker]
    if source:
        new_section.append(f"# source: {source}")
    # ensure key_lines are stripped and valid-looking (they should already be)
    new_section.extend([ln for ln in (l.strip() for l in key_lines) if ln])
    new_section.append(end_marker)

    out_lines: List[str] = []
    i = 0
    replaced = 0
    n = len(orig_lines)
    while i < n:
        line = orig_lines[i]
        if line.strip() == start_marker:
            # Found an existing section: skip it until matching end_marker
            replaced += 1
            out_lines.extend(new_section)
            # skip until end_marker (inclusive)
            i += 1
            while i < n and orig_lines[i].strip() != end_marker:
                i += 1
            if i < n and orig_lines[i].strip() == end_marker:
                i += 1
            continue
        else:
            out_lines.append(line)
            i += 1

    if replaced == 0:
        # Append a blank line separator if file does not end with empty line
        if out_lines and out_lines[-1].strip() != "":
            out_lines.append("")
        out_lines.extend(new_section)

    # Write atomically
    tmp_path = path + ".tmp"
    try:
        # ensure parent directory exists
        parent = os.path.dirname(os.path.expanduser(path))
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
        with open(tmp_path, "w", encoding="utf-8") as f:
            for ln in out_lines:
                f.write(ln + "\n")
        os.replace(tmp_path, path)
    except Exception as e:
        # cleanup tmp file if present
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        raise RuntimeError(f"failed to write authorized_keys file {path}: {e}") from e


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Fetch SSH public keys and print in authorized_keys format")
    ap.add_argument("target", nargs="*", help="username for github/gitlab, or file paths for local. stdin reads from STDIN.")
    ap.add_argument("--provider", choices=["github", "gitlab", "local", "stdin"], default="github",
        help="where to fetch keys from (default: github)")
    ap.add_argument("--output", "-o", help="Write output to this file instead of stdout")
    ap.add_argument("--timeout", "-t", type=int, default=10,
                    help="Network timeout in seconds when fetching from providers (default: 10)")
    ap.add_argument("--auth-file", default="~/.ssh/authorized_keys",
                    help="Path to the authorized_keys file to update when using --update (default: ~/.ssh/authorized_keys)")
    ap.add_argument("--update", action="store_true",
                    help="Update (replace or insert) the hardcoded section inside an authorized_keys file.")
    args = ap.parse_args(argv)

    PROVIDERS = ["github", "gitlab", "local", "stdin"]
    provider = args.provider
    targets = args.target
    # If provider is specified as the first positional, shift it
    if targets and targets[0] in PROVIDERS:
        provider = targets[0]
        targets = targets[1:]

    # Hardcoded section name
    SECTION_NAME = "managed"
    try:
        keys: List[str] = []
        source_desc: str | None = None

        if provider == "github":
            if not targets:
                raise SystemExit("GitHub provider requires a username")
            username = targets[0]
            try:
                keys = fetch_github(username, timeout=args.timeout)
                source_desc = f"github:{username}"
            except RuntimeError as e:
                print(f"Warning: failed to fetch from github:{username}: {e}", file=sys.stderr)

        elif provider == "gitlab":
            if not targets:
                raise SystemExit("GitLab provider requires a username")
            username = targets[0]
            try:
                keys = fetch_gitlab(username, timeout=args.timeout)
                source_desc = f"gitlab:{username}"
            except RuntimeError as e:
                print(f"Warning: failed to fetch from gitlab:{username}: {e}", file=sys.stderr)

        elif provider == "local":
            if not targets:
                raise SystemExit("local provider requires at least one file path or directory")
            keys = read_local(targets)
            source_desc = "local"

        elif provider == "stdin":
            keys = read_stdin()
            source_desc = "stdin"

        if not keys:
            print("# No valid SSH public keys found.", file=sys.stderr)

        out_lines = format_for_authorized_keys(keys, source=source_desc)

        if args.output:
            if args.update:
                raise SystemExit("--output and --update are mutually exclusive")
            with open(args.output, "w", encoding="utf-8") as f:
                f.write("\n".join(out_lines) + ("\n" if out_lines else ""))
        elif args.update:
            auth_path = os.path.expanduser(args.auth_file)
            try:
                update_authorized_keys_section(auth_path, SECTION_NAME, out_lines, source_desc)
            except RuntimeError as e:
                print(f"Error updating authorized_keys file: {e}", file=sys.stderr)
                return 3
        else:
            for ln in out_lines:
                print(ln)

        return 0
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
