#!/usr/bin/env python3
"""
fetch_ssh_keys.py

Fetch SSH public keys from common providers and print them in authorized_keys format.

Usage examples:
  python fetch_ssh_keys.py github torvalds
  python fetch_ssh_keys.py gitlab gitlab-org
  python fetch_ssh_keys.py local ~/.ssh/id_rsa.pub ~/.ssh/another_key.pub
  echo "ssh-ed25519 AAAA... user@host" | python fetch_ssh_keys.py stdin

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


def fetch_github(username: str) -> List[str]:
    """Fetch public keys from GitHub's /<user>.keys endpoint."""
    url = f"https://github.com/{username}.keys"
    data = fetch_url(url)
    lines = [l.strip() for l in data.splitlines() if l.strip()]
    return [l for l in lines if is_valid_pubkey(l)]


def fetch_gitlab(username: str) -> List[str]:
    """Fetch public keys from GitLab's public API.

    Steps:
      1) GET /api/v4/users?username=<username> to find user id
      2) GET /api/v4/users/<id>/keys to obtain keys
    """
    search_url = f"https://gitlab.com/api/v4/users?username={username}"
    data = fetch_url(search_url)
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
    data = fetch_url(keys_url)
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


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Fetch SSH public keys and print in authorized_keys format")
    ap.add_argument("provider", choices=["github", "gitlab", "local", "stdin"],
                    help="where to fetch keys from")
    ap.add_argument("target", nargs="*", help="username for github/gitlab, or file paths for local. stdin reads from STDIN.")
    ap.add_argument("--output", "-o", help="Write output to this file instead of stdout")
    args = ap.parse_args(argv)

    try:
        keys: List[str] = []
        source_desc = None
        if args.provider == "github":
            if not args.target:
                raise SystemExit("GitHub provider requires a username")
            username = args.target[0]
            keys = fetch_github(username)
            source_desc = f"github:{username}"
        elif args.provider == "gitlab":
            if not args.target:
                raise SystemExit("GitLab provider requires a username")
            username = args.target[0]
            keys = fetch_gitlab(username)
            source_desc = f"gitlab:{username}"
        elif args.provider == "local":
            if not args.target:
                raise SystemExit("local provider requires at least one file path or directory")
            keys = read_local(args.target)
            source_desc = "local"
        elif args.provider == "stdin":
            keys = read_stdin()
            source_desc = "stdin"

        if not keys:
            print("# No valid SSH public keys found.", file=sys.stderr)

        out_lines = format_for_authorized_keys(keys, source=source_desc)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write("\n".join(out_lines) + ("\n" if out_lines else ""))
        else:
            for ln in out_lines:
                print(ln)

        return 0
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
