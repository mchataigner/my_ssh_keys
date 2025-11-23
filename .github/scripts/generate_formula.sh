#!/usr/bin/env bash
set -euo pipefail

# Generate Homebrew formula into dist/ using environment variables TAG and SHA256
mkdir -p dist

# TAG may be provided from the environment; fall back to GITHUB_REF if not set
TAG=${TAG:-${GITHUB_REF#refs/tags/}}
# Allow SHA to be passed in via SHA256 env (as used in the workflow)
SHA=${SHA256:-}

# If SHA is not provided, try to locate the generated tarball and compute it
if [ -z "${SHA:-}" ]; then
  VERSION=${TAG#v}
  # possible tarball locations
  for f in dist/my_ssh_keys-${VERSION}.tar.gz my_ssh_keys-${VERSION}.tar.gz; do
    if [ -f "$f" ]; then
      if command -v sha256sum >/dev/null 2>&1; then
        SHA=$(sha256sum "$f" | awk '{print $1}')
      elif command -v shasum >/dev/null 2>&1; then
        SHA=$(shasum -a 256 "$f" | awk '{print $1}')
      else
        echo "Warning: no sha256sum/shasum available to compute checksum" >&2
        SHA=""
      fi
      break
    fi
  done
fi

cat > dist/fetch-ssh-keys.rb <<RUBY
class FetchSshKeys < Formula
  desc "Fetch SSH public keys from providers and print in authorized_keys format"
  homepage "https://github.com/${GITHUB_REPOSITORY}"
  url "https://github.com/${GITHUB_REPOSITORY}/archive/refs/tags/${TAG}.tar.gz"
  sha256 "${SHA}"
  license "MIT"

  uses_from_macos "python"

  def install
    bin.install "fetch_ssh_keys"
    prefix.install "LICENSE"
  end

  test do
    assert_predicate bin/"fetch_ssh_keys", :exist?
  end
end
RUBY

exit 0
