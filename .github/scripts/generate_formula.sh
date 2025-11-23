#!/usr/bin/env bash
set -euo pipefail

# Generate Homebrew formula into dist/ using environment variables TAG and SHA256
mkdir -p dist
TAG=${TAG:-${GITHUB_REF#refs/tags/}}
SHA=${SHA256:-}

cat > dist/fetch-ssh-keys.rb <<'RUBY'
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
