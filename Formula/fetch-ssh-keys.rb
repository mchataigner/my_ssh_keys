class FetchSshKeys < Formula
  desc "Fetch SSH public keys from providers and print in authorized_keys format"
  homepage "https://github.com/mchataigner/my_ssh_keys"
  # If you publish a release (tagged) on GitHub, update the URL to the tarball and set the correct sha256.
  # Using the git URL makes it possible to install directly from the repository when testing locally.
  url "https://github.com/mchataigner/my_ssh_keys.git", tag: "v1.0"
  version "1.0"
  license "MIT"

  uses_from_macos "python"

  def install
    # The repository contains a single script named `fetch_ssh_keys` which we install into Homebrew's bin
    bin.install "fetch_ssh_keys"

    # Install the license for reference
    prefix.install "LICENSE"
  end

  test do
    # Basic sanity check: the installed executable exists
    assert_predicate bin/"fetch_ssh_keys", :exist?
  end
end
