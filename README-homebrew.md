# Homebrew / macOS installation

This repository includes a simple Homebrew formula at `Formula/fetch-ssh-keys.rb` so you (or a tap) can package the project for macOS users.

Two common ways to install from this repository:

1) Install locally (for development / testing)

   brew install --build-from-source ./Formula/fetch-ssh-keys.rb

   This will build/install the script directly from the current repository tree.

2) Publish a Homebrew tap

   - Create a repository `homebrew-<tapname>` (or use an existing tap) and add `fetch-ssh-keys.rb` into its `Formula/` directory.
   - If you publish tagged releases on GitHub, update the `url` in the formula to point to the released tarball and set the correct `sha256` value. Example:

     url "https://github.com/mchataigner/my_ssh_keys/archive/refs/tags/v1.0.tar.gz"
     sha256 "<sha256-of-tarball>"

   - Compute the tarball sha256 with:

     curl -L https://github.com/mchataigner/my_ssh_keys/archive/refs/tags/v1.0.tar.gz | shasum -a 256

   - Users can then tap and install:

     brew tap <user>/<tap>
     brew install <user>/<tap>/fetch-ssh-keys

Notes
- The formula installs the `fetch_ssh_keys` script into Homebrew's `bin` directory.
- The formula currently references the repository git URL and a `v1.0` tag for convenience; if you publish releases, prefer using the release tarball + sha256 for a stable formula.
