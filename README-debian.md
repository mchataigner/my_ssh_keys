# Building a .deb package

This repository includes a minimal Debian packaging directory in `debian/` to build a simple .deb of the project.

What is packaged
- `fetch_ssh_keys` -> installed to `/usr/bin/fetch_ssh_keys`.

Build steps (on Debian/Ubuntu/macOS with dpkg-buildpackage available via dpkg-dev inside Linux):

1. Ensure packaging tools are installed on a Debian-based system:

```sh
sudo apt update
sudo apt install build-essential devscripts debhelper-compat
```

2. Make `debian/rules` executable if needed:

```sh
chmod +x debian/rules
```

3. Build the package from the project root:

```sh
dpkg-buildpackage -us -uc -b
```

The produced .deb will be one level above the project directory.

Notes
- The packaging is intentionally minimal. If you want additional files installed (docs, systemd units, configuration files), add them to `debian/install` or create appropriate packaging scripts.
- The maintainer and homepage fields are set to reasonable defaults but you may update them in `debian/control`.
