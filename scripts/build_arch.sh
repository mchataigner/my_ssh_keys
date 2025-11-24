
#!/usr/bin/env bash
set -euo pipefail

# build_arch.sh [version]
# Builds Arch package inside Docker. Mounts current repo to /src and runs makepkg.


VERSION=${1:-$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")}
VERSION=${VERSION#v}
ARCH_IMAGE=${ARCH_IMAGE:-archlinux:latest}
# allow overriding docker platform (default to amd64)
DOCKER_PLATFORM=${DOCKER_PLATFORM:-linux/amd64}

echo "Building Arch package inside container ${ARCH_IMAGE} for version ${VERSION}..."

# Run the container and execute a small script inside it. We use a here-doc to avoid complicated
# quoting. The heredoc is passed to bash -s inside the container.
docker run --rm -i --platform "${DOCKER_PLATFORM}" -e VERSION="${VERSION}" -v "$PWD:/src" -w /src "${ARCH_IMAGE}" bash -s <<'EOF'
set -e
pacman -Sy --noconfirm --needed base-devel git python
useradd -m builder || true
mkdir -p /build/src
cp -a /src/. /build/src/
if [ -f /build/src/PKGBUILD ]; then
	sed -i "s/^pkgver=.*/pkgver=${VERSION}/" /build/src/PKGBUILD || true
fi
chown -R builder:builder /build/src || true
su builder -c "cd /build/src && makepkg -s --noconfirm" || true
cp -f /build/src/*.pkg.tar.* /src/ 2>/dev/null || true
EOF

echo "Arch build finished. Artifacts (if any) are in the repository root."
