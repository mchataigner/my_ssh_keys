#!/usr/bin/env bash
set -euo pipefail

# build_deb.sh [version]
# Builds Debian package inside Docker. Mounts current repo to /src and runs dpkg-buildpackage.

VERSION=${1:-$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")}
VERSION=${VERSION#v}
DEB_IMAGE=${DEB_IMAGE:-debian:stable-slim}
# allow overriding docker platform (default to amd64)
DOCKER_PLATFORM=${DOCKER_PLATFORM:-linux/amd64}

echo "Preparing debian/changelog for version ${VERSION}"
DCH_EMAIL="mchataigner@example.com"
printf '%s\n' "my-ssh-keys (${VERSION}) unstable; urgency=medium" "" "  * Release ${VERSION}" "" " -- Mathieu Bressolle Chataigner <${DCH_EMAIL}>  $(date -R)" > debian/changelog

echo "Building Debian package inside container ${DEB_IMAGE}..."

docker run --rm -i --platform "${DOCKER_PLATFORM}" -e VERSION="${VERSION}" -v "$PWD:/src" -w /src "${DEB_IMAGE}" bash -s <<'EOF'
set -e
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential devscripts fakeroot debhelper dh-python python3 ca-certificates
# build package
dpkg-buildpackage -us -uc -b || (echo 'dpkg-buildpackage failed' && exit 1)
EOF

echo "Debian build finished. Artifacts (if any) are in the parent directory of the repo (../)."
