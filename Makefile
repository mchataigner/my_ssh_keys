# Makefile for local development: build tarball, Debian package, Arch package (via Docker),
# install the script locally, and clean artifacts.

.PHONY: help all build tarball deb arch install test clean

ifndef VERSION
GIT_TAG := $(shell (command -v git >/dev/null 2>&1 && git describe --tags --abbrev=0 2>/dev/null) || echo "v0.0.0")
VERSION := $(shell echo $(GIT_TAG) | sed 's/^v//')
endif

DISTDIR := dist

all: build

help:
	@echo "Available targets:"
	@echo "  make tarball    - create source tarball in $(DISTDIR)/"
	@echo "  make deb        - build Debian package inside a Debian Docker container (requires docker)"
	@echo "  make arch       - build Arch package inside archlinux:latest Docker container"
	@echo "  make install    - install script to /usr/local/bin (use DESTDIR to stage)"
	@echo "  make test       - run a quick smoke test"
	@echo "  make clean      - remove build artifacts"

build: tarball deb arch

$(DISTDIR):
	mkdir -p $(DISTDIR)

tarball: $(DISTDIR)
	@echo "Creating source tarball for version $(VERSION)"
	git archive --format=tar --prefix=my_ssh_keys-$(VERSION)/ $(GIT_TAG) | gzip > $(DISTDIR)/my_ssh_keys-$(VERSION).tar.gz
	@echo "sha256:" $(shell sha256sum $(DISTDIR)/my_ssh_keys-$(VERSION).tar.gz | awk '{print $$1}')



deb: $(DISTDIR)
	@echo "Building Debian package inside Docker (needs docker installed)"
	@if ! command -v docker >/dev/null 2>&1; then \
		echo "docker not found; please install docker or run make deb on a Debian/Ubuntu host"; exit 1; \
	fi
	@# delegate to the scripts helper to avoid quoting/Makefile issues
	@bash scripts/build_deb.sh $(VERSION)
	# move generated .deb(s) to dist
	mv ../*.deb $(DISTDIR)/ 2>/dev/null || true
	mv *.deb $(DISTDIR)/ 2>/dev/null || true

arch: $(DISTDIR)
	@echo "Building Arch Linux package inside Docker (needs docker installed)"
	@if ! command -v docker >/dev/null 2>&1; then \
		echo "docker not found; please install docker or run make arch on an Arch host"; exit 1; \
	fi
	@# delegate to the scripts helper to avoid quoting/Makefile issues
	@bash scripts/build_arch.sh $(VERSION)
	# move resulting packages to dist
	mv *.pkg.tar.* $(DISTDIR)/ 2>/dev/null || true

install:
	@echo "Installing fetch_ssh_keys to $(DESTDIR)/usr/local/bin"
	install -d "$(DESTDIR)/usr/local/bin"
	install -m 755 fetch_ssh_keys "$(DESTDIR)/usr/local/bin/fetch_ssh_keys"

test:
	@echo "Running quick smoke test"
	python3 fetch_ssh_keys --help >/dev/null
	@echo "OK"

clean:
	rm -rf $(DISTDIR) my_ssh_keys-*.tar.gz *.deb *.changes *.build *.pkg.tar.* debian/*.debhelper* || true
