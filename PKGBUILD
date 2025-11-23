pkgname=fetch-ssh-keys
pkgver=0.0.0
pkgrel=1
pkgdesc="Fetch SSH public keys from providers and print in authorized_keys format"
arch=('any')
url="https://github.com/mchataigner/my_ssh_keys"
license=('MIT')
depends=('python')
install=fetch-ssh-keys.install
source=("fetch_ssh_keys" "LICENSE")
sha512sums=('SKIP' 'SKIP')

build() {
    # No build step required for this simple script
    return 0
}

package() {
    # Install to /usr/local/bin as requested
    install -d "$pkgdir/usr/local/bin"
    install -m755 "$srcdir/fetch_ssh_keys" "$pkgdir/usr/local/bin/fetch_ssh_keys"

    # Install license
    install -d "$pkgdir/usr/share/licenses/$pkgname"
    install -m644 "$srcdir/LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
