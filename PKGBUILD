# Maintainer: David Ford <david@blue-labs.org>
pkgname=python-pam
pkgver=1.8.2
pkgrel=1
pkgdesc="Linux, FreeBSD, etc (any system that uses PAM) PAM module that provides an
authenticate function given a username, password, and other optional keywords."
arch=('any')
url="https://github.com/FirefighterBlu3/python-pam"
license=('MIT')
depends=('python','pam')
options=(!emptydirs)
changelog=('ChangeLog')
source=(https://pypi.python.org/packages/source/p/${pkgname}/${pkgname}-${pkgver}.tar.gz
        https://pypi.python.org/packages/source/p/${pkgname}/${pkgname}-${pkgver}.tar.gz.asc)
md5sums=(9a07139fea29e8dae66f5bc37d830a74
         ee1be19c5a69cb37629bded9a5816335)

package() {
  cd "$srcdir/$pkgname-$pkgver"
  python setup.py install --root="$pkgdir/" --optimize=1
}

# vim:set ts=2 sw=2 et:
