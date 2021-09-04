import sys


if sys.version_info < (3, ):  # pragma: no cover
    print('WARNING, Python 2 is EOL and therefore py2 support in this '
          "package is deprecated. It won't be actively checked for"
          'correctness')

__all__ = ['authenticate']

from .pam import authenticate
