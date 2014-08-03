from distutils.core import setup

__sdesc = 'Python PAM for py3/py2'
__ldesc = '''Pluggable Authentication Modules (PAM) pure python module
using ctypes that supports python3 (and python2)'''

setup(name='pam',
      description= __sdesc,
      long_description=__ldesc,
      py_modules=['pam'],
      version='1.8'
      author='David Ford',
      author_email='david@blue-labs.org',
      maintainer='David Ford',
      maintainer_email='david@blue-labs.org',
      original_author='Chris AtLee',
      original_author_email='chris@atlee.ca',
      url='https://github.com/FirefighterBlu3/python-pam',
      license='LICENSE',
      classifiers=[
          'Development Status :: 6 - Mature',
          'Environment :: Console',
          'Environment :: No Input/Output (Daemon)',
          'Environment :: OpenStack',
          'Environment :: Other Environment',
          'Environment :: Plugins',
          'Intended Audience :: Developers',
          'Intended Audience :: Information Technology',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: MIT License',
          'Operating System :: POSIX',
          'Programming Language :: Python',
          'Topic :: System :: Systems Administration :: Authentication/Directory',
          ],
      platforms=['Linux','FreeBSD'],
      )
