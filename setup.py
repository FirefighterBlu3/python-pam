import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

__sdesc = 'Python PAM for py3/py2'

setup(name='python-pam',
      description= __sdesc,
      long_description=read('README.md'),
      py_modules=['pam'],
      version='1.8.1',
      author='David Ford',
      author_email='david@blue-labs.org',
      maintainer='David Ford',
      maintainer_email='david@blue-labs.org',
      url='https://github.com/FirefighterBlu3/python-pam',
      download_url='https://github.com/FirefighterBlu3/python-pam',
      bugtrack_url='https://github.com/FirefighterBlu3/python-pam/issues',
      license='License :: OSI Approved :: MIT License',
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
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 3',
          'Topic :: System :: Systems Administration :: Authentication/Directory',
          ],
      platforms=['Linux','FreeBSD'],
      )
