# ChangeLog

## 2.1.0
December 14, 2025
  - switch to poetry
  - merge outstanding PRs
  - make handle checks and make them more robust
  - update documentation with better example
  - remove py2 support
  - tox test suite set to py312 and py313

## 2.0.2 Latest
March 17, 2022

### Surface fixes

  - Fixed #31 whereby I changed the boolean response in 2.0.0 to a PAM constant. This reverts to the boolean response as existed in v1.8.5. The result code is still stored in the obj.code attribute
  - Added the PamAuthenticate.authenticate() method signature and docstring to both of the new and legacy interfaces
  - Changed the PamAuthenticate.authenticate() type hinting so it didn't interfere with the docstring
  - update the version to 2.0.2

### Under the hood changes
  - Start mocking the libpam methods so we can wholly disassociate ourselves from the underlying system. This lets us test more of the actual python code and lets us start injecting errors to test for


## Release 2.0.0
March 13, 2022

The surface functionality hasn't changed much but a few bugs have been fixed. Under the hood, a lot has changed. Functionality has now been moved into a class that helped with value tracking. I planned on removing Python 2 support but was convinced to leave it in for now as apparently there are still a lot of python2 users. 😕 🤷‍♂️

Most testing has moved to occur underneath tox, this is superior as it provides for testing in a clean environment and an installed environment.

### Merges
  - #22, #24, #25 by @abompard
  - #21 by @spaceone and @LaurieReeves
  - #16 by @okin
  - #14 by @codypiersall
  - #11 by @e4r7hbug and @hugovk
  - #5 by @willmo
  - #4 by @skylize
  - #3 by @fatlotus

### Features & Changes
  - Unit testing and code coverage is 100% for all automated methods. Some methods require a valid TEST_USERNAME and TEST_PASSWORD to function and those are marked SKIP if not found in the environment. Sorry :-} -- mocking the internals of libc and libpam are far too hairy for the trivial bit of testing that can be verified by hand

### Testing summary
  - bandit added for security checks
  - flake8 added for linting
  - mypy for type hinting
  - coverage added (generated reports go in htmlcov/
  - Multi-factor authentication is supported now from #25 @abompard
  - All of the constants are now exposed such as pam.PAM_SUCCESS or pam.PAM_PERM_DENIED
  - pam.authenticate(..., print_failure_messages=False) parameter was added to help your debugging

## 1.8.5
Nov 12, 2019
  - use pam_set_item() to set PAM_TTY for pam_securetty module
  - add a bunch of tools for code quality
  - refactored the class slightly so the module can be imported and passive at
    runtime until authentication is actually needed

## 1.8.4
June 15, 2018
  - include LICENSE file as some distributions rely on the presence of it
    rather than extracting from setup.py

## 1.8.3
March 22, 2018
  - add a test for the existence libpam.pam_end function

## 1.8.2
November 17th, 2014
  - add MANIFEST.in so README.md gets included for pypi (pip installs)

## 1.8.1
August 4, 2014
  - adapt, add files, package up for PyPi
  - adapt, add files, package up for github
  - adapt, add files, package up for ArchLinux

Start of forked copy from Chris AtLee 2011-Dec
