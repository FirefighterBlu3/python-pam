# python-pam

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/FirefighterBlu3/python-pam/badge)](https://scorecard.dev/viewer/?uri=github.com/FirefighterBlu3/python-pam)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13794/badge)](https://www.bestpractices.dev/projects/13794)

Python pam module supporting py3 for Linux type systems (!windows)

## Security

See [SECURITY.md](SECURITY.md) for supported versions and how to report vulnerabilities.

## Threading and concurrency

`pam.authenticate()` is safe to call from many threads at once. Each call uses
its own PAM handle; libpam ctypes bindings are loaded once and shared (no global
lock on the auth path).

Do **not** share a single `PamAuthenticator` / `pam.pam()` instance across threads
without external synchronization. That object owns mutable PAM session state
(`handle`, `code`, `reason`, `messages`). For sessions (`call_end=False`), keep
one instance per thread (or serialize access).

High-QPS login APIs should use:

```python
import pam

if pam.authenticate(username, password, service='myapp'):
    ...
```

## Credentials (`resetcreds`)

After a successful `pam_authenticate` + `pam_acct_mgmt`, `authenticate()` calls
`pam_setcred(..., PAM_REINITIALIZE_CRED)` when `resetcreds=True` (the default).

**Keep the default (`True`)** when this process is acting like a login / credential
handoff: modules may establish or refresh credentials (e.g. Kerberos), and you care
about that step succeeding as part of auth.

**Set `resetcreds=False`** when you only need to verify a username/password (typical
web/API “is this password valid?” checks). You are not assuming the user’s identity
or opening a session; skipping setcred avoids extra module work and avoids treating a
setcred failure as an authentication failure.

```python
# Password check only
pam.authenticate(user, password, service='myapp', resetcreds=False)

# Login-style / credential-aware stack (default)
pam.authenticate(user, password, service='login')
```

## Examples

Commandline example:

```bash
[david@Scott python-pam]$ python pam/pam.py
Username: david
Password:
Auth result: Success (0)
Pam Environment List item: XDG_SEAT=seat0
Pam Environment item: XDG_SEAT=seat0
Missing Pam Environment item: asdf=None
Open session: Success (0)
Close session: Success (0)
```

Inline examples:

```python
>>> import pam
>>> pam.authenticate('david', 'correctpassword')
True
>>> p = pam.pam()
>>> p.authenticate('david', 'correctpassword')
True
>>> p.authenticate('david', 'badpassword')
False
>>> p.authenticate('david', 'correctpassword', service='login')
True
>>> p.authenticate('david', 'correctpassword', service='unknownservice')
False
>>> p.authenticate('david', 'correctpassword', service='login', resetcreds=True)
True
>>> p.authenticate('david', 'correctpassword', encoding='latin-1')
True
>>> print('{} {}'.format(p.code, p.reason))
0 Success
>>> p.authenticate('david', 'badpassword')
False
>>> print('{} {}'.format(p.code, p.reason))
7 Authentication failure
>>>
```

## Authentication and privileges
Please note, python-pam and *all* tools that do authentication follow two rules:

* You have root (or privileged access): you can check any account's password for validity
* You don't have root: you can only check the validity of the username running the tool

If you need to authenticate multiple users, you must use an authentication stack that at some stage has privileged access. On Linux systems one example of doing this is using SSSD.

Typical Linux installations check against `/etc/shadow` with `pam_unix.so` which will spawn `/usr/bin/unix_chkpwd` to verify the password. Both of these are intentionally written to meet the above two rules. You can test the functionality of `unix_chkpwd` in the following manner:

Replace `good` with the correct password, replace `david` with your appropriate username.

```
~$ mkfifo /tmp/myfifo

~$ (echo -ne 'good\0' > /tmp/myfifo & /usr/bin/unix_chkpwd david nullok < /tmp/myfifo ) ; echo $?
0

~$ (echo -ne 'bad\0' > /tmp/myfifo & /usr/bin/unix_chkpwd david nullok < /tmp/myfifo ) ; echo $?
7

~$ (echo -ne 'good\0' > /tmp/myfifo & /usr/bin/unix_chkpwd someotheruser nullok < /tmp/myfifo ) ; echo $?
9
```
