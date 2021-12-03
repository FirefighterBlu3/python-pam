# python-pam

Python pam module supporting py3 (and py2)

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
[david@Scott python-pam]$ python
Python 3.9.7 (default, Oct 10 2021, 15:13:22)
[GCC 11.1.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import pam
>>> p = pam.authenticate()
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
