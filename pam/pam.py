# (c) 2007 Chris AtLee <chris@atlee.ca>
# Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license.php
#
# Original author: Chris AtLee
#
# Modified by David Ford, 2011-12-6
# added py3 support and encoding
# added pam_end
# added pam_setcred to reset credentials after seeing Leon Walker's remarks
# added byref as well
# use readline to prestuff the getuser input
#
# Modified by Laurie Reeves, 2020-02-14
# added opening and closing the pam session
# added setting and reading the pam environment variables
# added setting the "misc" pam environment
# added saving the messages passed back in the conversation function

'''
PAM module for python

Provides an authenticate function that will allow the caller to authenticate
a user against the Pluggable Authentication Modules (PAM) on the system.

Implemented using ctypes, so no compilation is necessary.
'''

import six

from . import internals

__all__ = ['pam']


def authenticate(*vargs, **dargs):
    """
    Compatibility function for older versions of python-pam.
    """
    return internals.PamAuthenticator().authenticate(*vargs, **dargs)


if __name__ == "__main__":  # pragma: no cover
    import readline
    import getpass

    def input_with_prefill(prompt, text):
        def hook():
            readline.insert_text(text)
            readline.redisplay()

        readline.set_pre_input_hook(hook)
        result = six.input(prompt)  # nosec (bandit; python2)

        readline.set_pre_input_hook()

        return result

    pam = internals.PamAuthenticator()

    username = input_with_prefill('Username: ', getpass.getuser())

    # enter a valid username and an invalid/valid password, to verify both
    # failure and success
    result = pam.authenticate(username, getpass.getpass(),
                              env={"XDG_SEAT": "seat0"},
                              call_end=False)
    print('Auth result: {} ({})'.format(pam.reason, pam.code))

    env_list = pam.getenvlist()
    for key, value in env_list.items():
        print("Pam Environment List item: {}={}".format(key, value))

    key = "XDG_SEAT"
    value = pam.getenv(key)
    print("Pam Environment item: {}={}".format(key, value))

    key = "asdf"
    value = pam.getenv(key)
    print("Missing Pam Environment item: {}={}".format(key, value))

    if pam.code == internals.PAM_SUCCESS:
        result = pam.open_session()
        print('Open session: {} ({})'.format(pam.reason, pam.code))

        if pam.code == internals.PAM_SUCCESS:
            result = pam.close_session()
            print('Close session: {} ({})'.format(pam.reason, pam.code))

        else:
            pam.end()
    else:
        pam.end()
