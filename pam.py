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

'''
PAM module for python

Provides an authenticate function that will allow the caller to authenticate
a user against the Pluggable Authentication Modules (PAM) on the system.

Implemented using ctypes, so no compilation is necessary.
'''

__all__      = ['pam']
__version__  = '1.8.5rc1'
__author__   = 'David Ford <david@blue-labs.org>'
__released__ = '2019 November 12'

import os
import sys

import PAM


class pam():
    code   = 0
    reason = None

    def __init__(self):
        pass

    def authenticate(self, username, password, service='login', encoding='utf-8', resetcreds=True):
        """username and password authentication for the given service.

           Returns True for success, or False for failure.

           self.code (integer) and self.reason (string) are always stored and may
           be referenced for the reason why authentication failed. 0/'Success' will
           be stored for success.

           Python3 expects bytes() for ctypes inputs.  This function will make
           necessary conversions using the supplied encoding.

        Inputs:
          username: username to authenticate
          password: password in plain text
          service:  PAM service to authenticate against, defaults to 'login'

        Returns:
          success:  True
          failure:  False
        """

        # python3 ctypes prefers bytes
        if sys.version_info >= (3,):
            if isinstance(username, str): username = username.encode(encoding)
            if isinstance(password, str): password = password.encode(encoding)
            if isinstance(service, str):  service  = service.encode(encoding)
        else:
            if isinstance(username, unicode):
                username = username.encode(encoding)
            if isinstance(password, unicode):
                password = password.encode(encoding)
            if isinstance(service, unicode):
                service  = service.encode(encoding)

        def conv(pam_self, query_list, user_data):
            response = []
            for prompt, msg in query_list:
                if msg == PAM.PAM_PROMPT_ECHO_OFF:
                    response.append((password, PAM.PAM_SUCCESS))
                else:
                    response.append((b'', PAM.PAM_SUCCESS))
            return response

        # if X DISPLAY is set, use it, otherwise get the STDIN tty
        ctty = os.environ.get('DISPLAY', os.ttyname(0)).encode(encoding)

        p = PAM.pam()
        try:
            p.start(service, username, conv)
        except PAM.error as exc:
            # This is not an authentication error, something has gone wrong starting up PAM
            self.code   = exc.errno
            self.reason = "pam_start() failed"
            return False

        # set the TTY, needed when pam_securetty is used and the username root is used
        p.set_item(PAM.PAM_TTY, ctty)
        try:
            p.authenticate()
            p.acct_mgmt()
            if resetcreds:
                p.setcred(PAM.PAM_REINITIALIZE_CRED)
        except PAM.error as exc:
            self.code   = exc.errno
            self.reason = exc.args[0]
        else:
            self.code = PAM.PAM_SUCCESS
            self.reason = b'Success'
        finally:
            p.end()
        if sys.version_info >= (3,):
            self.reason = self.reason.decode(encoding)
        return self.code == PAM.PAM_SUCCESS


def authenticate(*vargs, **dargs):
    """
    Compatibility function for older versions of python-pam.
    """
    return pam().authenticate(*vargs, **dargs)


if __name__ == "__main__":
    import readline, getpass

    def input_with_prefill(prompt, text):
        def hook():
            readline.insert_text(text)
            readline.redisplay()
        readline.set_pre_input_hook(hook)

        if sys.version_info >= (3,):
            result = input(prompt)
        else:
            result = raw_input(prompt)

        readline.set_pre_input_hook()
        return result

    pam = pam()

    username = input_with_prefill('Username: ', getpass.getuser())

    # enter a valid username and an invalid/valid password, to verify both failure and success
    pam.authenticate(username, getpass.getpass())
    print('{} {}'.format(pam.code, pam.reason))
