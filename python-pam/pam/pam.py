# Now owned and maintained by David Ford, <david.ford@blue-labs.org>
#
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

This is a legacy file, it is not used. Here for example.

Provides an authenticate function that will allow the caller to authenticate
a user against the Pluggable Authentication Modules (PAM) on the system.

Implemented using ctypes, so no compilation is necessary.
'''

from . import __internals

if __name__ == "__main__":  # pragma: no cover
    import readline
    import getpass

    def input_with_prefill(prompt, text):
        """Input function with prefilled text."""
        def hook():
            readline.insert_text(text)
            readline.redisplay()

        readline.set_pre_input_hook(hook)
        user_input = input(prompt)  # nosec (bandit; python2)

        readline.set_pre_input_hook()

        return user_input

    __pam = __internals.PamAuthenticator()

    username = input_with_prefill('Username: ', getpass.getuser())

    # enter a valid username and an invalid/valid password, to verify both
    # failure and success
    result = __pam.authenticate(username, getpass.getpass(),
                                env={"XDG_SEAT": "seat0"},
                                call_end=False)
    reason_str = __pam.reason if isinstance(__pam.reason, str) else str(__pam.reason)
    print(f'Auth result: {reason_str} ({__pam.code})')

    env_list = __pam.getenvlist()
    if isinstance(env_list, dict):
        for key, value in env_list.items():
            print(f"Pam Environment List item: {key}={value}")

    key = "XDG_SEAT"
    env_value = __pam.getenv(key)
    if env_value is not None:
        print(f"Pam Environment item: {key}={env_value}")
    else:
        print(f"Pam Environment item: {key}=None")

    if __pam.code == __internals.PAM_SUCCESS:
        session_result = __pam.open_session()
        session_reason = __pam.reason if isinstance(__pam.reason, str) else str(__pam.reason)
        print(f'Open session: {session_reason} ({__pam.code})')

        if __pam.code == __internals.PAM_SUCCESS:
            close_result = __pam.close_session()
            close_reason = __pam.reason if isinstance(__pam.reason, str) else str(__pam.reason)
            print(f'Close session: {close_reason} ({__pam.code})')

        else:
            __pam.end()
    else:
        __pam.end()
