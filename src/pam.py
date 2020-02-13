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

import os
import sys
import six

from ctypes import CDLL, POINTER, Structure, CFUNCTYPE, cast, byref, sizeof
from ctypes import c_void_p, c_size_t, c_char_p, c_char, c_int
from ctypes import memmove
from ctypes.util import find_library

__all__ = ['pam']
__version__ = '1.8.5rc2'
__author__ = 'David Ford <david@blue-labs.org>'
__released__ = '2019 November 14'

if sys.version_info < (3, ):
    print('WARNING, Python 2 is EOL and therefore py2 support in this '
          "package is deprecated. It won't be actively checked for"
          'correctness')


# Various constants
PAM_PROMPT_ECHO_OFF = 1
PAM_PROMPT_ECHO_ON = 2
PAM_ERROR_MSG = 3
PAM_TEXT_INFO = 4
PAM_REINITIALIZE_CRED = 8

# Linux-PAM item types
PAM_TTY = 3
PAM_XDISPLAY = 11

# Linux-PAM return values
PAM_SUCCESS = 0
PAM_SYSTEM_ERR = 4


class PamHandle(Structure):
    """wrapper class for pam_handle_t pointer"""
    _fields_ = [("handle", c_void_p)]

    def __init__(self):
        super().__init__()
        self.handle = 0

    def __repr__(self):
        return f"<PamHandle {self.handle}>"


class PamMessage(Structure):
    """wrapper class for pam_message structure"""
    _fields_ = [("msg_style", c_int), ("msg", c_char_p)]

    def __repr__(self):
        return "<PamMessage %i '%s'>" % (self.msg_style, self.msg)


class PamResponse(Structure):
    """wrapper class for pam_response structure"""
    _fields_ = [("resp", c_char_p), ("resp_retcode", c_int)]

    def __repr__(self):
        return "<PamResponse %i '%s'>" % (self.resp_retcode, self.resp)


conv_func = CFUNCTYPE(c_int, c_int, POINTER(POINTER(PamMessage)),
                      POINTER(POINTER(PamResponse)), c_void_p)


class PamConv(Structure):
    """wrapper class for pam_conv structure"""
    _fields_ = [("conv", conv_func), ("appdata_ptr", c_void_p)]


class PamAuthenticator:
    code = 0
    reason = None

    def __init__(self):
        libc = CDLL(find_library("c"))
        libpam = CDLL(find_library("pam"))
        libpam_misc = CDLL(find_library("pam_misc"))

        self.handle = None
        self.messages = []

        self.calloc = libc.calloc
        self.calloc.restype = c_void_p
        self.calloc.argtypes = [c_size_t, c_size_t]

        # bug #6 (@NIPE-SYSTEMS), some libpam versions don't include this
        # function
        if hasattr(libpam, 'pam_end'):
            self.pam_end = libpam.pam_end
            self.pam_end.restype = c_int
            self.pam_end.argtypes = [PamHandle, c_int]

        self.pam_start = libpam.pam_start
        self.pam_start.restype = c_int
        self.pam_start.argtypes = [c_char_p, c_char_p, POINTER(PamConv),
                                   POINTER(PamHandle)]

        self.pam_acct_mgmt = libpam.pam_acct_mgmt
        self.pam_acct_mgmt.restype = c_int
        self.pam_acct_mgmt.argtypes = [PamHandle, c_int]

        self.pam_set_item = libpam.pam_set_item
        self.pam_set_item.restype = c_int
        self.pam_set_item.argtypes = [PamHandle, c_int, c_void_p]

        self.pam_setcred = libpam.pam_setcred
        self.pam_strerror = libpam.pam_strerror
        self.pam_strerror.restype = c_char_p
        self.pam_strerror.argtypes = [PamHandle, c_int]

        self.pam_authenticate = libpam.pam_authenticate
        self.pam_authenticate.restype = c_int
        self.pam_authenticate.argtypes = [PamHandle, c_int]

        self.pam_open_session = libpam.pam_open_session
        self.pam_open_session.restype = c_int
        self.pam_open_session.argtypes = [PamHandle, c_int]

        self.pam_close_session = libpam.pam_close_session
        self.pam_close_session.restype = c_int
        self.pam_close_session.argtypes = [PamHandle, c_int]

        self.pam_putenv = libpam.pam_putenv
        self.pam_putenv.restype = c_int
        self.pam_putenv.argtypes = [PamHandle, c_char_p]

        if libpam_misc._name:
            self.pam_misc_setenv = libpam_misc.pam_misc_setenv
            self.pam_misc_setenv.restype = c_int
            self.pam_misc_setenv.argtypes = [PamHandle, c_char_p, c_char_p,
                                             c_int]

        self.pam_getenv = libpam.pam_getenv
        self.pam_getenv.restype = c_char_p
        self.pam_getenv.argtypes = [PamHandle, c_char_p]

        self.pam_getenvlist = libpam.pam_getenvlist
        self.pam_getenvlist.restype = POINTER(c_char_p)
        self.pam_getenvlist.argtypes = [PamHandle]

    def authenticate(
                self,
                username,
                password,
                service='login',
                env=None,
                call_end=True,
                encoding='utf-8',
                resetcreds=True):
        authenticate.__annotations = {'username': str,
                                      'password': str,
                                      'service': str,
                                      'env': dict,
                                      'call_end': bool,
                                      'encoding': str,
                                      'resetcreds': bool,
                                      'return': bool}
        """username and password authentication for the given service.

        Returns True for success, or False for failure.

        self.code (integer) and self.reason (string) are always stored and may
        be referenced for the reason why authentication failed. 0/'Success'
        will be stored for success.

        Python3 expects bytes() for ctypes inputs.  This function will make
        necessary conversions using the supplied encoding.

        Args:
          username: username to authenticate
          password: password in plain text
          service:  PAM service to authenticate against, defaults to 'login'
          env:      Pam environment variables
          call_end: call the pam_end() function after (default true)

        Returns:
          success:  True
          failure:  False
        """

        @conv_func
        def my_conv(n_messages, messages, p_response, app_data):
            """Simple conversation function that responds to any
               prompt where the echo is off with the supplied password"""
            # Create an array of n_messages response objects
            addr = self.calloc(n_messages, sizeof(PamResponse))
            response = cast(addr, POINTER(PamResponse))
            p_response[0] = response
            for i in range(n_messages):
                if sys.version_info >= (3,):
                    message = messages[i].contents.msg.decode(encoding)
                else:
                    message = messages[i].contents.msg
                self.messages.append(message)
                if messages[i].contents.msg_style == PAM_PROMPT_ECHO_OFF:
                    dst = self.calloc(len(password)+1, sizeof(c_char))
                    memmove(dst, cpassword, len(password))
                    response[i].resp = dst
                    response[i].resp_retcode = 0
            return 0

        # python3 ctypes prefers bytes
        if sys.version_info >= (3, ):
            if isinstance(username, str):
                username = username.encode(encoding)
            if isinstance(password, str):
                password = password.encode(encoding)
            if isinstance(service, str):
                service = service.encode(encoding)

        else:  # py2
            if isinstance(username, six.text_type):
                username = username.encode(encoding)
            if isinstance(password, six.text_type):
                password = password.encode(encoding)
            if isinstance(service, six.text_type):
                service = service.encode(encoding)

        if b'\x00' in username or b'\x00' in password or b'\x00' in service:
            self.code = PAM_SYSTEM_ERR
            self.reason = 'strings may not contain NUL'
            return False

        # do this up front so we can safely throw an exception if there's
        # anything wrong with it
        cpassword = c_char_p(password)

        self.handle = PamHandle()
        conv = PamConv(my_conv, 0)
        retval = self.pam_start(service, username, byref(conv),
                                byref(self.handle))

        if retval != 0:
            # This is not an authentication error, something has gone wrong
            # starting up PAM
            self.code = retval
            self.reason = "pam_start() failed"
            return False

        # set the TTY, required when pam_securetty is used and the username
        # root is used note: this is only needed WHEN the pam_securetty.so
        # module is used; for checking /etc/securetty for allowing root
        # logins.  if your application doesn't use a TTY or your pam setup
        # doesn't involve pam_securetty for this auth path, don't worry
        # about it
        #
        # if your app isn't authenticating root with the right password, you
        # may not have the appropriate list of TTYs in /etc/securetty and/or
        # the correct configuration in /etc/pam.d/*
        #
        # if X $DISPLAY is set, use it - otherwise if we have a STDIN tty,
        # get it

        ctty = os.environ.get('DISPLAY')
        if not ctty and os.isatty(0):
            ctty = os.ttyname(0)
        if ctty:
            ctty = c_char_p(ctty.encode(encoding))

            self.pam_set_item(self.handle, PAM_TTY, ctty)
            self.pam_set_item(self.handle, PAM_XDISPLAY, ctty)

        # Set the environment variables if they were supplied
        if env and isinstance(env, dict):
            for key, value in env.items():
                name_value = "{}={}".format(key, value)
                self.putenv(name_value, encoding)

        retval = self.pam_authenticate(self.handle, 0)
        auth_success = retval == 0

        if auth_success:
            retval = self.pam_acct_mgmt(self.handle, 0)
            auth_success = retval == 0

        if auth_success and resetcreds:
            retval = self.pam_setcred(self.handle, PAM_REINITIALIZE_CRED)

        # store information to inform the caller why we failed
        self.code = retval
        self.reason = self.pam_strerror(self.handle, retval)
        if sys.version_info >= (3,):
            self.reason = self.reason.decode(encoding)

        if call_end and hasattr(self, 'pam_end'):
            self.pam_end(self.handle, retval)
            self.handle = None

        return auth_success

    def end(self):
        """A direct call to pam_end()

        Returns: Linux-PAM return value as int

        """
        if not self.handle or not hasattr(self, 'pam_end'):
            return PAM_SYSTEM_ERR
        retval = self.pam_end(self.handle, self.code)
        self.handle = None
        return retval

    def open_session(self, encoding='utf-8'):
        """Call pam_open_session as required by the pam_api

        Returns: Linux-PAM return value as int

        """
        if not self.handle:
            return PAM_SYSTEM_ERR

        retval = self.pam_open_session(self.handle, 0)
        self.code = retval
        self.reason = self.pam_strerror(self.handle, retval)
        if sys.version_info >= (3,):
            self.reason = self.reason.decode(encoding)
        return retval

    def close_session(self, encoding='utf-8'):
        """Call pam_close_session as required by the pam_api
        Returns:
          Linux-PAM return value as int
        """
        if not self.handle:
            return PAM_SYSTEM_ERR

        retval = self.pam_close_session(self.handle, 0)
        self.code = retval
        self.reason = self.pam_strerror(self.handle, retval)
        if sys.version_info >= (3,):
            self.reason = self.reason.decode(encoding)

        return retval

    def misc_setenv(self, name, value, readonly, encoding='utf-8'):
        """A wrapper for the pam_misc_setenv function
        Args:
          name: key name of the environment variable
          value: the value of the environment variable
        Returns:
          Linux-PAM return value as int
        """
        if not self.handle or not hasattr(self, "pam_misc_setenv"):
            return PAM_SYSTEM_ERR

        return self.pam_misc_setenv(self.handle,
                                    name.encode(encoding),
                                    value.encode(encoding),
                                    readonly)

    def putenv(self, name_value, encoding='utf-8'):
        """A wrapper for the pam_putenv function
        Args:
          name_value: environment variable in the format KEY=VALUE
                      Without an '=' delete the corresponding variable

        Returns:
          Linux-PAM return value as int
        """
        if not self.handle:
            return PAM_SYSTEM_ERR

        return self.pam_putenv(self.handle,
                               name_value.encode(encoding))

    def getenv(self, key, encoding='utf-8'):
        """A wrapper for the pam_getenv function
        Args:
          key name of the environment variable
        Returns:
          value of the environment variable or None on error
        """
        if not self.handle:
            return PAM_SYSTEM_ERR
        if sys.version_info >= (3, ):
            if isinstance(key, str):
                key = key.encode(encoding)
        else:
            if isinstance(key, six.text_type):
                key = key.encode(encoding)
        value = self.pam_getenv(self.handle, key)
        if isinstance(value, type(None)):
            return None
        if sys.version_info >= (3,):
            value = value.decode(encoding)
        return value

    def getenvlist(self, encoding='utf-8'):
        """A wrapper for the pam_getenvlist function
        Returns:
          environment as python dictionary
        """
        if not self.handle:
            return PAM_SYSTEM_ERR

        env_list = self.pam_getenvlist(self.handle)

        env_count = 0
        pam_env_items = {}
        while True:
            try:
                item = env_list[env_count]
            except IndexError:
                break
            if not item:
                # end of the list
                break
            if sys.version_info >= (3,):
                env_item = item.decode(encoding)
            else:
                env_item = item
            try:
                pam_key, pam_value = env_item.split("=", 1)
            except ValueError:
                # Incorrectly formatted envlist item
                pass
            else:
                pam_env_items[pam_key] = pam_value
            env_count += 1

        return pam_env_items


# legacy due to bad naming conventions
pam = PamAuthenticator


def authenticate(*vargs, **dargs):
    """
    Compatibility function for older versions of python-pam.
    """
    return PamAuthenticator().authenticate(*vargs, **dargs)


if __name__ == "__main__":
    import readline
    import getpass

    def input_with_prefill(prompt, text):
        def hook():
            readline.insert_text(text)
            readline.redisplay()

        readline.set_pre_input_hook(hook)

        if sys.version_info >= (3,):
            result = input(prompt)  # nosec (bandit; python2)
        else:
            result = raw_input(prompt)  # noqa:F821

        readline.set_pre_input_hook()

        return result

    pam = PamAuthenticator()

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

    if pam.code == PAM_SUCCESS:
        result = pam.open_session()
        print('Open session: {} ({})'.format(pam.reason, pam.code))
        if pam.code == PAM_SUCCESS:
            result = pam.close_session()
            print('Close session: {} ({})'.format(pam.reason, pam.code))
        else:
            pam.end()
    else:
        pam.end()
