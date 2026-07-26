"""Internal PAM implementation using ctypes.

This module provides the low-level interface to Linux-PAM using ctypes,
including structure definitions, constants, and the PamAuthenticator class.
"""
import os
import sys
from ctypes import (
    CDLL,
    CFUNCTYPE,
    POINTER,
    Structure,
    byref,
    c_char,
    c_char_p,
    c_int,
    c_size_t,
    c_void_p,
    cast,
    cdll,
    memmove,
    py_object,
    sizeof,
)
from typing import Any
from ctypes.util import find_library

PAM_ABORT = 26
PAM_ACCT_EXPIRED = 13
PAM_AUTHINFO_UNAVAIL = 9
PAM_AUTHTOK_DISABLE_AGING = 23
PAM_AUTHTOK_ERR = 20
PAM_AUTHTOK_EXPIRED = 27
PAM_AUTHTOK_LOCK_BUSY = 22
PAM_AUTHTOK_RECOVER_ERR = 21
PAM_AUTH_ERR = 7
PAM_BAD_ITEM = 29
PAM_BUF_ERR = 5
PAM_CHANGE_EXPIRED_AUTHTOK = 32
PAM_CONV = 5
PAM_CONV_ERR = 19
PAM_CRED_ERR = 17
PAM_CRED_EXPIRED = 16
PAM_CRED_INSUFFICIENT = 8
PAM_CRED_UNAVAIL = 15
PAM_DATA_SILENT = 1073741824
PAM_DELETE_CRED = 4
PAM_DISALLOW_NULL_AUTHTOK = 1
PAM_ERROR_MSG = 3
PAM_ESTABLISH_CRED = 2
PAM_IGNORE = 25
PAM_MAXTRIES = 11
PAM_MODULE_UNKNOWN = 28
PAM_NEW_AUTHTOK_REQD = 12
PAM_NO_MODULE_DATA = 18
PAM_OPEN_ERR = 1
PAM_PERM_DENIED = 6
PAM_PROMPT_ECHO_OFF = 1
PAM_PROMPT_ECHO_ON = 2
PAM_REFRESH_CRED = 16
PAM_REINITIALIZE_CRED = 8
PAM_RHOST = 4
PAM_RUSER = 8
PAM_SERVICE = 1
PAM_SERVICE_ERR = 3
PAM_SESSION_ERR = 14
PAM_SILENT = 32768
PAM_SUCCESS = 0
PAM_SYMBOL_ERR = 2
PAM_SYSTEM_ERR = 4
PAM_TEXT_INFO = 4
PAM_TRY_AGAIN = 24
PAM_TTY = 3
PAM_USER = 2
PAM_USER_PROMPT = 9
PAM_USER_UNKNOWN = 10
PAM_XDISPLAY = 11


__all__ = ('PAM_ABORT', 'PAM_ACCT_EXPIRED', 'PAM_AUTHINFO_UNAVAIL',
           'PAM_AUTHTOK_DISABLE_AGING', 'PAM_AUTHTOK_ERR',
           'PAM_AUTHTOK_EXPIRED', 'PAM_AUTHTOK_LOCK_BUSY',
           'PAM_AUTHTOK_RECOVER_ERR', 'PAM_AUTH_ERR', 'PAM_BAD_ITEM',
           'PAM_BUF_ERR', 'PAM_CHANGE_EXPIRED_AUTHTOK', 'PAM_CONV',
           'PAM_CONV_ERR', 'PAM_CRED_ERR', 'PAM_CRED_EXPIRED',
           'PAM_CRED_INSUFFICIENT', 'PAM_CRED_UNAVAIL', 'PAM_DATA_SILENT',
           'PAM_DELETE_CRED', 'PAM_DISALLOW_NULL_AUTHTOK', 'PAM_ERROR_MSG',
           'PAM_ESTABLISH_CRED', 'PAM_IGNORE', 'PAM_MAXTRIES',
           'PAM_MODULE_UNKNOWN', 'PAM_NEW_AUTHTOK_REQD', 'PAM_NO_MODULE_DATA',
           'PAM_OPEN_ERR', 'PAM_PERM_DENIED', 'PAM_PROMPT_ECHO_OFF',
           'PAM_PROMPT_ECHO_ON', 'PAM_REFRESH_CRED', 'PAM_REINITIALIZE_CRED',
           'PAM_RHOST', 'PAM_RUSER', 'PAM_SERVICE', 'PAM_SERVICE_ERR',
           'PAM_SESSION_ERR', 'PAM_SILENT', 'PAM_SUCCESS', 'PAM_SYMBOL_ERR',
           'PAM_SYSTEM_ERR', 'PAM_TEXT_INFO', 'PAM_TRY_AGAIN', 'PAM_TTY',
           'PAM_USER', 'PAM_USER_PROMPT', 'PAM_USER_UNKNOWN',
           'PamAuthenticator')


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
        return f"<PamMessage style: {self.msg_style}, content: {self.msg} >"


class PamResponse(Structure):
    """wrapper class for pam_response structure"""
    _fields_ = [("resp", c_char_p), ("resp_retcode", c_int)]

    def __repr__(self):
        return f"<PamResponse code: {self.resp_retcode}, content: {self.resp} >"


conv_func = CFUNCTYPE(c_int,
                      c_int,
                      POINTER(POINTER(PamMessage)),
                      POINTER(POINTER(PamResponse)),
                      c_void_p)


def my_conv(
    n_messages: int,
    messages: Any,  # POINTER(POINTER(PamMessage)) - ctypes types not supported by mypy
    p_response: Any,  # POINTER(POINTER(PamResponse)) - ctypes types not supported by mypy
    libc: Any,
    msg_list: list[str],
    password: bytes,
    encoding: str,
) -> int:
    """Simple conversation function that responds to any
       prompt where the echo is off with the supplied password"""
    # Create an array of n_messages response objects
    calloc = libc.calloc
    calloc.restype = c_void_p
    calloc.argtypes = [c_size_t, c_size_t]

    cpassword = c_char_p(password)

    # PAM_PROMPT_ECHO_OFF = 1
    # PAM_PROMPT_ECHO_ON = 2
    # PAM_ERROR_MSG = 3
    # PAM_TEXT_INFO = 4

    addr = calloc(n_messages, sizeof(PamResponse))
    response = cast(addr, POINTER(PamResponse))
    p_response[0] = response

    for i in range(n_messages):
        message = messages[i].contents.msg
        if sys.version_info >= (3,):  # pragma: no branch
            message = message.decode(encoding)

        msg_list.append(message)

        if messages[i].contents.msg_style == PAM_PROMPT_ECHO_OFF:
            if i == 0:
                dst = calloc(len(password)+1, sizeof(c_char))
                memmove(dst, cpassword, len(password))
                response[i].resp = dst
            else:
                # void out the message
                response[i].resp = None

            response[i].resp_retcode = 0

    return PAM_SUCCESS


class PamConv(Structure):
    """wrapper class for pam_conv structure"""
    _fields_ = [("conv", conv_func), ("appdata_ptr", c_void_p)]


class PamAuthenticator:
    """PAM authenticator class.

    This class provides methods to authenticate users against Linux-PAM,
    manage PAM sessions, and handle PAM environment variables.
    """
    code: int = 0
    reason: str | bytes | None = None

    def __init__(self):
        # use a trick of dlopen(), this effectively becomes
        # dlopen("", ...) which opens our own executable. since 'python' has
        # a libc dependency, this means libc symbols are already available
        # to us

        # libc = CDLL(find_library("c"))
        libc = cdll.LoadLibrary(None)  # type: ignore[arg-type]
        self.libc = libc

        libpam = CDLL(find_library("pam"))
        libpam_misc = CDLL(find_library("pam_misc"))

        self.handle: PamHandle | None = None
        self.messages: list[str] = []

        self.calloc = libc.calloc
        self.calloc.restype = c_void_p
        self.calloc.argtypes = [c_size_t, c_size_t]

        # bug #6 (@NIPE-SYSTEMS), some libpam versions don't include this
        # function
        if hasattr(libpam, 'pam_end'):  # pragma: no branch
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

        if libpam_misc._name:  # pragma: no branch
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
        username: str | bytes,
        password: str | bytes,
        service: str | bytes = 'login',
        env: dict[str, str] | None = None,
        call_end: bool = True,
        encoding: str = 'utf-8',
        resetcreds: bool = True,
        print_failure_messages: bool = False,
    ) -> bool:
        """username and password authentication for the given service.

        Returns True for success, or False for failure.

        self.code (integer) and self.reason (string) are always stored and may
        be referenced for the reason why authentication failed. 0/'Success'
        will be stored for success.

        Python3 expects bytes() for ctypes inputs.  This function will make
        necessary conversions using the supplied encoding.

        Args:
          username (str): username to authenticate
          password (str): password in plain text
          service (str):  PAM service to authenticate against, defaults to 'login'
          env (dict):      Pam environment variables
          call_end (bool): call the pam_end() function after (default true)
          print_failure_messages (bool): Print messages on failure

        Returns:
          success:  PAM_SUCCESS
          failure:  False
        """

        @conv_func
        def __conv(n_messages, messages, p_response, app_data):
            pyob = cast(app_data, py_object).value

            msg_list = pyob.get('msgs')
            password = pyob.get('password')
            encoding = pyob.get('encoding')

            return my_conv(n_messages, messages, p_response, self.libc, msg_list, password, encoding)

        if isinstance(username, str):
            username = username.encode(encoding)
        if isinstance(password, str):
            password = password.encode(encoding)
        if isinstance(service, str):
            service = service.encode(encoding)

        if b'\x00' in username or b'\x00' in password or b'\x00' in service:
            self.code = PAM_SYSTEM_ERR
            self.reason = ('none of username, password, or service may contain'
                           ' NUL')
            raise ValueError(self.reason)

        # do this up front so we can safely throw an exception if there's
        # anything wrong with it
        app_data = {'msgs': self.messages, 'password': password, 'encoding': encoding}
        conv = PamConv(__conv, c_void_p.from_buffer(py_object(app_data)))

        self.handle = PamHandle()
        retval = self.pam_start(service, username, byref(conv),
                                byref(self.handle))

        if retval != PAM_SUCCESS:  # pragma: no cover
            # This is not an authentication error, something has gone wrong
            # starting up PAM
            self.code = retval
            self.reason = f"pam_start() failed: {self.pam_strerror(self.handle, retval)}"
            self.handle = None
            return False

        # Verify handle was properly initialized by pam_start
        if self.handle is None or self.handle.handle == 0:
            self.code = PAM_SYSTEM_ERR
            self.reason = "pam_start() succeeded but handle was not properly initialized"
            self.handle = None
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

        # ctty can be invalid if no tty is being used
        if ctty:  # pragma: no branch (we don't test a void tty yet)
            ctty_p = c_char_p(ctty.encode(encoding))

            retval = self.pam_set_item(self.handle, PAM_TTY, ctty_p)
            retval = self.pam_set_item(self.handle, PAM_XDISPLAY, ctty_p)

        # Set the environment variables if they were supplied
        if env:
            if not isinstance(env, dict):
                raise TypeError('"env" must be a dict')

            # Ensure handle is still valid before setting environment variables
            if self.handle is None or self.handle.handle == 0:
                self.code = PAM_SYSTEM_ERR
                self.reason = "PAM handle became invalid before setting environment variables"
                return False

            for key, value in env.items():
                if isinstance(key, bytes) and b'\x00' in key:
                    raise ValueError('"env{}" key cannot contain NULLs')
                if isinstance(value, bytes) and b'\x00' in value:
                    raise ValueError('"env{}" value cannot contain NULLs')

                name_value = f"{key}={value}"
                retval = self.putenv(name_value, encoding)

        # Ensure handle is still valid before authentication
        if self.handle is None or self.handle.handle == 0:
            self.code = PAM_SYSTEM_ERR
            self.reason = "PAM handle became invalid before authentication"
            return False

        auth_success = self.pam_authenticate(self.handle, 0)

        if auth_success == PAM_SUCCESS:
            # Ensure handle is still valid before account management
            if self.handle is None or self.handle.handle == 0:
                self.code = PAM_SYSTEM_ERR
                self.reason = "PAM handle became invalid before account management"
                return False
            auth_success = self.pam_acct_mgmt(self.handle, 0)

        if auth_success == PAM_SUCCESS and resetcreds:
            # Ensure handle is still valid before setting credentials
            if self.handle is None or self.handle.handle == 0:
                self.code = PAM_SYSTEM_ERR
                self.reason = "PAM handle became invalid before setting credentials"
                return False
            auth_success = self.pam_setcred(self.handle, PAM_REINITIALIZE_CRED)

        # store information to inform the caller why we failed
        self.code = auth_success
        # Ensure handle is still valid before getting error message
        if self.handle is not None and self.handle.handle != 0:
            reason_bytes = self.pam_strerror(self.handle, auth_success)
            if sys.version_info >= (3,):  # pragma: no branch (we don't test non-py3 versions)
                self.reason = reason_bytes.decode(encoding)
            else:
                self.reason = reason_bytes  # type: ignore[assignment]
        else:
            self.reason = f"PAM error {auth_success} (handle invalid)"

        if call_end and hasattr(self, 'pam_end'):  # pragma: no branch
            self.pam_end(self.handle, auth_success)
            self.handle = None

        if print_failure_messages and self.code != PAM_SUCCESS:  # pragma: no cover
            reason_str = self.reason if isinstance(self.reason, str) else str(self.reason)
            print(f"Failure: {reason_str}")

        return bool(auth_success == PAM_SUCCESS)

    def end(self) -> int:
        """A direct call to pam_end()
        Returns:
          Linux-PAM return value as int
        """
        if not self.handle or not hasattr(self, 'pam_end'):
            return PAM_SYSTEM_ERR

        retval = self.pam_end(self.handle, self.code)
        self.handle = None

        return int(retval)

    def open_session(self, encoding: str = 'utf-8') -> int:
        """Call pam_open_session as required by the pam_api
        Returns:
          Linux-PAM return value as int
        """
        if not self.handle:
            return PAM_SYSTEM_ERR

        retval = self.pam_open_session(self.handle, 0)
        self.code = retval
        reason_bytes = self.pam_strerror(self.handle, retval)
        if sys.version_info >= (3,):  # pragma: no branch
            self.reason = reason_bytes.decode(encoding)
        else:
            self.reason = reason_bytes  # type: ignore[assignment]

        return int(retval)

    def close_session(self, encoding: str = 'utf-8') -> int:
        """Call pam_close_session as required by the pam_api
        Returns:
          Linux-PAM return value as int
        """
        if not self.handle:
            return PAM_SYSTEM_ERR

        retval = self.pam_close_session(self.handle, 0)
        self.code = retval
        reason_bytes = self.pam_strerror(self.handle, retval)
        if sys.version_info >= (3,):  # pragma: no branch
            self.reason = reason_bytes.decode(encoding)
        else:
            self.reason = reason_bytes  # type: ignore[assignment]

        return int(retval)

    def misc_setenv(self, name: str, value: str, readonly: int, encoding: str = 'utf-8') -> int:
        """A wrapper for the pam_misc_setenv function
        Args:
          name: key name of the environment variable
          value: the value of the environment variable
        Returns:
          Linux-PAM return value as int
        """
        if not self.handle or not hasattr(self, "pam_misc_setenv"):
            return PAM_SYSTEM_ERR

        retval = self.pam_misc_setenv(self.handle,
                                      name.encode(encoding),
                                      value.encode(encoding),
                                      readonly)
        return int(retval)

    def putenv(self, name_value: str, encoding: str = 'utf-8') -> int:
        """A wrapper for the pam_putenv function
        Args:
          name_value: environment variable in the format KEY=VALUE
                      Without an '=' delete the corresponding variable
        Returns:
          Linux-PAM return value as int
        """
        if not self.handle:
            return PAM_SYSTEM_ERR

        name_value_bytes = name_value.encode(encoding)

        retval = self.pam_putenv(self.handle, name_value_bytes)
        if retval != PAM_SUCCESS:
            error_msg_bytes = self.pam_strerror(self.handle, retval)
            if sys.version_info >= (3,):  # pragma: no branch
                error_msg = error_msg_bytes.decode(encoding)
            else:
                error_msg = error_msg_bytes  # type: ignore[assignment]
            raise RuntimeError(error_msg)

        return int(retval)

    def getenv(self, key: str | bytes, encoding: str = 'utf-8') -> str | None | int:
        """A wrapper for the pam_getenv function
        Args:
          key name of the environment variable
        Returns:
          value of the environment variable, None on error, or PAM_SYSTEM_ERR if handle is invalid
        """
        if not self.handle:
            return PAM_SYSTEM_ERR

        #  can't happen unless someone is using internals directly
        if isinstance(key, str):  # pragma: no branch
            key = key.encode(encoding)

        value = self.pam_getenv(self.handle, key)

        if isinstance(value, type(None)):
            return None

        if isinstance(value, int):  # pragma: no cover
            error_msg = self.pam_strerror(self.handle, value)
            if sys.version_info >= (3,):  # pragma: no branch
                error_msg = error_msg.decode(encoding)
            raise RuntimeError(error_msg)

        if sys.version_info >= (3,):  # pragma: no branch
            if isinstance(value, bytes):
                return value.decode(encoding)
            # value is c_char_p which is bytes-like, but mypy doesn't know
            # c_char_p can be None, bytes, or int, but in practice it's bytes here
            # We've already checked for None and bytes, so this should be safe
            # At this point value should be bytes (c_char_p), but mypy sees it as Any
            # Since we've checked for None and bytes, the remaining case is safe
            return str(value)
        # Python 2 path (not tested) - value is bytes in py2
        # This path is never executed in Python 3, so mypy doesn't see the error
        return str(value)

    def getenvlist(self, encoding: str = 'utf-8') -> dict[str, str] | int:
        """A wrapper for the pam_getenvlist function
        Returns:
          environment as python dictionary, or PAM_SYSTEM_ERR if handle is invalid
        """
        if not self.handle:
            return PAM_SYSTEM_ERR

        env_list = self.pam_getenvlist(self.handle)

        env_count = 0
        pam_env_items = {}

        while True:
            try:
                item = env_list[env_count]
            except IndexError:  # pragma: no cover
                break

            if not item:
                # end of the list
                break

            env_item = item
            if sys.version_info >= (3,):  # pragma: no branch
                env_item = env_item.decode(encoding)

            try:
                pam_key, pam_value = env_item.split("=", 1)
            except ValueError:  # pragma: no cover
                # Incorrectly formatted envlist item
                pass
            else:
                pam_env_items[pam_key] = pam_value

            env_count += 1

        return pam_env_items
