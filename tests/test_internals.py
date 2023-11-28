import os
import pytest
# from pytest import monkeypatch

from ctypes import cdll
from ctypes import c_void_p
from ctypes import pointer

from pam.__internals import PAM_SYSTEM_ERR
from pam.__internals import PAM_SUCCESS
from pam.__internals import PAM_SESSION_ERR
from pam.__internals import PAM_AUTH_ERR
from pam.__internals import PAM_USER_UNKNOWN
from pam.__internals import PAM_PROMPT_ECHO_OFF
from pam.__internals import PAM_PROMPT_ECHO_ON
from pam.__internals import PamConv
from pam.__internals import PamHandle
from pam.__internals import PamMessage
from pam.__internals import PamResponse
from pam.__internals import PamAuthenticator
from pam.__internals import my_conv


class MockPam:
    def __init__(self, og):
        self.og = og
        self.og_pam_start = og.pam_start
        self.PA_authenticate = og.authenticate
        self.username = None
        self.password = None

    def authenticate(self, *args, **kwargs):
        if len(args) > 0:
            self.username = args[0]
        if len(args) > 1:
            self.password = args[1]
        self.service = kwargs.get('service')
        return self.PA_authenticate(*args, **kwargs)

    def pam_start(self, service, username, conv, handle):
        rv = self.og_pam_start(service, username, conv, handle)
        return rv

    def pam_authenticate(self, handle, flags):
        if isinstance(self.username, str):
            self.username = self.username.encode()
        if isinstance(self.password, str):
            self.password = self.password.encode()

        if self.username == b'good_username' and self.password == b'good_password':
            return PAM_SUCCESS

        if self.username == b'unknown_username':
            return PAM_USER_UNKNOWN

        return PAM_AUTH_ERR

    def pam_acct_mgmt(self, handle, flags):
        # we don't test anything here (yet)
        return PAM_SUCCESS


@pytest.fixture
def pam_obj(request, monkeypatch):
    obj = PamAuthenticator()
    MP = MockPam(obj)
    monkeypatch.setattr(obj, 'authenticate', MP.authenticate)
    monkeypatch.setattr(obj, 'pam_start', MP.pam_start)
    monkeypatch.setattr(obj, 'pam_authenticate', MP.pam_authenticate)
    monkeypatch.setattr(obj, 'pam_acct_mgmt', MP.pam_acct_mgmt)
    yield obj


def test_PamHandle__void0():
    x = PamHandle()
    assert x.handle == c_void_p(0).value


def test_PamHandle__repr():
    x = PamHandle()
    assert '<PamHandle None>' == repr(x)


def test_PamMessage__repr():
    x = PamMessage()
    x.msg_style = 1
    x.msg = b'1'
    str(x)
    assert "<PamMessage style: 1, content: b'1' >" == repr(x)


def test_PamResponse__repr():
    x = PamResponse()
    assert "<PamResponse code: 0, content: None >" == repr(x)


def test_PamAuthenticator__setup():
    x = PamAuthenticator()
    assert hasattr(x, 'reason')


def test_PamAuthenticator__requires_username_password(pam_obj):
    with pytest.raises(TypeError):
        pam_obj.authenticate()


def test_PamAuthenticator__requires_username_no_nulls(pam_obj):
    with pytest.raises(ValueError):
        pam_obj.authenticate(b'username\x00', b'password')


def test_PamAuthenticator__requires_password_no_nulls(pam_obj):
    with pytest.raises(ValueError):
        pam_obj.authenticate(b'username', b'password\x00')


def test_PamAuthenticator__requires_service_no_nulls(pam_obj):
    with pytest.raises(ValueError):
        pam_obj.authenticate(b'username', b'password', b'service\x00')


# TEST_* require a valid account
def test_PamAuthenticator__normal_success(pam_obj):
    rv = pam_obj.authenticate('good_username', 'good_password')
    assert True is rv


def test_PamAuthenticator__normal_password_failure(pam_obj):
    rv = pam_obj.authenticate('good_username', 'bad_password')
    assert False is rv
    assert PAM_AUTH_ERR == pam_obj.code


def test_PamAuthenticator__normal_unknown_username(pam_obj):
    rv = pam_obj.authenticate('unknown_username', '')
    assert False is rv
    assert PAM_USER_UNKNOWN == pam_obj.code


def test_PamAuthenticator__unset_DISPLAY(pam_obj):
    os.environ['DISPLAY'] = ''

    rv = pam_obj.authenticate('good_username', 'good_password')
    assert True is rv
    assert PAM_SUCCESS == pam_obj.code


def test_PamAuthenticator__env_requires_dict(pam_obj):
    with pytest.raises(TypeError):
        pam_obj.authenticate('good_username', 'good_password', env='value')


def test_PamAuthenticator__env_requires_key_no_nulls(pam_obj):
    with pytest.raises(ValueError):
        pam_obj.authenticate('good_username', 'good_password', env={b'\x00invalid_key': b'value'})


def test_PamAuthenticator__env_requires_value_no_nulls(pam_obj):
    with pytest.raises(ValueError):
        pam_obj.authenticate('good_username', 'good_password', env={b'key': b'\x00invalid_value'})


def test_PamAuthenticator__env_set(pam_obj):
    rv = pam_obj.authenticate('good_username', 'good_password', env={'key': b'value'})
    assert True is rv
    assert PAM_SUCCESS == pam_obj.code


def test_PamAuthenticator__putenv_incomplete_setup(pam_obj):
    pam_obj.handle = None
    pam_obj.putenv('NAME=SomeValue')
    rv = pam_obj.getenv('NAME')
    assert PAM_SYSTEM_ERR == rv


def test_PamAuthenticator__putenv(pam_obj):
    pam_obj.handle = PamHandle()
    pam_conv = PamConv()
    pam_obj.pam_start(b'', b'', pam_conv, pam_obj.handle)
    pam_obj.putenv('NAME=SomeValue')
    rv = pam_obj.getenv('NAME')
    assert 'SomeValue' == rv


def test_PamAuthenticator__putenv_bad_key(pam_obj):
    pam_obj.handle = PamHandle()
    pam_conv = PamConv()
    pam_obj.pam_start(b'', b'', pam_conv, pam_obj.handle)
    with pytest.raises(Exception):
        pam_obj.putenv('NAME\0=SomeValue')


def test_PamAuthenticator__putenv_missing_key_delete(pam_obj):
    pam_obj.handle = PamHandle()
    pam_conv = PamConv()
    pam_obj.pam_start(b'', b'', pam_conv, pam_obj.handle)
    with pytest.raises(Exception):
        pam_obj.putenv('NAME')


def test_PamAuthenticator__getenv_missing_key(pam_obj):
    pam_obj.handle = PamHandle()
    pam_conv = PamConv()
    pam_obj.pam_start(b'', b'', pam_conv, pam_obj.handle)
    pam_obj.putenv('NAME=Foo')
    pam_obj.putenv('NAME')
    rv = pam_obj.getenv('NAME')
    assert rv is None


def test_PamAuthenticator__getenv_missing_value(pam_obj):
    pam_obj.handle = PamHandle()
    pam_conv = PamConv()
    pam_obj.pam_start(b'', b'', pam_conv, pam_obj.handle)
    pam_obj.putenv('NAME=')
    rv = pam_obj.getenv('NAME')
    assert '' == rv


def test_PamAuthenticator__getenv(pam_obj):
    pam_obj.handle = PamHandle()
    pam_conv = PamConv()
    pam_obj.pam_start(b'', b'', pam_conv, pam_obj.handle)
    pam_obj.putenv('NAME=foo')
    rv = pam_obj.getenv('NAME')
    assert 'foo' == rv


def test_PamAuthenticator__getenv_stutter(pam_obj):
    pam_obj.handle = PamHandle()
    pam_conv = PamConv()
    pam_obj.pam_start(b'', b'', pam_conv, pam_obj.handle)
    pam_obj.putenv('NAME=NAME=foo')
    rv = pam_obj.getenv('NAME')
    assert 'NAME=foo' == rv


def test_PamAuthenticator__getenvlist_incomplete_setup(pam_obj):
    pam_obj.handle = None
    rv = pam_obj.getenvlist()
    assert PAM_SYSTEM_ERR == rv


def test_PamAuthenticator__getenvlist(pam_obj):
    pam_obj.handle = PamHandle()
    pam_conv = PamConv()
    pam_obj.pam_start(b'', b'', pam_conv, pam_obj.handle)
    pam_obj.putenv('A=b')
    pam_obj.putenv('C=d')
    rv = pam_obj.getenvlist()
    assert {'A': 'b', 'C': 'd'} == rv


def test_PamAuthenticator__getenvlist_missing_value(pam_obj):
    pam_obj.handle = PamHandle()
    pam_conv = PamConv()
    pam_obj.pam_start(b'', b'', pam_conv, pam_obj.handle)
    pam_obj.putenv('A=b')
    pam_obj.putenv('C=')
    rv = pam_obj.getenvlist()
    assert {'A': 'b', 'C': ''} == rv


def test_PamAuthenticator__misc_setenv_incomplete_setup(pam_obj):
    pam_obj.handle = None
    rv = pam_obj.misc_setenv('NAME', 'SomeValue', False)
    assert PAM_SYSTEM_ERR == rv


def test_PamAuthenticator__misc_setenv(pam_obj):
    pam_obj.handle = PamHandle()
    pam_conv = PamConv()
    pam_obj.pam_start(b'', b'', pam_conv, pam_obj.handle)
    rv = pam_obj.misc_setenv('NAME', 'SomeValue', False)
    assert PAM_SUCCESS == rv


def test_PamAuthenticator__pam_end_incomplete_setup(pam_obj):
    pam_obj.handle = None
    rv = pam_obj.end()
    assert PAM_SYSTEM_ERR == rv


def test_PamAuthenticator__pam_end(pam_obj):
    pam_obj.handle = PamHandle()
    pam_conv = PamConv()
    pam_obj.pam_start(b'', b'', pam_conv, pam_obj.handle)
    rv = pam_obj.end()
    assert PAM_SUCCESS == rv


def test_PamAuthenticator__open_session_incomplete_setup(pam_obj):
    pam_obj.handle = None
    rv = pam_obj.open_session()
    assert PAM_SYSTEM_ERR == rv


def test_PamAuthenticator__open_session_unauthenticated(pam_obj):
    pam_obj.handle = PamHandle()
    pam_conv = PamConv()
    pam_obj.pam_start(b'', b'', pam_conv, pam_obj.handle)
    rv = pam_obj.open_session()
    assert PAM_SESSION_ERR == rv


def test_PamAuthenticator__close_session_incomplete_setup(pam_obj):
    pam_obj.handle = None
    rv = pam_obj.close_session()
    assert PAM_SYSTEM_ERR == rv


def test_PamAuthenticator__close_session_unauthenticated(pam_obj):
    pam_obj.handle = PamHandle()
    pam_conv = PamConv()
    pam_obj.pam_start(b'', b'', pam_conv, pam_obj.handle)
    rv = pam_obj.close_session()
    assert PAM_SESSION_ERR == rv


def test_PamAuthenticator__conversation_callback_prompt_echo_off(pam_obj):
    '''Verify that the password is stuffed into the pp_response structure and the
    response code is set to zero
    '''
    n_messages = 1

    messages = PamMessage(PAM_PROMPT_ECHO_OFF, b'Password: ')
    pp_messages = pointer(pointer(messages))

    response = PamResponse(b'overwrite', -1)
    pp_response = pointer(pointer(response))

    encoding = 'utf-8'
    password = b'blank'
    msg_list = []

    libc = cdll.LoadLibrary(None)

    rv = my_conv(n_messages,
                 pp_messages,
                 pp_response,
                 libc,
                 msg_list,
                 password,
                 encoding)

    assert b'blank' == pp_response.contents.contents.resp
    assert 0 == pp_response.contents.contents.resp_retcode
    assert PAM_SUCCESS == rv


def test_PamAuthenticator__conversation_callback_prompt_echo_on(pam_obj):
    '''Verify that the stuffed PamResponse "overwrite" is copied into the output
    and the resp_retcode is set to zero
    '''
    n_messages = 1

    messages = PamMessage(PAM_PROMPT_ECHO_ON, b'Password: ')
    pp_messages = pointer(pointer(messages))

    response = PamResponse(b'overwrite', -1)
    pp_response = pointer(pointer(response))

    encoding = 'utf-8'
    password = b'blank'
    msg_list = []

    libc = cdll.LoadLibrary(None)

    rv = my_conv(n_messages,
                 pp_messages,
                 pp_response,
                 libc,
                 msg_list,
                 password,
                 encoding)

    assert None is pp_response.contents.contents.resp
    assert 0 == pp_response.contents.contents.resp_retcode
    assert PAM_SUCCESS == rv


def test_PamAuthenticator__conversation_callback_multimessage_OFF_ON(pam_obj):
    '''Verify that the stuffed PamResponse "overwrite" is copied into the output
    and the resp_retcode is set to zero
    '''
    n_messages = 2

    msg1 = PamMessage(PAM_PROMPT_ECHO_OFF, b'overwrite with PAM_PROMPT_ECHO_OFF')
    msg2 = PamMessage(PAM_PROMPT_ECHO_ON, b'overwrite with PAM_PROMPT_ECHO_ON')

    ptr1 = pointer(msg1)
    ptr2 = pointer(msg2)

    ptrs = pointer(ptr1)
    ptrs[1] = ptr2

    pp_messages = pointer(ptrs[0])

    response = PamResponse(b'overwrite', -1)
    pp_response = pointer(pointer(response))

    encoding = 'utf-8'
    password = b'blank'
    msg_list = []

    libc = cdll.LoadLibrary(None)

    rv = my_conv(n_messages,
                 pp_messages,
                 pp_response,
                 libc,
                 msg_list,
                 password,
                 encoding)

    assert b'blank' == pp_response.contents.contents.resp
    assert 0 == pp_response.contents.contents.resp_retcode
    assert PAM_SUCCESS == rv


def test_PamAuthenticator__conversation_callback_multimessage_ON_OFF(pam_obj):
    '''Verify that the stuffed PamResponse "overwrite" is copied into the output
    and the resp_retcode is set to zero
    '''
    n_messages = 2

    msg1 = PamMessage(PAM_PROMPT_ECHO_ON, b'overwrite with PAM_PROMPT_ECHO_ON')
    msg2 = PamMessage(PAM_PROMPT_ECHO_OFF, b'overwrite with PAM_PROMPT_ECHO_OFF')

    ptr1 = pointer(msg1)
    ptr2 = pointer(msg2)

    ptrs = pointer(ptr1)
    ptrs[1] = ptr2

    pp_messages = pointer(ptrs[0])

    response = PamResponse(b'overwrite', -1)
    pp_response = pointer(pointer(response))

    encoding = 'utf-8'
    password = b'blank'
    msg_list = []

    libc = cdll.LoadLibrary(None)

    rv = my_conv(n_messages,
                 pp_messages,
                 pp_response,
                 libc,
                 msg_list,
                 password,
                 encoding)

    assert None is pp_response.contents.contents.resp
    assert 0 == pp_response.contents.contents.resp_retcode
    assert PAM_SUCCESS == rv
