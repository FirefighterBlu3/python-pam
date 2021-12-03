import os
import pytest

from ctypes import c_void_p

from pam.__internals import PAM_SYSTEM_ERR
from pam.__internals import PAM_SUCCESS
from pam.__internals import PAM_SESSION_ERR
from pam.__internals import PAM_AUTH_ERR
from pam.__internals import PAM_USER_UNKNOWN
from pam.__internals import PamConv
from pam.__internals import PamHandle
from pam.__internals import PamMessage
from pam.__internals import PamResponse
from pam.__internals import PamAuthenticator

# In order to run some tests, we need a working user/pass combo
# you can specify these on the command line
TEST_USERNAME = os.getenv('USERNAME', '')
TEST_PASSWORD = os.getenv('PASSWORD', '')


@pytest.fixture
def pam_obj(request):
    obj = PamAuthenticator()
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
    assert "<PamMessage 1 'b'1''>" == repr(x)


def test_PamResponse__repr():
    x = PamResponse()
    assert "<PamResponse 0 'None'>" == repr(x)


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
    if not (TEST_USERNAME and  TEST_PASSWORD):
        pytest.skip("test requires valid TEST_USERNAME and TEST_PASSWORD set in environment")

    rv = pam_obj.authenticate(TEST_USERNAME, TEST_PASSWORD)
    assert PAM_SUCCESS == rv


def test_PamAuthenticator__normal_password_failure(pam_obj):
    if not (TEST_USERNAME and  TEST_PASSWORD):
        pytest.skip("test requires valid TEST_USERNAME and TEST_PASSWORD set in environment")

    rv = pam_obj.authenticate(TEST_USERNAME, 'not-valid')
    assert PAM_AUTH_ERR == rv


def test_PamAuthenticator__normal_unknown_username(pam_obj):
    rv = pam_obj.authenticate('bad_user_name', '')
    assert PAM_AUTH_ERR == rv


def test_PamAuthenticator__unset_DISPLAY(pam_obj):
    os.environ['DISPLAY'] = ''

    rv = pam_obj.authenticate(TEST_USERNAME, TEST_PASSWORD)

    # yes, this is intentional. this lets us run code coverage on the
    # affected area even though we know the assert would have failed
    if not (TEST_USERNAME and TEST_PASSWORD):
        pytest.skip("test requires valid TEST_USERNAME and TEST_PASSWORD set in environment")

    assert PAM_SUCCESS == rv


def test_PamAuthenticator__env_requires_dict(pam_obj):
    with pytest.raises(TypeError):
        pam_obj.authenticate(TEST_USERNAME, TEST_PASSWORD, env='value')


def test_PamAuthenticator__env_requires_key_no_nulls(pam_obj):
    with pytest.raises(ValueError):
        pam_obj.authenticate(TEST_USERNAME, TEST_PASSWORD, env={b'\x00invalid_key': b'value'})


def test_PamAuthenticator__env_requires_value_no_nulls(pam_obj):
    with pytest.raises(ValueError):
        pam_obj.authenticate(TEST_USERNAME, TEST_PASSWORD, env={b'key': b'\x00invalid_value'})


def test_PamAuthenticator__env_set(pam_obj):
    rv = pam_obj.authenticate(TEST_USERNAME, TEST_PASSWORD, env={'key': b'value'})

    # yes, this is intentional. this lets us run code coverage on the
    # affected area even though we know the assert would have failed
    if not (TEST_USERNAME and  TEST_PASSWORD):
        pytest.skip("test requires valid TEST_USERNAME and TEST_PASSWORD set in environment")

    assert PAM_SUCCESS == rv


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
