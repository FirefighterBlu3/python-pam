from ctypes import CDLL, POINTER, Structure, CFUNCTYPE, cast, byref, sizeof
from ctypes import c_void_p, c_size_t, c_char_p, c_char, c_int
from ctypes import memmove
from ctypes.util import find_library

__all__ = ('PAM_ABORT', 'PAM_ACCT_EXPIRED', 'PAM_AUTHINFO_UNAVAIL', 'PAM_AUTHTOK_DISABLE_AGING', 'PAM_AUTHTOK_ERR', 'PAM_AUTHTOK_EXPIRED', 'PAM_AUTHTOK_LOCK_BUSY', 'PAM_AUTHTOK_RECOVER_ERR', 'PAM_AUTH_ERR', 'PAM_BAD_ITEM', 'PAM_BUF_ERR', 'PAM_CHANGE_EXPIRED_AUTHTOK', 'PAM_CONV', 'PAM_CONV_ERR', 'PAM_CRED_ERR', 'PAM_CRED_EXPIRED', 'PAM_CRED_INSUFFICIENT', 'PAM_CRED_UNAVAIL', 'PAM_DATA_SILENT', 'PAM_DELETE_CRED', 'PAM_DISALLOW_NULL_AUTHTOK', 'PAM_ERROR_MSG', 'PAM_ESTABLISH_CRED', 'PAM_IGNORE', 'PAM_MAXTRIES', 'PAM_MODULE_UNKNOWN', 'PAM_NEW_AUTHTOK_REQD', 'PAM_NO_MODULE_DATA', 'PAM_OPEN_ERR', 'PAM_PERM_DENIED', 'PAM_PROMPT_ECHO_OFF', 'PAM_PROMPT_ECHO_ON', 'PAM_REFRESH_CRED', 'PAM_REINITIALIZE_CRED', 'PAM_RHOST', 'PAM_RUSER', 'PAM_SERVICE', 'PAM_SERVICE_ERR', 'PAM_SESSION_ERR', 'PAM_SILENT', 'PAM_SUCCESS', 'PAM_SYMBOL_ERR', 'PAM_SYSTEM_ERR', 'PAM_TEXT_INFO', 'PAM_TRY_AGAIN', 'PAM_TTY', 'PAM_USER', 'PAM_USER_PROMPT', 'PAM_USER_UNKNOWN', 'error', 'pam')


class PamHandle(Structure):
	"""wrapper class for pam_handle_t pointer"""
	_fields_ = [("handle", c_void_p)]

	def __init__(self):
		Structure.__init__(self)
		self.handle = 0


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


conv_func = CFUNCTYPE(c_int, c_int, POINTER(POINTER(PamMessage)), POINTER(POINTER(PamResponse)), c_void_p)


class PamConv(Structure):
	"""wrapper class for pam_conv structure"""
	_fields_ = [("conv", conv_func), ("appdata_ptr", c_void_p)]


libc = CDLL(find_library("c"))
libpam = CDLL(find_library("pam"))
libpam_misc = CDLL(find_library("pam_misc"))

calloc = libc.calloc
calloc.restype = c_void_p
calloc.argtypes = [c_size_t, c_size_t]

# bug #6 (@NIPE-SYSTEMS), some libpam versions don't include this function
if hasattr(libpam, 'pam_end'):
	pam_end = libpam.pam_end
	pam_end.restype = c_int
	pam_end.argtypes = [PamHandle, c_int]
else:
	pam_end = None

pam_start = libpam.pam_start
pam_start.restype = c_int
pam_start.argtypes = [c_char_p, c_char_p, POINTER(PamConv), POINTER(PamHandle)]

pam_setcred = libpam.pam_setcred
pam_setcred.restype = c_int
pam_setcred.argtypes = [PamHandle, c_int]

pam_strerror = libpam.pam_strerror
pam_strerror.restype = c_char_p
pam_strerror.argtypes = [PamHandle, c_int]

pam_authenticate = libpam.pam_authenticate
pam_authenticate.restype = c_int
pam_authenticate.argtypes = [PamHandle, c_int]

pam_acct_mgmt = libpam.pam_acct_mgmt
pam_acct_mgmt.restype = c_int
pam_acct_mgmt.argtypes = [PamHandle, c_int]

pam_chauthtok = libpam.pam_chauthtok
pam_chauthtok.restype = c_int
pam_chauthtok.argtypes = [PamHandle, c_int]

pam_open_session = libpam.pam_open_session
pam_open_session.restype = c_int
pam_open_session.argtypes = [PamHandle, c_int]

pam_close_session = libpam.pam_close_session
pam_close_session.restype = c_int
pam_close_session.argtypes = [PamHandle, c_int]

pam_set_item = libpam.pam_set_item
pam_set_item.restype = c_int
pam_set_item.argtypes = [PamHandle, c_int, c_void_p]

pam_get_item = libpam.pam_get_item
pam_get_item.restype = c_int
pam_get_item.argtypes = [PamHandle, c_int, POINTER(c_void_p)]

pam_putenv = libpam.pam_putenv
pam_putenv.restype = c_int
pam_putenv.argtypes = [PamHandle, c_char_p]

pam_getenv = libpam.pam_getenv
pam_getenv.restype = c_char_p
pam_getenv.argtypes = [PamHandle, c_char_p]

pam_getenvlist = libpam.pam_getenvlist
pam_getenvlist.restype = POINTER(c_char_p)
pam_getenvlist.argtypes = [PamHandle]

if libpam_misc._name:
	pam_misc_setenv = libpam_misc.pam_misc_setenv
	pam_misc_setenv.restype = c_int
	pam_misc_setenv.argtypes = [PamHandle, c_char_p, c_char_p, c_int]
else:
	pam_misc_setenv = None

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


class error(Exception):  # noqa: N801

	def __init__(self, pam, errno):
		self.errno = errno
		super(error, self).__init__(pam_strerror(pam.pamh, errno), errno)


class pam(object):  # noqa: N801

	__slots__ = ('pamh', 'conv', 'service', 'user', 'user_data', 'callback')

	def __init__(self):
		self.pamh = PamHandle()
		self.conv = None
		self.callback = None
		self.service = None
		self.user = None
		self.user_data = None
		self.__set_conversation(None)

	def start(self, service=None, user=None, callback=None):
		if service:
			self.service = self.__securestring(service)
		if user:
			self.user = self.__securestring(user)
		if callback:
			self.__set_conversation(callback)

		retval = pam_start(self.service, self.user, byref(self.callback), byref(self.pamh))
		if retval != PAM_SUCCESS:
			raise error(self, retval)

	def __set_conversation(self, conv):
		self.conv = conv

		@conv_func
		def callback(n_messages, messages, p_response, app_data):
			messages = [messages[i] for i in range(n_messages)]
			# Create an array of n_messages response objects
			addr = calloc(n_messages, sizeof(PamResponse))
			response = cast(addr, POINTER(PamResponse))
			p_response[0] = response

			if conv is None:
				return PAM_CONV_ERR

			query_list = [(x.contents.msg, x.contents.msg_style) for x in messages]
			try:
				result_list = conv(self, query_list, self.user_data)
			except BaseException as exc:
				import traceback
				print('ExC', exc, traceback.format_exc())
				return PAM_CONV_ERR

			if not isinstance(result_list, list):
				return PAM_CONV_ERR

			if len(result_list) != n_messages:
				return PAM_CONV_ERR

			for result, message, resp in zip(result_list, messages, response):
				if not isinstance(result, tuple) or len(result) != 2:
					return PAM_CONV_ERR
				answer, retcode = result
				if not isinstance(answer, bytes) or b'\x00' in answer or not isinstance(retcode, int):
					return PAM_CONV_ERR
				# if message.contents.msg_style == PAM_PROMPT_ECHO_OFF or 0:
				dst = calloc(len(answer) + 1, sizeof(c_char))
				memmove(dst, c_char_p(answer), len(answer))
				resp.resp = dst
				resp.resp_retcode = retcode

			return PAM_SUCCESS

		self.callback = PamConv(callback, 0)

	def authenticate(self, flags=0):
		retval = pam_authenticate(self.pamh, int(flags))
		if retval != PAM_SUCCESS:
			raise error(self, retval)

	def setcred(self, flags=0):  # flags=PAM_REINITIALIZE_CRED ?
		retval = pam_setcred(self.pamh, int(flags))
		if retval != PAM_SUCCESS:
			raise error(self, retval)

	def acct_mgmt(self, flags=0):
		retval = pam_acct_mgmt(self.pamh, int(flags))
		if retval != PAM_SUCCESS:
			raise error(self, retval)

	def chauthtok(self, flags=0):
		retval = pam_chauthtok(self.pamh, int(flags))
		if retval != PAM_SUCCESS:
			raise error(self, retval)

	def open_session(self, flags=0):
		retval = pam_open_session(self.pamh, int(flags))
		if retval != PAM_SUCCESS:
			raise error(self, retval)

	def close_session(self, flags=0):
		retval = pam_close_session(self.pamh, int(flags))
		if retval != PAM_SUCCESS:
			raise error(self, retval)

	def set_item(self, item_type, item):
		if item_type == PAM_CONV:
			if not callable(item):
				raise TypeError("parameter must be a function")
			self.__set_conversation(item)
			item = byref(self.callback)
		else:
			if item_type == PAM_USER:
				self.user = item
			elif item_type == PAM_SERVICE:
				self.service = item
			elif item_type not in (PAM_TTY, PAM_XDISPLAY):
				raise TypeError("bad parameter")
			item = c_char_p(self.__securestring(item))
		retval = pam_set_item(self.pamh, int(item_type), cast(item, c_void_p))

		if retval != PAM_SUCCESS:
			raise error(self, retval)

	def get_item(self, item_type):
		item = byref(c_void_p())
		retval = pam_get_item(self.pamh, int(item_type), item)
		if retval != PAM_SUCCESS:
			raise error(self, retval)
		if item_type == PAM_CONV:
			return cast(item, POINTER(PamConv)).contents.conv
		return cast(item, POINTER(c_char_p)).contents.value

	def putenv(self, value):
		if not isinstance(value, bytes) or b'\x00' in value:
			raise TypeError("parameter must be a string")

		retval = pam_putenv(self.pamh, value)
		if retval != PAM_SUCCESS:
			raise error(self, retval)

	def getenv(self, env):
		return pam_getenv(self.pamh, env)

	def getenvlist(self):
		env = []
		for x in pam_getenvlist(self.pamh):
			if x is None:
				break
			env.append(x)
		return env

	def setUserData(self, data):  # noqa: N802
		self.user_data = data

	def __securestring(self, string):
		if not isinstance(string, bytes):
			raise TypeError('parameter must be a string')
		if b'\x00' in string:
			raise error(self, PAM_SYSTEM_ERR)

		return string

	def end(self):
		if pam_end is not None:
			pam_end(self.pamh, PAM_SUCCESS)
			self.pamh = None

	def misc_setenv(self, name, value, readonly):
		retval = pam_misc_setenv(self.pamh, self.__securestring(name), self.__securestring(value), int(readonly))
		if retval != PAM_SUCCESS:
			raise error(self, retval)

	def __del__(self):
		if self.pamh:
			self.end()

	def __repr__(self):
		return '<pam object, service="%s", user="%s", conv=0x%x, pamh=0x%x>' % (self.service, self.user, id(self.callback), id(self.pamh))
