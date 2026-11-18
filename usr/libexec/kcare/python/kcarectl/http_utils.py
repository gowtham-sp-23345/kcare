# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT

import errno
import os
import socket
import ssl
from ssl import SSLError

from . import config, constants, errors, log_utils, utils
from .py23 import HTTPError, Request, URLError, httplib, std_urlopen


def urlopen_base(url, *args, **kwargs):  # mocked: tests/unit
    if hasattr(url, 'get_full_url'):
        request_url = url.get_full_url()
    else:
        request_url = url
        url = Request(url)

    headers = kwargs.pop('headers', {})
    headers.update(
        {
            'KC-Version': constants.VERSION,
            'KC-Patch-Version': constants.KC_PATCH_VERSION,
        }
    )
    for header, value in headers.items():
        url.add_header(header, value)

    log_utils.logdebug("Requesting url: `{0}`. Headers: {1}".format(request_url, headers))

    try:
        # add timeout exclude python 2.6
        if not constants.PY2_6 and 'timeout' not in kwargs:
            kwargs['timeout'] = config.HTTP_TIMEOUT
        # bandit warns about use of file: in urlopen which can happen here but is secure
        if not config.CHECK_SSL_CERTS and getattr(ssl, 'HAS_SNI', None):  # pragma: no cover unit
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            kwargs['context'] = ctx
            return std_urlopen(url, *args, **kwargs)  # nosec B310
        return std_urlopen(url, *args, **kwargs)  # nosec B310
    except HTTPError as ex:
        if ex.code == 404:
            raise errors.NotFound(ex.url, ex.code, ex.msg, ex.hdrs, ex.fp)
        # HTTPError is a URLError descendant and contains URL, raise it as is
        raise
    except URLError as ex:
        # Local patches OSError(No such file) should be interpreted as Not found(404)
        # It was done as a chain because when it implemented with "duck-typing" it will mess
        # with error context
        if ex.args and hasattr(ex.args[0], 'errno') and ex.args[0].errno == errno.ENOENT:
            raise errors.NotFound(url, 404, str(ex), None, None)  # type: ignore[arg-type]

        # there is no information about URL in the base URLError class, add it and raise
        ex.reason = 'Request for `{0}` failed: {1}'.format(request_url, ex)
        ex.url = request_url  # type: ignore[attr-defined]
        raise


def check_urlopen_retry_factory(retry_on_500=True):
    def check_function(e, state):
        if isinstance(e, HTTPError):
            return retry_on_500 and e.code >= 500
        elif isinstance(e, (URLError, httplib.HTTPException, SSLError, socket.timeout)):
            return True
        elif hasattr(e, 'args') and len(e.args) == 2 and e.args[0] == errno.ECONNRESET:  # pragma: no cover unit
            # SysCallError "Connection reset by peer" from PyOpenSSL
            return True

    return check_function


def is_local_url(url):
    if hasattr(url, 'get_full_url'):
        url = url.get_full_url()
    return url.startswith('file:')


def urlopen(url, *args, **kwargs):
    retry_on_500 = kwargs.pop('retry_on_500', True)
    retry_count = kwargs.pop('retry_count', constants.RETRY_COUNT)
    if is_local_url(url):
        return urlopen_base(url, *args, **kwargs)
    return utils.retry(check_urlopen_retry_factory(retry_on_500=retry_on_500), count=retry_count)(urlopen_base)(url, *args, **kwargs)


def http_request(url, auth_string, auth_token=None, method=None):
    request = Request(url, method=method)
    if not config.UPDATE_FROM_LOCAL and auth_string:
        request.add_header('Authorization', 'Basic {0}'.format(auth_string))

    if not config.UPDATE_FROM_LOCAL and auth_token:
        request.add_header(constants.AUTH_TOKEN_HEADER, auth_token)

    return request


def get_proxy_from_env(scheme):
    if scheme == 'http':
        return os.getenv('http_proxy') or os.getenv('HTTP_PROXY')
    elif scheme == 'https':
        return os.getenv('https_proxy') or os.getenv('HTTPS_PROXY')


def proxy_is_used():
    return bool(get_proxy_from_env('http')) or bool(get_proxy_from_env('https'))


check_urlopen_retry = check_urlopen_retry_factory()

