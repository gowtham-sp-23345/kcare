# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT

import base64
import os
import re
import time

from . import config, constants, errors, http_utils, ipv6_support, log_utils, platform_utils, serverid, utils
from .py23 import HTTPError, URLError, urlencode


def unregister(silent=False):
    url = None
    try:
        server_id = serverid.get_serverid()
        if server_id is None:
            if not silent:
                log_utils.logerror('Error unregistering server: cannot find server id')
            return
        url = ipv6_support.get_registration_url() + '/unregister_server.plain?server_id={0}'.format(server_id)
        response = http_utils.urlopen(url)
        content = utils.nstr(response.read())
        res = utils.data_as_dict(content)
        if res['success'] == 'true':
            serverid.rm_serverid()
            if not silent:
                log_utils.loginfo('Server was unregistered')
        elif not silent:
            log_utils.logerror(content)
            log_utils.logerror('Error unregistering server: ' + res['message'])
    except HTTPError as e:
        if not silent:
            log_utils.print_cln_http_error(e, url)


def _register_retry(url):  # pragma: no cover unit
    utils.print_wrapper('Register auto-retry has been enabled, the system can be registered later')
    pid = os.fork()
    if pid > 0:
        return
    os.setsid()
    pid = os.fork()
    import sys

    if pid > 0:
        sys.exit(0)
    sys.stdout.flush()
    si = open('/dev/null', 'r')
    so = open('/dev/null', 'a+')
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(so.fileno(), sys.stderr.fileno())
    while True:
        time.sleep(60 * 60 * 2)
        code, server_id, auth_token = _try_register(url)
        if code == 0 and server_id:
            serverid.set_server_id(server_id)
            _set_auth_token(auth_token)
            sys.exit(0)


def _validate_urlsafe_encoding(value):
    if value is not None and not re.match(r'^[\w.-]+$', value):
        raise ValueError('Invalid value received: %s' % value)
    return value


def _try_register(url):
    try:
        response = http_utils.urlopen(url)
        auth_token = response.headers.get(constants.AUTH_TOKEN_HEADER, None)
        res = utils.data_as_dict(utils.nstr(response.read()))
        return int(res['code']), _validate_urlsafe_encoding(res.get('server_id')), _validate_urlsafe_encoding(auth_token)
    except (HTTPError, URLError) as e:
        log_utils.print_cln_http_error(e, url)
        return None, None, None
    except Exception:
        log_utils.kcarelog.exception('Exception while trying to register URL %s' % url)
        return None, None, None


def register(key, retry=False):
    try:
        unregister(True)
    except Exception:
        log_utils.kcarelog.exception('Exception while trying to unregister URL before register.')

    hostname = platform_utils.get_hostname()

    query = urlencode([('hostname', hostname), ('key', key)])
    url = '{0}/register_server.plain?{1}'.format(ipv6_support.get_registration_url(), query)

    code, server_id, auth_token = _try_register(url)
    if code == 0:
        serverid.set_server_id(server_id)
        _set_auth_token(auth_token)
        log_utils.loginfo('Server Registered')
        return 0
    elif code == 1:
        log_utils.logerror('Account Locked')
    elif code == 2:
        log_utils.logerror('Invalid Key')
    elif code == 3:
        log_utils.logerror(
            'You have reached maximum registered servers for this key. '
            'Please go to your CLN account, remove unused servers and try again.'
        )
    elif code == 4:
        log_utils.logerror('IP is not allowed. Please change allowed IP ranges for the key in KernelCare Key tab in CLN')
    elif code == 5:
        log_utils.logerror('This IP was already used for trial, you cannot use it for trial again')
    elif code == 6:
        log_utils.logerror('This IP was banned. Please contact support for more information at https://www.kernelcare.com/support/')
    else:
        log_utils.logerror('Unknown Error {0}'.format(code))
    if retry:  # pragma: no cover
        _register_retry(url)
        return 0
    return code or -1


@utils.cached
def _get_auth_token():
    return utils.try_to_read(constants.AUTH_TOKEN_DUMP_PATH)


def _set_auth_token(auth_token):
    if not auth_token:
        return

    utils.atomic_write(constants.AUTH_TOKEN_DUMP_PATH, auth_token)


def urlopen_auth(url, *args, **kwargs):
    method = kwargs.pop('method', None)
    if kwargs.pop('check_license', True):
        check = _check_auth_retry
    else:
        check = http_utils.check_urlopen_retry
    if http_utils.is_local_url(url):
        return http_utils.urlopen_base(url, *args, **kwargs)

    request = http_utils.http_request(url, get_http_auth_string(), _get_auth_token(), method=method)
    return utils.retry(check, count=8)(http_utils.urlopen_base)(request, *args, **kwargs)


def get_http_auth_string():
    server_id = serverid.get_serverid()
    if server_id:
        return utils.nstr(base64.b64encode(utils.bstr('{0}:{1}'.format(server_id, 'kernelcare'))))
    return None


def _check_auth_retry(e, state):
    if isinstance(e, HTTPError):
        if e.code in (403, 401):
            return _handle_forbidden(state)
        return e.code >= 500
    elif isinstance(e, URLError):
        return True


def _handle_forbidden(state):
    """In case of 403 error we should check what's happen.
    Case #1. We are trying to register unlicensed machine and should try to register trial.
    Case #2. We have a valid license but access restrictions on server are not consistent yet
             and we had to try later.
    """
    if 'license' in state:
        # license has already been checked and is valid, no need to ask CLN again
        return True

    if config.CHECK_CLN_LICENSE_STATUS:
        server_id = serverid.get_serverid()
        url = ipv6_support.get_registration_url() + '/check.plain'

        if server_id:
            url += '?server_id={0}'.format(server_id)

        try:
            # do not retry in case of 500 from CLN!
            # otherwise, CLN will die in pain because of too many requests
            content = utils.nstr(http_utils.urlopen(url, retry_on_500=False).read())
            info = utils.data_as_dict(content)
        except URLError as ex:
            log_utils.print_cln_http_error(ex, url, stdout=False)
            return

        if not info or not info.get('code'):
            log_utils.kcarelog.error('Unexpected CLN response: {0}'.format(content))
            return

        if info['code'] in ['0', '1']:
            # license is fine: 0 - valid license, 1 - valid trial license;
            # looks like htpasswd not updated yet;
            # mark state as licensed to avoid repeated requests to CLN
            state['license'] = True
            log_utils.logerror('Unable to access server. Retrying...')
            return True
        else:
            _register_trial()


def license_info():
    server_id = serverid.get_serverid()
    if server_id:
        url = ipv6_support.get_registration_url() + '/check.plain?server_id={0}'.format(server_id)
        try:
            response = http_utils.urlopen(url)
            content = utils.nstr(response.read())
            res = utils.data_as_dict(content)
            if not res or not res.get('code'):
                utils.print_wrapper('Unexpected CLN response: {0}'.format(content))
                return 1
            code = int(res['code'])
            if code == 0:
                utils.print_wrapper('Key-based valid license found')
                return 1
            else:
                license_type = _get_license_info_by_ip(key_checked=1)
                if license_type == 0:
                    utils.print_wrapper('No valid key-based license found')
                return license_type
        except URLError as e:
            log_utils.print_cln_http_error(e, url)
            return 0
    else:
        return _get_license_info_by_ip()


def _get_license_info_by_ip(key_checked=0):
    url = ipv6_support.get_registration_url() + '/check.plain'
    try:
        response = http_utils.urlopen(url)
        content = utils.nstr(response.read())
        res = utils.data_as_dict(content)
        if res['success'].lower() == 'true':
            code = int(res['code'])
            if code == 0:
                utils.print_wrapper('Valid license found for IP {0}'.format(res['ip']))
                return 1  # valid license
            if code == 1:
                ip = res['ip']
                expires_str = utils.parse_response_date(res['expire_date']).strftime('%Y-%m-%d')
                utils.print_wrapper('You have a trial license for the IP {0} that will expire on {1}'.format(ip, expires_str))
                return 2  # trial license
            if code == 2 and key_checked == 0:
                ip = res['ip']
                expires_str = utils.parse_response_date(res['expire_date']).strftime('%Y-%m-%d')
                utils.print_wrapper('Your trial license for the IP {0} expired on {1}'.format(ip, expires_str))
            if code == 3 and key_checked == 0:
                if 'ip' in res:
                    utils.print_wrapper("The IP {0} hasn't been licensed".format(res['ip']))
                else:
                    utils.print_wrapper("This server hasn't been licensed")
        else:
            message = res.get('message', '')
            utils.print_wrapper('Error retrieving license info: {0}'.format(message))
    except URLError as e:
        log_utils.print_cln_http_error(e, url)
    except KeyError as key:
        utils.print_wrapper('Unexpected CLN response, cannot find {0} key:\n{1}'.format(key, content.strip()))
    return 0  # no valid license


def _register_trial():
    trial_mark = os.path.join(constants.PATCH_CACHE, 'trial-requested')
    if os.path.exists(trial_mark):
        return

    try:
        response = http_utils.urlopen(ipv6_support.get_registration_url() + '/trial.plain')
        res = utils.data_as_dict(utils.nstr(response.read()))
        try:
            if res['success'].lower() == 'true':
                utils.atomic_write(trial_mark, '', ensure_dir=True)
                if res['expired'] == 'true':
                    raise errors.AlreadyTrialedException(res['ip'], res['created'])
                log_utils.loginfo('Requesting trial license for IP {0}. Please wait...'.format(res['ip']))
                return None
            elif res['success'] == 'na':
                utils.atomic_write(trial_mark, '', ensure_dir=True)
                raise errors.KcareError('Invalid License')
            else:
                # TODO: make sane exception messages
                raise errors.UnableToGetLicenseException(-1)  # Invalid response?
        except KeyError as ke:
            raise errors.UnableToGetLicenseException(ke)
    except HTTPError as e:
        raise errors.UnableToGetLicenseException(e.code)

