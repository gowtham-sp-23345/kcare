# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT

from __future__ import print_function

import base64
import json
import logging
import os
import platform
import random
import re
import shutil
import socket
import ssl
import sys
import tempfile
import time
import traceback
import warnings
from argparse import ArgumentParser
from contextlib import contextmanager
from datetime import datetime

from . import (
    auth,
    capabilities,
    config,
    config_handlers,
    constants,
    errors,
    fetch,
    http_utils,
    ipv6_support,
    kcare,
    libcare,
    log_utils,
    platform_utils,
    process_utils,
    selinux,
    server_info,
    serverid,
    update_utils,
    utils,
)
from .errors import KcareError, NotFound, SafeExceptionWrapper
from .py23 import HTTPError, URLError, httplib, json_loads_nstr, urlencode

CPANEL_GID = 99
EFFECTIVE_LATEST = 'v3'
EXPECTED_PREFIX = ('12h', '24h', '48h', 'test')
FREEZER_BLACKLIST = '/etc/sysconfig/kcare/freezer.modules.blacklist'
KCDOCTOR = '/usr/libexec/kcare/kcdoctor.sh'

PATCH_LATEST = (
    'latest.v3',
    'latest.v2',
)
SYSCTL_CONFIG = '/etc/sysconfig/kcare/sysctl.conf'

UNLOAD_RETRY_DELAY = 10

BLACKLIST_RE = re.compile('==BLACKLIST==\n(.*)==END BLACKLIST==\n', re.DOTALL)
CONFLICTING_MODULES_RE = re.compile('(kpatch.*|ksplice.*|kpatch_livepatch.*)')


if os.path.isdir('/usr/libexec/kcare/python'):  # pragma: no cover
    sys.path.insert(0, '/usr/libexec/kcare/python')

warnings.filterwarnings('ignore', category=DeprecationWarning)


if False:  # pragma: no cover
    from typing import Any, Dict, Optional, Set, Tuple, Union  # noqa: F401


log_utils.kcarelog.setLevel(logging.DEBUG)


def get_freezer_blacklist():
    result = set()
    if os.path.isfile(FREEZER_BLACKLIST):
        f = open(FREEZER_BLACKLIST, 'r')
        for line in f:
            result.add(line.rstrip())
        f.close()
    return result


def _apply_ptype(ptype, filename):
    name_parts = filename.split('.')
    if ptype:
        filename = '.'.join([name_parts[0], ptype, name_parts[-1]])
    else:
        filename = '.'.join([name_parts[0], name_parts[-1]])
    return filename


def apply_ptype(ptype):
    config.PATCH_BIN = _apply_ptype(ptype, config.PATCH_BIN)
    config.PATCH_INFO = _apply_ptype(ptype, config.PATCH_INFO)
    config.BLACKLIST_FILE = _apply_ptype(ptype, config.BLACKLIST_FILE)
    config.FIXUPS_FILE = _apply_ptype(ptype, config.FIXUPS_FILE)
    config.PATCH_DONE = _apply_ptype(ptype, config.PATCH_DONE)


def format_exception_without_details():
    etype, value, tb = sys.exc_info()
    details_sanitized = ''
    if isinstance(value, OSError) and not isinstance(value, URLError):
        try:
            # reconstruct for safety, it may be any IO-related subclass
            details_sanitized = "[Errno %i] %s: '%s'" % (value.errno, os.strerror(value.errno), value.filename)
        except (AttributeError, TypeError):
            pass
    elif isinstance(value, (KeyError, TypeError, IOError)) and not isinstance(value, URLError):
        details_sanitized = '%s' % value
    elif isinstance(value, SafeExceptionWrapper):
        etype = value.etype or type(value.inner)
        details_sanitized = value.details or ('%s' % value.inner)

    distro = platform_utils.get_distro()
    return {
        'agent_version': constants.VERSION,
        'python_version': platform_utils.get_python_version(),
        'distro': distro[0],
        'distro_version': distro[1],
        'error': getattr(etype, '__name__', str(etype)),
        'details': details_sanitized,
        'traceback': ''.join(traceback.format_tb(tb, 100)),
        'attempts': getattr(value, 'attempts', 0),
    }


def send_exc():
    if config.UPDATE_FROM_LOCAL:  # pragma: no cover
        return

    trace = json.dumps(format_exception_without_details())
    encoded_trace = utils.nstr(base64.urlsafe_b64encode(utils.bstr(trace)))  # type: str
    url = utils.get_patch_server_url('/api/kcarectl-trace') + '?trace=' + encoded_trace
    request = http_utils.http_request(url, auth.get_http_auth_string())

    try:
        http_utils.urlopen_base(request)
    except Exception:
        # import traceback
        # traceback.print_exc()
        # we really don't interested in exception
        pass


def nohup_fork(func, sleep=None):  # pragma: no cover
    """
    Run func in a fork in an own process group
    (will stay alive after kcarectl process death).
    :param func: function to execute
    :return:
    """
    # TODO move to process_utils.py
    pid = os.fork()
    if pid != 0:
        os.waitpid(pid, 0)
        return

    os.setsid()

    pid = os.fork()
    if pid != 0:
        os._exit(0)

    # close standard files to release TTY
    os.close(0)

    # redirect stdout/stdin into log file
    with open(constants.LOG_FILE, 'a') as fd:
        os.dup2(fd.fileno(), 1)
        os.dup2(fd.fileno(), 2)

    if sleep:
        time.sleep(sleep)

    try:
        func()
    except Exception:
        log_utils.kcarelog.exception('Wait exception')
        os._exit(1)
    os._exit(0)


def touch_anchor():
    """Check the fact that there was a failed patching attempt.
    If anchor file not exists we should create an anchor with
    timestamp and schedule its deletion at $timeout.

    If anchor exists and its timestamp more than $timeout from now
    we should raise an error.
    """
    anchor_filepath = os.path.join(constants.PATCH_CACHE, '.kcareprev.lock')
    if os.path.isfile(anchor_filepath):
        with open(anchor_filepath, 'r') as afile:
            try:
                timestamp = int(afile.read())
                # anchor was created quite recently
                # that means that something went wrong
                if timestamp + config.SUCCESS_TIMEOUT > time.time():
                    raise PreviousPatchFailedException(timestamp, anchor_filepath)
            except ValueError:
                pass

    utils.atomic_write(anchor_filepath, utils.timestamp_str())  # write a new timestamp


def commit_update(state_data):
    """
    See touch_anchor() for detailed explanation of anchor mechanics.
    See KPT-730 for details about action registration.
    :param state_data: dict with current level, kernel_id etc.
    """
    try:
        os.remove(os.path.join(constants.PATCH_CACHE, '.kcareprev.lock'))
    except OSError:
        pass
    register_action('done', state_data)

    # reset module cache, to allow server_info get fresh data
    kcare.get_loaded_modules.clear()

    try:
        get_latest_patch_level(reason='done')
    except Exception:
        log_utils.kcarelog.exception('Cannot send update info!')


def clear_cache(khash, plevel):
    utils.clean_directory(os.path.join(constants.PATCH_CACHE, 'patches'), exclude_path=kcare.get_cache_path(khash, plevel, ''))


def get_current_level_path(khash, fname):
    prefix = config.PREFIX or 'none'
    module_dir = '-'.join([prefix, khash])
    result = (constants.PATCH_CACHE, 'modules', module_dir)  # type: Tuple[str, ...]
    if fname:
        result += (fname,)
    return os.path.join(*result)


def save_cache_latest(khash, patch_level):
    utils.atomic_write(get_current_level_path(khash, 'latest'), str(patch_level), ensure_dir=True)


def get_cache_latest(khash):
    # type: (str) -> Optional[kcare.LegacyKernelPatchLevel]
    path_with_latest = get_current_level_path(khash, 'latest')
    if os.path.isfile(path_with_latest):
        try:
            pl = int(open(path_with_latest, 'r').read().strip())
            return kcare.LegacyKernelPatchLevel(khash, pl)
        except (ValueError, TypeError):
            pass

    return None


class CertificateError(ValueError):
    pass


class UnknownKernelException(KcareError):
    def __init__(self):
        Exception.__init__(
            self,
            'New kernel detected ({0} {1} {2}).\nThere are no updates for this kernel yet.'.format(
                platform_utils.get_distro()[0], platform.release(), kcare.get_kernel_hash()
            ),
        )


class ApplyPatchError(KcareError):
    def __init__(self, code, freezer_style, level, patch_file, *args, **kwargs):
        super(ApplyPatchError, self).__init__(*args, **kwargs)
        self.code = code
        self.freezer_style = freezer_style
        self.level = level
        self.patch_file = patch_file
        self.distro = platform_utils.get_distro()[0]
        self.release = platform.release()

    def __str__(self):
        return 'Unable to apply patch ({0} {1} {2} {3} {4}, {5})'.format(
            self.patch_file,
            self.level,
            self.code,
            self.distro,
            self.release,
            ', '.join([str(i) for i in self.freezer_style]),
        )


# KCARE-509
class PreviousPatchFailedException(KcareError):
    def __init__(self, timestamp, anchor, *args, **kwargs):
        super(PreviousPatchFailedException, self).__init__(*args, **kwargs)
        self.timestamp = timestamp
        self.anchor = anchor

    def __str__(self):
        message = (
            'It seems, the latest patch, applying at {0}, crashed, '
            'and further attempts will be suspended. '
            'To force patch applying, remove `{1}` file'
        )
        return message.format(self.timestamp, self.anchor)


def set_monitoring_key_for_ip_license(key):
    url = ipv6_support.get_registration_url() + '/nagios/register_key.plain?key={0}'.format(key)
    try:
        response = http_utils.urlopen(url)
        res = utils.data_as_dict(utils.nstr(response.read()))
        code = int(res['code'])
        if code == 0:
            utils.print_wrapper('Key successfully registered')
        elif code == 1:
            utils.print_wrapper('Wrong key format or size')
        elif code == 2:
            utils.print_wrapper('No KernelCare license for that IP')
        else:
            utils.print_wrapper('Unknown error {0}'.format(code))
        return code
    except HTTPError as e:
        log_utils.print_cln_http_error(e, url)
    return -1


@contextmanager
def execute_hooks():
    if config.BEFORE_UPDATE_COMMAND:
        process_utils.run_command(config.BEFORE_UPDATE_COMMAND, shell=True)

    try:
        yield
    finally:
        if config.AFTER_UPDATE_COMMAND:
            process_utils.run_command(config.AFTER_UPDATE_COMMAND, shell=True)


def plugin_info(fmt=None):
    """
    The output will consist of:
    Ignore output up to the line with "--START--"
    Line 1: show if update is needed:
        0 - updated to latest,
        1 - update available,
        2 - unknown kernel
        3 - kernel doesn't need patches
        4 - no license, cannot determine
    Line 2: licensing message (can be skipped, can be more then one line)
    Line 3: LICENSE: CODE: 1: license present, 2: trial license present, 0: no license
    Line 4: Update mode (True - auto-update, False, no auto update)
    Line 5: Effective kernel version
    Line 6: Real kernel version
    Line 7: Patchset Installed # --> If None, no patchset installed
    Line 8: Uptime (in seconds)

    If *format* is 'json' return the results in JSON format.

    Any other output means error retrieving info
    :return:
    """

    pli = _patch_level_info()
    update_code = pli.code
    loaded_pl = pli.applied_lvl
    license_info_result = auth.license_info()

    if fmt == 'json':
        results = {
            'updateCode': str(update_code),
            'autoUpdate': config.AUTO_UPDATE,
            'effectiveKernel': kcare.kcare_uname(),
            'realKernel': platform.release(),
            'loadedPatchLevel': loaded_pl,
            'uptime': int(platform_utils.get_uptime()),
            'license': license_info_result,
        }
        utils.print_wrapper('--START--')
        utils.print_wrapper(json.dumps(results))
    else:
        utils.print_wrapper('--START--')
        utils.print_wrapper(str(update_code))
        utils.print_wrapper('LICENSE: ' + str(license_info_result))
        utils.print_wrapper(config.AUTO_UPDATE)
        utils.print_wrapper(kcare.kcare_uname())
        utils.print_wrapper(platform.release())
        utils.print_wrapper(loaded_pl)
        utils.print_wrapper(platform_utils.get_uptime())


def get_update_status():
    current_level = kcare.loaded_patch_level()
    try:
        latest_patch_level = get_latest_patch_level(reason='info')
    except UnknownKernelException:
        return 0 if config.IGNORE_UNKNOWN_KERNEL else 3

    if current_level is None:
        return 1

    if current_level >= latest_patch_level:
        return 0

    return 2 if update_utils.status_gap_passed() else 0


def edf_fallback_ptype():
    distro, version = platform_utils.get_distro()[:2]
    # From talk with @kolshanov
    if distro == 'CloudLinux' and version.startswith('7.'):
        return 'extra'
    else:
        return ''


# addr -> resolved_peer_addr map
CONNECTION_STICKY_MAP = {}  # type: Dict[Tuple[str, int], Tuple[Optional[str], int]]


def sticky_connect(self):
    """Function remembers IP address of host connected to
    and uses it for later connections.

    Replaces stdlib version of httplib.HTTPConnection.connect
    """
    addr = self.host, self.port
    resolved_addr = CONNECTION_STICKY_MAP.get(addr, addr)  # type: Tuple[Optional[str], int]
    self.sock = socket.create_connection(resolved_addr, self.timeout)
    self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    if addr not in CONNECTION_STICKY_MAP:
        CONNECTION_STICKY_MAP[addr] = self.sock.getpeername()[:2]

    if self._tunnel_host:
        self._tunnel()


httplib.HTTPConnection.connect = sticky_connect  # type: ignore[method-assign]


# python >= 2.7.9 stdlib (with ssl.HAS_SNI) is able to process https request on its own,
# for earlier versions manual checks should be done
if not getattr(ssl, 'HAS_SNI', None):  # pragma: no cover unit
    # TODO move to http_utils or py23
    try:
        import distutils.version

        import OpenSSL.SSL

        if distutils.version.StrictVersion(OpenSSL.__version__) < distutils.version.StrictVersion('0.13'):  # type: ignore[attr-defined]
            raise ImportError('No pyOpenSSL module with SNI ability.')
    except ImportError:
        pass
    else:

        def dummy_verify_callback(*args):
            # OpenSSL.SSL.Context.set_verify() requires callback
            # where additional checks could be done;
            # here is a dummy callback and a hostname check is made externally
            # to provide original exception from match_hostname()
            return True

        PureHTTPSConnection = httplib.HTTPSConnection

        class SSLSock(object):
            def __init__(self, sock):
                self._ssl_conn = sock
                self._makefile_refs = 0

            def makefile(self, *args):
                self._makefile_refs += 1
                return socket._fileobject(self._ssl_conn, *args, close=True)  # type: ignore[attr-defined]

            def close(self):
                if not self._makefile_refs and self._ssl_conn:
                    self._ssl_conn.close()
                    self._ssl_conn = None

            def sendall(self, *args):
                return self._ssl_conn.sendall(*args)

        class PyOpenSSLHTTPSConnection(httplib.HTTPSConnection):
            def connect(self):
                httplib.HTTPConnection.connect(self)

                # workaround to force pyopenssl to use TLSv1.2
                ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
                ctx.set_options(OpenSSL.SSL.OP_NO_SSLv2 | OpenSSL.SSL.OP_NO_SSLv3)

                if config.CHECK_SSL_CERTS:
                    ctx.set_verify(OpenSSL.SSL.VERIFY_PEER, dummy_verify_callback)
                else:
                    ctx.set_verify(OpenSSL.SSL.VERIFY_NONE, dummy_verify_callback)

                ctx.set_default_verify_paths()
                conn = OpenSSL.SSL.Connection(ctx, self.sock)
                conn.set_connect_state()

                # self._tunnel_host is an original hostname in case of proxy use
                server_host = self._tunnel_host or self.host  # type: ignore[attr-defined]
                conn.set_tlsext_host_name(server_host.encode())
                conn.do_handshake()
                if config.CHECK_SSL_CERTS:
                    match_hostname(conn.get_peer_certificate(), server_host)
                self.sock = SSLSock(conn)

        httplib.HTTPSConnection = PyOpenSSLHTTPSConnection  # type: ignore[misc]


def _fetch_patch_level_request(khash, latest, reason, mode):
    if config.UPDATE_FROM_LOCAL:
        url = kcare.get_kernel_prefixed_url(khash, latest)
        return fetch.wrap_with_cache_key(auth.urlopen_auth)(url, check_license=False)

    b64_encoding = latest not in ['latest.v1', 'latest.v2']

    for secure_boot_info, perf_metrics in [(True, b64_encoding), (False, b64_encoding), (False, False)]:  # pragma: no branch
        request_param = server_info.encoded_server_info(
            reason, b64_encoding=b64_encoding, secure_boot_info=secure_boot_info, perf_metrics=perf_metrics
        )
        if b64_encoding:
            request_param = 'info={0}'.format(request_param)

        url = kcare.get_kernel_prefixed_url(khash, stickyfy(latest, mode)) + '?' + request_param
        max_url_length = 7000  # the entire request should fit in 8K
        if (secure_boot_info or perf_metrics) and len(url) > max_url_length:
            discard_info = 'secure boot info' if secure_boot_info else 'perf metrics'
            log_utils.logwarn('Check-in URL param is too large, discarding %s', discard_info)
            continue
        try:
            return fetch.wrap_with_cache_key(auth.urlopen_auth)(url, check_license=False)
        except HTTPError as ex:
            if (secure_boot_info or perf_metrics) and (ex.code in (413, 414) or ex.code >= 500):
                log_utils.logwarn('Check-in request failed with error: {0}, retrying with reduced info'.format(ex))
                continue
            raise


def fetch_patch_level(reason, mode=constants.UPDATE_MODE_MANUAL):
    khash = kcare.get_kernel_hash()
    if config.PATCH_LEVEL is not None:
        return kcare.LegacyKernelPatchLevel(khash, int(config.PATCH_LEVEL))

    for latest in PATCH_LATEST:
        try:
            response = _fetch_patch_level_request(khash, latest, reason, mode)
            config_handlers.set_config_from_patchserver(response.headers)
            update_all_kmod_params()

            pl = utils.nstr(response.read()).strip()
            log_utils.loginfo('fetch patch level, reason: {0}, kernel latest response: {1}'.format(reason, pl), print_msg=False)
            if pl and pl.startswith('{'):
                latest_info = json_loads_nstr(pl)
                required_capabilities = latest_info.get('capabilities', [])
                if not capabilities.has_kc_capabilities(required_capabilities):
                    raise errors.CapabilitiesMismatch(
                        'Latest KernelCare patchset is incompatible with the current kernecare package version, please upgrade'
                    )
                return kcare.KernelPatchLevel(khash, latest_info['level'], latest_info['baseurl'], latest_info['release'])
            return kcare.LegacyKernelPatchLevel(khash, int(pl))
        except NotFound:
            # old ePortal version < 2.20 returns 404 for latest.v3 requests
            pass
        except HTTPError as ex:
            # No license - no access
            if ex.code in (403, 401):
                raise KcareError('KC licence is required')
            raise
    raise UnknownKernelException()


def probe_patch(level, ptype):
    bin_url = level.file_url(_apply_ptype(ptype, config.PATCH_BIN))
    log_utils.kcarelog.info('Probing patch URL: {0}'.format(bin_url))
    try:
        auth.urlopen_auth(bin_url, check_license=False, method='HEAD')
        return True
    except NotFound:
        log_utils.kcarelog.info('{0} is not available: 404'.format(bin_url))
        return False
    except Exception as ex:  # Fallback to GET in case of any error.
        log_utils.kcarelog.debug('HEAD request for {0} raised an error, fallback to the GET request: {1}'.format(bin_url, str(ex)))

    url = level.file_url(_apply_ptype(ptype, config.PATCH_BIN) + constants.SIG)
    log_utils.kcarelog.info('Probing patch URL: {0}'.format(url))

    try:
        auth.urlopen_auth(url, check_license=False)
    except NotFound:
        log_utils.kcarelog.info('{0} is not available: 404'.format(url))
        return False
    except URLError as ex:
        log_utils.kcarelog.info('{0} is not available: {1}'.format(url, str(ex)))
    return True


def fetch_and_verify_kernel_file(level, name):
    if name == constants.KMOD_BIN:
        url = level.kmod_url(constants.KMOD_BIN)
    else:
        url = level.file_url(name)
    dst = level.cache_path(name)
    return fetch.fetch_url(url, dst, config.USE_SIGNATURE, hash_checker=fetch.get_hash_checker(level))


class PatchFetcher(object):
    # TODO move to fetch.py
    def __init__(self, patch_level=None):
        self.patch_level = patch_level  # LegacyKernelPatchLevel or KernelPatchLevel

    def _fetch(self, name):
        return fetch_and_verify_kernel_file(self.patch_level, name)

    def is_patch_fetched(self):
        patch_done_path = self.patch_level.cache_path(config.PATCH_DONE)
        patch_bin_path = self.patch_level.cache_path(config.PATCH_BIN)
        patch_info_path = self.patch_level.cache_path(config.PATCH_INFO)
        kmod_bin_path = self.patch_level.cache_path(constants.KMOD_BIN)

        return (
            all(os.path.isfile(path) for path in (patch_done_path, patch_bin_path, patch_info_path, kmod_bin_path))
            and os.path.getsize(patch_bin_path) > 0
            and os.path.getsize(kmod_bin_path) > 0
        )

    def fetch_patch(self):
        utils.print_wrapper(
            "[DEBUG] [file: kcarectl/__init__.py, function: PatchFetcher.fetch_patch] start, patch_level={0!r}".format(
                self.patch_level
            )
        )
        if self.patch_level is None:
            utils.print_wrapper("[DEBUG] patch_level is None, raising ValueError")
            raise ValueError("Cannot fetch patch as no patch level is set")

        if not self.patch_level:  # level is 0, do nothing
            utils.print_wrapper("[DEBUG] patch_level is 0, nothing to fetch")
            return self.patch_level

        if self.is_patch_fetched():
            utils.print_wrapper("[DEBUG] patch {0} is already fetched, skipping download".format(self.patch_level))
            log_utils.loginfo('Updates already downloaded')
            return self.patch_level

        utils.print_wrapper("[DEBUG] patch {0} not fetched yet, downloading".format(self.patch_level))
        log_utils.loginfo('Downloading updates')

        # try to upgrade patch level
        if isinstance(self.patch_level, kcare.LegacyKernelPatchLevel):
            utils.print_wrapper("[DEBUG] legacy patch level, sending HEAD request to look for KC-Base-Url")
            try:
                resp = auth.urlopen_auth(self.patch_level.file_url(config.PATCH_BIN), method='HEAD')
            except NotFound:
                utils.print_wrapper("[DEBUG] HEAD request returned 404, keeping legacy patch level")
            else:
                baseurl = resp.headers.get('KC-Base-Url', None)
                utils.print_wrapper("[DEBUG] KC-Base-Url header: {0!r}".format(baseurl))
                if baseurl:
                    self.patch_level = self.patch_level.upgrade(utils.nstr(baseurl))
                    utils.print_wrapper("[DEBUG] patch level upgraded, baseurl={0}".format(self.patch_level.baseurl))

        try:
            utils.print_wrapper("[DEBUG] fetching patch binary: {0}".format(config.PATCH_BIN))
            self._fetch(config.PATCH_BIN)
        except NotFound:
            utils.print_wrapper("[DEBUG] patch binary not found (404)")
            raise KcareError(
                'The `{0}` patch level is not found for `{1}` patch type. '
                'Please select valid patch type or patch level'.format(self.patch_level, config.PATCH_TYPE or 'default')
            )

        utils.print_wrapper("[DEBUG] fetching patch info: {0}".format(config.PATCH_INFO))
        self._fetch(config.PATCH_INFO)
        utils.print_wrapper("[DEBUG] fetching kmod: {0}".format(constants.KMOD_BIN))
        self._fetch(constants.KMOD_BIN)

        utils.print_wrapper("[DEBUG] extracting blacklist")
        self.extract_blacklist()
        utils.atomic_write(self.patch_level.cache_path(config.PATCH_DONE), b'', mode='wb')
        utils.print_wrapper("[DEBUG] wrote patch done marker: {0}".format(self.patch_level.cache_path(config.PATCH_DONE)))
        selinux.restore_selinux_context(constants.PATCH_CACHE)
        utils.print_wrapper("[DEBUG] fetch_patch finished, returning {0!r}".format(self.patch_level))
        return self.patch_level

    def extract_blacklist(self):
        buf = open(self.patch_level.cache_path(config.PATCH_INFO), 'r').read()
        if buf:
            mo = BLACKLIST_RE.search(buf)
            if mo:
                utils.atomic_write(self.patch_level.cache_path(config.BLACKLIST_FILE), mo.group(1))

    def fetch_fixups(self, level):
        """
        Download fixup files for defined patch level
        :param level: download fixups for this patch level (usually it's a level of loaded patch)
        :return: None
        """
        if level is None:
            return

        try:
            # never use cache for fixup files, must be downloaded from scratch
            resp = fetch_and_verify_kernel_file(level, config.FIXUPS_FILE)
        except NotFound:
            return

        # Upgrade level to a new format with baseurl to fetch fixup files
        baseurl = resp.headers.get('KC-Base-Url', None)
        if baseurl:
            level = level.upgrade(utils.nstr(baseurl))

        fixups_fname = level.cache_path(config.FIXUPS_FILE)
        with open(fixups_fname, 'r') as f:
            fixups = set([fixup.strip() for fixup in f.readlines()])

        for fixup in fixups:
            fetch_and_verify_kernel_file(level, fixup)

        selinux.restore_selinux_context(constants.PATCH_CACHE)


def kcare_check():
    pli = _patch_level_info()
    utils.print_wrapper(pli.msg)
    if pli.code == PLI.PATCH_NEED_UPDATE:
        sys.exit(0)
    else:
        sys.exit(1)


def show_generic_info():
    pli = _patch_level_info()
    kcare_info = _kcare_patch_info_json(pli)

    try:
        libcare_info = libcare.libcare_patch_info_basic()
    except KcareError:
        libcare_info = {}

    state = kcare.get_state()
    latest_update = "Unknown"
    if state is not None:
        latest_update = datetime.fromtimestamp(state['ts']).strftime('%Y-%m-%d')

    effective_version = kcare.kcare_uname()
    kernel_vulnerabilities = len(kcare_info.get('patches', []))
    userspace_vulnerabilities = sum(len(rec.get('patches', [])) for rec in libcare_info)

    patch_level = kcare.loaded_patch_level()
    if not patch_level:
        utils.print_wrapper("KernelCare live patching is disabled")
    else:
        utils.print_wrapper("KernelCare live patching is active")

    utils.print_wrapper(" - Last updated on {0}".format(latest_update))
    utils.print_wrapper(" - Effective kernel version {0}".format(effective_version))
    if kernel_vulnerabilities > 0:
        utils.print_wrapper(" - {0} kernel vulnerabilities live patched".format(kernel_vulnerabilities))
    if userspace_vulnerabilities > 0:
        utils.print_wrapper(" - {0} userspace vulnerabilities live patched".format(userspace_vulnerabilities))
    if kernel_vulnerabilities + userspace_vulnerabilities == 0:
        utils.print_wrapper(" - This system has no applied patches")
    utils.print_wrapper("Type kcarectl --patch-info to learn more")


def kcare_latest_patch_info(is_json=False):
    """
    Retrieve and output to STDOUT latest patch info, so it is easy to get
    list of CVEs in use. More info at
    https://cloudlinux.atlassian.net/browse/KCARE-952
    :return: None
    """
    try:
        latest = get_latest_patch_level(reason='info', policy=constants.POLICY_REMOTE)
        if not latest:
            raise UnknownKernelException
        url = latest.file_url(config.PATCH_INFO)
        patch_info = utils.nstr(auth.urlopen_auth(url).read())
        if is_json:
            patches, result = [], {}
            for chunk in patch_info.split('\n\n'):
                data = utils.data_as_dict(chunk)
                if data and 'kpatch-name' in data:
                    patches.append(data)
                else:
                    result.update(data)
            result['patches'] = patches  # type: ignore[assignment]
            patch_info = json.dumps(result)
        utils.print_wrapper(patch_info)
    except HTTPError as e:
        log_utils.print_cln_http_error(e, e.url)
        return 1
    except UnknownKernelException:
        utils.print_wrapper('No patches available')
    return 0


def _kcare_patch_info_json(pli):
    result = {'message': pli.msg}

    if pli.applied_lvl is not None:
        patch_info = _kcare_patch_info(pli)
        patches = []
        for chunk in patch_info.split('\n\n'):
            data = utils.data_as_dict(chunk)
            if data and 'kpatch-name' in data:
                patches.append(data)
            else:
                result.update(data)
        result['patches'] = patches

        saved_patch_level = kcare.read_dumped_kernel_patch_level()
        result['release'] = saved_patch_level['release'] if saved_patch_level else 'unknown'

    return result


def _kcare_patch_info(pli):
    khash = kcare.get_kernel_hash()
    cache_path = kcare.get_cache_path(khash, pli.applied_lvl, config.PATCH_INFO)
    if not os.path.isfile(cache_path):
        raise KcareError(
            "Can't find information due to the absent patch information file."
            " Please, run /usr/bin/kcarectl --update and try again."
        )
    info = open(cache_path, 'r').read()
    if info:
        info = BLACKLIST_RE.sub('', info)
    return info


def patch_info(is_json=False):
    pli = _patch_level_info()
    if not is_json:
        if pli.code != 0:
            utils.print_wrapper(pli.msg)
        if pli.applied_lvl is None:
            return
        utils.print_wrapper(_kcare_patch_info(pli))
    else:
        utils.print_wrapper(json.dumps(_kcare_patch_info_json(pli), sort_keys=True))


def is_same_patch(new_patch_file):  # mocked: tests/unit
    args = [constants.KPATCH_CTL, 'file-info', new_patch_file]
    new_patch_info = process_utils.check_output(args)
    current_patch_info = kcare._patch_info()
    build_time_label = 'kpatch-build-time'
    return kcare.get_patch_value(new_patch_info, build_time_label) == kcare.get_patch_value(current_patch_info, build_time_label)


def kcare_need_update(applied_level, new_level):
    utils.print_wrapper(
        "[DEBUG] [file: kcarectl/__init__.py, function: kcare_need_update] start, applied_level={0}, new_level={1}".format(
            applied_level, new_level
        )
    )
    if new_level == 0:
        utils.print_wrapper("[DEBUG] new_level is 0, no update needed")
        return False

    # ignore down-patching
    if applied_level and new_level < applied_level:
        utils.print_wrapper("[DEBUG] new_level < applied_level (down-patching), no update needed")
        return False

    if applied_level != new_level:
        utils.print_wrapper("[DEBUG] applied_level != new_level, update needed")
        return True

    new_patch_file = kcare.get_cache_path(kcare.get_kernel_hash(), new_level, config.PATCH_BIN)
    utils.print_wrapper("[DEBUG] levels are equal, comparing patch file {0} with the loaded patch".format(new_patch_file))
    if not is_same_patch(new_patch_file):
        utils.print_wrapper("[DEBUG] patch content differs (build time), update needed")
        return True

    utils.print_wrapper("[DEBUG] same patch already applied, no update needed")
    return False


def update_sysctl():
    # TODO move to platform_utils.py
    if config.UPDATE_SYSCTL_CONFIG:
        if not (os.path.isfile(SYSCTL_CONFIG) and os.access(SYSCTL_CONFIG, os.R_OK)):
            log_utils.kcarelog.warning('File {0} does not exist or has no read access'.format(SYSCTL_CONFIG))
            return
        code, _, _ = process_utils.run_command(['/sbin/sysctl', '-q', '-p', SYSCTL_CONFIG], catch_stdout=True)
        if code != 0:
            log_utils.kcarelog.warning('Unable to load kcare sysctl.conf: {0}'.format(code))


def edit_sysctl_conf(remove, append):
    """Update SYSCTL_CONFIG accordingly the edits"""
    # TODO move to platform_utils.py
    # Create if it does not exist
    if not os.path.isfile(SYSCTL_CONFIG):
        open(SYSCTL_CONFIG, 'a').close()

    # Check kcare sysctl path and read access
    if not os.access(SYSCTL_CONFIG, os.R_OK):
        log_utils.kcarelog.warning('File {0} has no read access'.format(SYSCTL_CONFIG))
        return

    with open(SYSCTL_CONFIG, 'r+') as sysctl:
        lines = sysctl.readlines()
        sysctl.seek(0)
        for line in lines:
            # Do not rewrite lines that should be deleted
            if not any(line.startswith(r) for r in remove):
                sysctl.write(line)
        # Write additional lines
        for a in append:
            sysctl.write(a + '\n')
        sysctl.truncate()


def detect_conflicting_modules(modules):
    for module in modules:
        if CONFLICTING_MODULES_RE.match(module):
            raise KcareError("Detected '{0}' kernel module loaded. Please unload that module first".format(module))


def get_kcare_kmod_link():
    return '/lib/modules/{0}/extra/kcare.ko'.format(platform_utils.get_system_uname())


def kmod_is_signed():
    level = get_latest_patch_level(reason='info')
    kmod_file = kcare.get_cache_path(kcare.get_kernel_hash(), level, constants.KMOD_BIN)
    if not os.path.isfile(kmod_file):
        return None
    with open(kmod_file, 'rb') as vfd:
        return vfd.read()[-28:] == b'~Module signature appended~\n'


def kcare_certs_enrolled():  # pragma: no cover
    system_keys = utils.try_to_read('/proc/keys')
    if system_keys is None:
        return None
    kcare_keys = [
        '12ff0613c0f80cfba3b2f8eba71ebc27c5a76170',  # CloudLinux key
        '69a6d9eed3f620d5c2e13a1d211c46510a5ad9f5',  # AlmaLinux kpatch signing key
    ]
    return any(key in system_keys for key in kcare_keys)


def load_kmod(kmod, **kwargs):
    cmd = ['/sbin/insmod', kmod]
    for key, value in kwargs.items():
        cmd.append('{0}={1}'.format(key, value))
    code, _, _ = process_utils.run_command(cmd, catch_stdout=True)
    if code != 0:
        raise KcareError('Unable to load kmod ({0} {1}). Try to run with `--check-compatibility` flag.'.format(kmod, code))


def check_compatibility():
    if platform_utils.is_secure_boot():
        if kmod_is_signed() is False:
            raise KcareError('Secure boot is enabled. Not supported by KernelCare.')
        if kcare_certs_enrolled() is False:
            raise KcareError('Secure boot is enabled. No KernelCare certificates enrolled.')
    if platform_utils.inside_vz_container() or platform_utils.inside_lxc_container() or platform_utils.inside_docker_container():
        raise KcareError('You are running inside a container. Kernelcare should be executed on host side instead.')


def check_patch_type_compatibility(ptype):
    # type: (str) -> None
    # TODO KPT-4474 patch type autodetection
    utils.print_wrapper(
        "[DEBUG] [file: kcarectl/__init__.py, function: check_patch_type_compatibility] start, ptype={0!r}".format(ptype)
    )
    cmd = process_utils.find_cmd('modinfo')
    utils.print_wrapper("[DEBUG] modinfo command: {0}".format(cmd))
    has_kmodlve = process_utils.run_command([cmd, 'kmodlve'], catch_stdout=True, catch_stderr=True)[0] == 0
    utils.print_wrapper("[DEBUG] has_kmodlve: {0}".format(has_kmodlve))

    if has_kmodlve and ptype in ('free', 'extra'):
        # KPT-4269 kcarectl: free/extra patches confict with kmodlve
        utils.print_wrapper("[DEBUG] conflict detected: {0} patch type with kmodlve, exiting".format(ptype))
        log_utils.logerror('{0} patch type conflicts with kmodlve kernel module'.format(ptype))
        sys.exit(1)
    utils.print_wrapper("[DEBUG] check_patch_type_compatibility: no conflict")


def get_kmod_available_params(kcare_link):
    stdout = process_utils.check_output(["/sbin/modinfo", "-F", "parm", kcare_link])
    available_params = []
    for line in stdout.split('\n'):
        if line.strip():
            param_name, _, _ = line.partition(':')
            available_params.append(param_name)
    return available_params


def make_kmod_new_params():
    return {
        'kpatch_debug': 1 if config.KPATCH_DEBUG else 0,
        'kmsg_output': 1 if config.KMSG_OUTPUT else 0,
        'kcore_output': config.KCORE_OUTPUT_SIZE if config.KCORE_OUTPUT else 0,
        'kdumps_dir': config.KDUMPS_DIR if isinstance(config.KDUMPS_DIR, str) else "",
        'enable_crashreporter': 1 if config.ENABLE_CRASHREPORTER else 0,
    }


def update_all_kmod_params():
    if config.KDUMPS_DIR and not os.path.exists(config.KDUMPS_DIR):
        os.makedirs(config.KDUMPS_DIR)

    for param, val in make_kmod_new_params().items():
        update_kmod_param(param, val)


def update_kmod_param(kmod_param_name, param_value):
    params_root = '/sys/module/kcare/parameters'
    param_path = os.path.join(params_root, kmod_param_name)

    if not os.path.exists(param_path):
        return

    try:
        with open(param_path, 'w') as f:
            f.write(str(param_value))
    except Exception:  # pragma: no cover
        log_utils.kcarelog.error('failed to set %s kmod param to %s', kmod_param_name, param_value)


def load_kcare_kmod(khash, level):
    # To make `kdump` service work. We need to copy
    # `kcare.ko` into `/lib/modules/$(uname -r)/extra/kcare.ko`
    # and call `/sbin/depmod`
    kcare_link = get_kcare_kmod_link()
    kcare_file = kcare.get_cache_path(khash, level, constants.KMOD_BIN)
    try:
        shutil.copy(kcare_file, kcare_link)
    except Exception:
        kcare_link = kcare_file

    if config.KDUMPS_DIR and not os.path.exists(config.KDUMPS_DIR):
        os.makedirs(config.KDUMPS_DIR)

    kmod_params = make_kmod_new_params()
    available_kmod_params = get_kmod_available_params(kcare_link)
    kmod_params = dict((k, v) for k, v in kmod_params.items() if k in available_kmod_params)

    load_kmod(kcare_link, **kmod_params)
    update_depmod()


def update_depmod(uname=None):
    cmd = [
        '/sbin/depmod',
    ]
    if uname is not None:
        cmd.extend(['-a', uname])
    code, _, stderr = process_utils.run_command(cmd, catch_stdout=True, catch_stderr=True)
    if code:
        # We don't want to show the error to the user but want to see it in logs
        log_utils.logerror('Running of `{0}` failed with {1}: {2}'.format(' '.join(cmd), code, stderr), print_msg=False)


def unload_kmod(modname):
    code, _, _ = process_utils.run_command(['/sbin/rmmod', modname], catch_stdout=True)
    if code != 0:
        raise KcareError('Unable to unload {0} kmod {1}'.format(modname, code))


def apply_fixups(khash, current_level, modules):
    loaded = []
    for mod in ['vmlinux'] + modules:
        modpath = kcare.get_cache_path(khash, current_level, 'fixup_{0}.ko'.format(mod))
        if os.path.exists(modpath):
            load_kmod(modpath)
            loaded.append('fixup_{0}'.format(mod))
    return loaded


def remove_fixups(fixups):
    for mod in fixups:
        try:
            unload_kmod(mod)
        except Exception:
            log_utils.kcarelog.exception('Exception while unloading module %s.' % mod)


def get_freezer_style(freezer, modules):
    if freezer:
        method = freezer
    elif config.PATCH_METHOD:
        method = config.PATCH_METHOD
    elif get_freezer_blacklist().intersection(modules):
        # blacklist module found, use smart freezer
        # xxx: this branch could be safely removed when smart would work by default
        return 'freeze_conflict', freezer, config.PATCH_METHOD, True
    else:
        # user doesn't provide patch method and no conflicting modules loaded
        return 'default', freezer, config.PATCH_METHOD, False

    # non default patch method, translate it into form accepted by kpatch_ctl
    patch_method_map = {
        'NONE': 'freeze_none',
        'NOFREEZE': 'freeze_none',
        'FULL': 'freeze_all',
        'FREEZE': 'freeze_all',
        'SMART': 'freeze_conflict',
    }

    method = method.upper()

    if method in patch_method_map:
        method = patch_method_map[method]
    else:
        raise KcareError('Unable to detect freezer style ({0}, {1}, {2}, {3})'.format(method, freezer, config.PATCH_METHOD, False))
    return method, freezer, config.PATCH_METHOD, False


def kcare_load(khash, level, mode, freezer='', use_anchor=False):
    state_data = {'khash': khash, 'future': level, 'mode': mode}
    register_action('start', state_data)

    current_level = kcare.loaded_patch_level()
    modules = kcare.get_loaded_modules()

    detect_conflicting_modules(modules)

    # get freezer in the beginning to prevent any further job in case of exception
    freezer_style = get_freezer_style(freezer, modules)

    patch_file = kcare.get_cache_path(khash, level, config.PATCH_BIN)
    save_cache_latest(khash, level)

    description = '{0}-{1}:{2};{3}'.format(
        level, config.PATCH_TYPE, utils.timestamp_str(), kcare.parse_uname(level)  # future server_info['ltimestamp']
    )

    kmod_loaded = 'kcare' in modules
    kmod_changed = kmod_loaded and kcare.is_kmod_version_changed(khash, level)
    patch_loaded = current_level is not None
    same_patch = patch_loaded and is_same_patch(patch_file) and kcare.kcare_update_effective_version(description)

    state_data.update({'current': current_level, 'kmod_changed': kmod_changed})

    if same_patch:
        register_action('done', state_data)
        return

    if patch_loaded:
        register_action('fxp', state_data)
        fixups = apply_fixups(khash, current_level, modules)
        register_action('unpatch', state_data)
        kpatch_ctl_unpatch(freezer_style)
        register_action('unfxp', state_data)
        remove_fixups(fixups)

    if kmod_changed:
        register_action('unload', state_data)
        unload_kmod('kcare')
        kmod_loaded = False

    if not kmod_loaded:
        register_action('load', state_data)
        load_kcare_kmod(khash, level)

    if use_anchor:  # KCARE-509
        touch_anchor()

    register_action('patch', state_data)
    kpatch_ctl_patch(patch_file, khash, level, description, freezer_style)
    update_sysctl()
    log_utils.loginfo('Patch level {0} applied. Effective kernel version {1}'.format(level, kcare.kcare_uname()))

    # Update last status check timestamp
    update_utils.touch_status_gap_file()

    # do final actions when update is considered as successful
    register_action('wait', state_data)
    nohup_fork(lambda: commit_update(state_data), sleep=config.SUCCESS_TIMEOUT)


def kpatch_ctl_patch(patch_file, khash, level, description, freezer_style):
    utils.print_wrapper(
        "[DEBUG] [file: kcarectl/__init__.py, function: kpatch_ctl_patch] start, patch_file={0}, level={1}, description={2!r}, freezer_style={3}".format(
            patch_file, level, description, freezer_style
        )
    )
    args = [constants.KPATCH_CTL]
    blacklist_file = kcare.get_cache_path(khash, level, config.BLACKLIST_FILE)
    if os.path.exists(blacklist_file):
        utils.print_wrapper("[DEBUG] blacklist file found: {0}".format(blacklist_file))
        args.extend(['-b', blacklist_file])
    else:
        utils.print_wrapper("[DEBUG] no blacklist file at {0}".format(blacklist_file))
    args.extend(['patch', '-d', description])
    args.extend(['-m', freezer_style[0]])
    args.append(patch_file)
    utils.print_wrapper("[DEBUG] running kpatch_ctl command: {0}".format(args))
    code, _, _ = process_utils.run_command(args, catch_stdout=True)
    utils.print_wrapper("[DEBUG] kpatch_ctl patch exit code: {0}".format(code))
    if code != 0:
        utils.print_wrapper("[DEBUG] kpatch_ctl patch failed, raising ApplyPatchError")
        raise ApplyPatchError(code, freezer_style, level, patch_file)
    utils.print_wrapper("[DEBUG] kpatch_ctl patch applied successfully")


def kpatch_ctl_unpatch(freezer_style):
    # TODO KPT-4001 refactoring, extract kpatch_ctl run to a class with patch/unpatch/etc methods with logging and error handling
    code, stdout, stderr = process_utils.run_command(
        [constants.KPATCH_CTL, 'unpatch', '-m', freezer_style[0]], catch_stdout=True, catch_stderr=True
    )
    if code != 0:
        log_utils.logerror('Error unpatching, kpatch_ctl stdout:\n{0}\nstderr:\n{1}'.format(stdout, stderr), print_msg=False)
        raise KcareError('Error unpatching [{0}] {1}'.format(code, str(freezer_style)))


def register_action(action, state_data):
    state_data['action'] = action
    state_data['ts'] = int(time.time())
    utils.atomic_write(os.path.join(constants.PATCH_CACHE, 'kcare.state'), str(state_data))


def update_weak_modules(kmod_link):
    modules_path = '/usr/lib/modules/'
    if not os.path.isdir(modules_path):
        return

    for entry in os.listdir(modules_path):
        sym_link_path = os.path.join(modules_path, entry, 'weak-updates', 'kcare.ko')
        if not os.path.islink(sym_link_path):
            continue

        target_path = os.readlink(sym_link_path)
        if target_path == kmod_link:
            os.unlink(sym_link_path)
            update_depmod(entry)


def kcare_unload(freezer='', force=False):
    current_level = kcare.loaded_patch_level()

    pf = PatchFetcher()
    try:
        pf.fetch_fixups(current_level)
    except Exception as err:
        if not force:
            raise KcareError(
                "Unable to retrieve fixups: '{0}'. The unloading of patches has been "
                "interrupted. To proceed without fixups, use the --force flag.".format(err)
            )

    modules = kcare.get_loaded_modules()
    freezer_style = get_freezer_style(freezer, modules)

    with execute_hooks():
        if 'kcare' in modules:
            need_unpatch = current_level is not None
            if need_unpatch:
                fixups = apply_fixups(kcare.get_kernel_hash(), current_level, modules)
                code, stdout, stderr = process_utils.run_command(
                    [constants.KPATCH_CTL, 'unpatch', '-m', freezer_style[0]], catch_stdout=True, catch_stderr=True
                )
                remove_fixups(fixups)
                if code != 0:
                    log_utils.logerror(
                        'Error unpatching, kpatch_ctl stdout:\n{0}\nstderr:\n{1}'.format(stdout, stderr), print_msg=False
                    )
                    raise KcareError('Error unpatching [{0}] {1}'.format(code, str(freezer_style)))

            # Unload kcare module and retry once after 10 seconds if failed
            # Kernel module could be loaded even if patch is not applyed
            utils.retry(errors.check_exc(KcareError), count=1, delay=UNLOAD_RETRY_DELAY)(unload_kmod)('kcare')

        kmod_link = get_kcare_kmod_link()
        if os.path.isfile(kmod_link):
            os.unlink(kmod_link)

        # KPT-3469 fix the case with kernel upgrade where third party modules are linked under
        # /usr/lib/modules/{uname_r}/weak-updates/kcare.ko so that kdump work good
        update_weak_modules(kmod_link)


def kcare_info(is_json):
    pli = _patch_level_info()

    if is_json:
        return _kcare_info_json(pli)
    else:
        if pli.code != 0:
            return pli.msg
        if pli.applied_lvl is not None:
            return kcare._patch_info()


def _kcare_info_json(pli):
    result = {'message': pli.msg}

    if pli.applied_lvl is not None:
        result.update(utils.data_as_dict(kcare._patch_info()))
        result.update(kcare.parse_patch_description(result.get('kpatch-description')))

    result['kpatch-state'] = pli.state

    return json.dumps(result)


class PLI:
    PATCH_LATEST = 0
    PATCH_NEED_UPDATE = 1
    PATCH_UNAVALIABLE = 2
    PATCH_NOT_NEEDED = 3

    def __init__(self, code, msg, remote_lvl, applied_lvl, state):
        self.code = code
        self.msg = msg
        self.remote_lvl = remote_lvl
        self.applied_lvl = applied_lvl
        self.state = state


def _patch_level_info():
    current_patch_level = kcare.loaded_patch_level()
    try:
        # this line raises UnknownKernel from the bottom of this try
        new_patch_level = get_latest_patch_level(reason='info')

        if current_patch_level:
            if kcare_need_update(current_patch_level, new_patch_level):
                code, msg, state = (
                    PLI.PATCH_NEED_UPDATE,
                    "Update available, run 'kcarectl --update'.",
                    'applied',
                )
            else:
                code, msg, state = (
                    PLI.PATCH_LATEST,
                    'The latest patch is applied.',
                    'applied',
                )
        else:
            # no patch applied
            if new_patch_level == 0:
                code, msg, state = (
                    PLI.PATCH_NOT_NEEDED,
                    "This kernel doesn't require any patches.",
                    'unset',
                )
            else:
                code, msg, state = (
                    PLI.PATCH_NEED_UPDATE,
                    "No patches applied, but some are available, run 'kcarectl --update'.",
                    'unset',
                )
        info = PLI(code, msg, new_patch_level, current_patch_level, state)
    except UnknownKernelException:
        code = PLI.PATCH_UNAVALIABLE
        if config.STICKY_PATCH:
            msg = (
                'Invalid sticky patch tag {0} for kernel ({1} {2}). '
                'Please check /etc/sysconfig/kcare/kcare.conf '
                'STICKY_PATCH settings'.format(config.STICKY_PATCH, platform_utils.get_distro()[0], platform.release())
            )
        else:
            msg = 'New kernel detected ({0} {1} {2}).\nThere are no updates for this kernel yet.'.format(
                platform_utils.get_distro()[0], platform.release(), kcare.get_kernel_hash()
            )
        info = PLI(code, msg, None, None, 'unavailable')
    return info


def tag_server(tag):
    """
    Request to tag server from ePortal. See KCARE-947 for more info

    :param tag: String used to tag the server
    :return: 0 on success, -1 on wrong server id, other values otherwise
    """
    url = None
    try:
        # TODO: is it ok to send request in case when no server_id found? (machine is not registered in ePortal)
        server_id = serverid.get_serverid()
        query = urlencode([('server_id', server_id), ('tag', tag)])
        url = ipv6_support.get_registration_url() + '/tag_server.plain?{0}'.format(query)
        response = http_utils.urlopen(url)
        res = utils.data_as_dict(utils.nstr(response.read()))
        return int(res['code'])
    except HTTPError as e:
        log_utils.print_cln_http_error(e, url)
        return -3
    except URLError as ue:
        log_utils.print_cln_http_error(ue, url)
        return -4
    except Exception as ee:
        log_utils.logerror('Internal Error {0}'.format(ee))
        return -5


def kcdoctor():
    doctor_url = utils.get_patch_server_url("doctor.sh")
    log_utils.logdebug("Requesting doctor script from `{0}`".format(doctor_url))
    doctor_filename = KCDOCTOR
    with tempfile.NamedTemporaryFile() as doctor_dst:
        try:
            signature = fetch.fetch_signature(doctor_url, doctor_dst.name)
            utils.save_to_file(http_utils.urlopen(doctor_url), doctor_dst.name)
            fetch.check_gpg_signature(doctor_dst.name, signature)
            doctor_filename = doctor_dst.name
        except Exception as err:
            log_utils.logerror('Kcare doctor error: {0}. Fallback to the local one.'.format(err))
        code, _, stderr = process_utils.run_command(['bash', doctor_filename, ipv6_support.get_patch_server()], catch_stderr=True)
        if code:
            raise KcareError("Script failed with '{0}' {1}".format(stderr, code))


def check_new_kc_version():
    utils.print_wrapper("[DEBUG] [file: kcarectl/__init__.py, function: check_new_kc_version] start")
    url = utils.get_patch_server_url('{0}-new-version'.format(EFFECTIVE_LATEST))
    utils.print_wrapper("[DEBUG] new version check url: {0}".format(url))
    try:
        http_utils.urlopen(url)
    except URLError as e:
        utils.print_wrapper("[DEBUG] URLError while checking new version ({0}), no new version assumed".format(e))
        return False
    utils.print_wrapper("[DEBUG] new version URL responded, a new KernelCare package version is available")
    log_utils.loginfo(
        'A new version of the KernelCare package is available. To continue to get kernel updates, please install the new version'
    )
    return True


# mocked: tests/unit/test_patch_level_info.py
def get_latest_patch_level(reason, policy=constants.POLICY_REMOTE, mode=constants.UPDATE_MODE_MANUAL):
    """
    Get patch level to apply.
    :param reason: what was the source of request (update, info etc.)
    :param policy: REMOTE -- get latest patch_level from patchserver,
                   LOCAL -- use cached latest,
                   LOCAL_FIRST -- if cached level is None get latest from patchserver, use cache otherwise
    :param mode: constants.UPDATE_MODE_MANUAL, constants.UPDATE_MODE_AUTO or constants.UPDATE_MODE_SMART
    :return: patch_level string
    """
    utils.print_wrapper(
        "[DEBUG] [file: kcarectl/__init__.py, function: get_latest_patch_level] start, reason={0!r}, policy={1!r}, mode={2!r}".format(
            reason, policy, mode
        )
    )

    khash = kcare.get_kernel_hash()
    cached_level = get_cache_latest(khash)
    consider_remote_ex = policy == constants.POLICY_REMOTE or (policy == constants.POLICY_LOCAL_FIRST and cached_level is None)
    utils.print_wrapper(
        "[DEBUG] khash={0}, cached_level={1}, consider_remote_ex={2}".format(khash, cached_level, consider_remote_ex)
    )

    try:
        utils.print_wrapper("[DEBUG] fetching remote patch level")
        remote_level = fetch_patch_level(reason, mode)
        utils.print_wrapper("[DEBUG] remote_level={0}".format(remote_level))
    except errors.CapabilitiesMismatch as e:
        utils.print_wrapper("[DEBUG] CapabilitiesMismatch: {0}, cached_level={1}".format(e, cached_level))
        if cached_level is None:
            # error will be logged in __main__.py
            raise

        log_utils.logwarn(str(e))
        log_utils.logwarn('Using previously downloaded patches')
        # force using already downloaded patches
        policy = constants.POLICY_LOCAL
        utils.print_wrapper("[DEBUG] policy forced to LOCAL")
    except Exception as ex:
        utils.print_wrapper("[DEBUG] fetch_patch_level failed: {0!r}, consider_remote_ex={1}".format(ex, consider_remote_ex))
        if consider_remote_ex:
            raise
        else:
            log_utils.kcarelog.warning('Unable to send data: {0}'.format(ex))

    if policy == constants.POLICY_REMOTE:
        level = remote_level
        utils.print_wrapper("[DEBUG] policy REMOTE, using remote level {0}".format(level))
    else:
        level = cached_level
        utils.print_wrapper("[DEBUG] policy {0!r}, using cached level {1}".format(policy, level))
        if cached_level is None:
            if policy == constants.POLICY_LOCAL:
                level = kcare.LegacyKernelPatchLevel(khash, 0)
                utils.print_wrapper("[DEBUG] no cache, LOCAL policy, level set to 0")
            elif policy == constants.POLICY_LOCAL_FIRST:
                level = remote_level
                utils.print_wrapper("[DEBUG] no cache, LOCAL_FIRST policy, using remote level {0}".format(level))
            else:
                utils.print_wrapper("[DEBUG] unknown policy {0!r}".format(policy))
                raise KcareError('Unknown policy, choose one of: REMOTE, LOCAL, LOCAL_FIRST')
    utils.print_wrapper("[DEBUG] get_latest_patch_level returning {0}".format(level))
    return level


def update_patch_type(ptype):
    if ptype == 'edf':
        # The only way user can get here if call kcarectl --set-patch-type
        # we don't support this anyway and can silently ignore
        return

    config.PATCH_TYPE = '' if ptype == 'default' else ptype

    if probe_patch(fetch_patch_level(reason='probe'), config.PATCH_TYPE):
        config_handlers.update_config(PATCH_TYPE=config.PATCH_TYPE)
        if config.PATCH_TYPE in ('free', 'extra') and platform_utils.is_cpanel():
            gid = config.FORCE_GID or CPANEL_GID
            edit_sysctl_conf(
                ('fs.enforce_symlinksifowner', 'fs.symlinkown_gid'),
                ('fs.enforce_symlinksifowner=1', 'fs.symlinkown_gid={0}'.format(gid)),
            )

        log_utils.loginfo("'{0}' patch type selected".format(ptype))
    else:
        raise KcareError("'{0}' patch type is unavailable for your kernel".format(ptype))


def do_update(freezer, mode, policy=constants.POLICY_REMOTE):
    """
    :param mode: constants.UPDATE_MODE_MANUAL, constants.UPDATE_MODE_AUTO or constants.UPDATE_MODE_SMART
    :param policy: REMOTE -- download latest and patches from patchserver,
                   LOCAL -- use cached files,
                   LOCAL_FIRST -- download latest and patches if cached level is None, use cache in other cases
    :param freezer: freezer mode
    """
    process_utils.log_all_parent_processes()
    check_patch_type_compatibility(config.PATCH_TYPE)

    if policy == constants.POLICY_REMOTE:
        check_new_kc_version()

    try:
        level = get_latest_patch_level(reason='update', policy=policy, mode=mode)
    except UnknownKernelException as e:
        if mode in (constants.UPDATE_MODE_AUTO, constants.UPDATE_MODE_SMART) and config.IGNORE_UNKNOWN_KERNEL:
            msg = str(e)
            log_utils.kcarelog.warning(msg)
            return
        raise

    current_level = kcare.loaded_patch_level()
    pf = PatchFetcher(level)
    pf.fetch_patch()

    if not kcare_need_update(applied_level=current_level, new_level=level):
        log_utils.loginfo('No updates are needed for this kernel')
        return

    # Rotate crash report dumps
    try:
        utils.clean_directory(config.KDUMPS_DIR, keep_n=3, pattern="kcore*.dump")
        utils.clean_directory(config.KDUMPS_DIR, keep_n=3, pattern="kmsg*.log")
    except Exception:
        log_utils.kcarelog.exception('Error during crash reporter cleanup')

    khash = kcare.get_kernel_hash()
    # take into account AUTO_UPDATE config setting in case of `--auto-update` cli option
    if mode != constants.UPDATE_MODE_AUTO or config.AUTO_UPDATE:
        with execute_hooks():
            pf.fetch_fixups(current_level)
            kcare_load(khash, level, mode, freezer, use_anchor=mode == constants.UPDATE_MODE_SMART)

    kcare.dump_kernel_patch_level(level)
    clear_cache(khash, level)


"""
This is needed to support sticky keys as per
https://cloudlinux.atlassian.net/browse/KCARE-953
"""


def get_sticky(mode):
    count = sum(
        (
            bool(config.STICKY_PATCH),
            bool(config.UPDATE_DELAY or config.AUTO_UPDATE_DELAY),
            bool(config.STICKY_PATCHSET or config.AUTO_STICKY_PATCHSET),
        )
    )
    if count > 1:
        raise KcareError(
            'Invalid configuration: conflicting settings STICKY_PATCH,'
            ' [AUTO_]UPDATE_DELAY or [AUTO_]STICKY_PATCHSET. There should be only one of them'
        )

    if config.STICKY_PATCH:
        return config.STICKY_PATCH

    if mode != constants.UPDATE_MODE_MANUAL:
        delay = config.AUTO_UPDATE_DELAY or config.UPDATE_DELAY
        patchset = config.AUTO_STICKY_PATCHSET or config.STICKY_PATCHSET
    else:
        delay = config.UPDATE_DELAY
        patchset = config.STICKY_PATCHSET

    if delay:
        return delay

    if patchset:
        return 'release-' + patchset


def _stickyfy(prefix, fname):
    return prefix + '.' + fname


def stickyfy(file, mode):
    """
    Used to add sticky prefix to satisfy KCARE-953
    :param file: name of the file to stickify
    :return: stickified file.
    """
    s = get_sticky(mode)
    if not s:
        return file

    if s != 'KEY':
        return _stickyfy(s, file)

    server_id = serverid.get_serverid()
    if not server_id:
        log_utils.kcarelog.info('Patch set to STICKY_PATCH=KEY, but server is not registered with the key')
        sys.exit(-4)

    try:
        response = http_utils.urlopen(ipv6_support.get_registration_url() + '/sticky_patch.plain?server_id={0}'.format(server_id))
    except HTTPError as e:
        log_utils.print_cln_http_error(e, e.url)
        sys.exit(-5)

    res = utils.data_as_dict(utils.nstr(response.read()))
    code = int(res['code'])

    if code == 0:
        return _stickyfy(res['prefix'], file)
    elif code == 1:
        return file
    elif code == 2:
        log_utils.kcarelog.info('Server ID is not recognized. Please check if the server is registered')
        sys.exit(-1)

    log_utils.kcarelog.info('Error: ' + res['message'])
    sys.exit(-3)


#################################
# from python 2.7.17 ssl stdlib #
#################################


def _dnsname_match(dn, hostname, max_wildcards=1):  # pragma: no cover
    """Matching according to RFC 6125, section 6.4.3

    http://tools.ietf.org/html/rfc6125#section-6.4.3
    """
    pats = []
    if not dn:
        return False

    pieces = dn.split(r'.')
    leftmost = pieces[0]
    remainder = pieces[1:]

    wildcards = leftmost.count('*')
    if wildcards > max_wildcards:
        # Issue #17980: avoid denials of service by refusing more
        # than one wildcard per fragment.  A survery of established
        # policy among SSL implementations showed it to be a
        # reasonable choice.
        raise CertificateError('too many wildcards in certificate DNS name: ' + repr(dn))

    # speed up common case w/o wildcards
    if not wildcards:
        return dn.lower() == hostname.lower()

    # RFC 6125, section 6.4.3, subitem 1.
    # The client SHOULD NOT attempt to match a presented identifier in which
    # the wildcard character comprises a label other than the left-most label.
    if leftmost == '*':
        # When '*' is a fragment by itself, it matches a non-empty dotless
        # fragment.
        pats.append('[^.]+')
    elif leftmost.startswith('xn--') or hostname.startswith('xn--'):
        # RFC 6125, section 6.4.3, subitem 3.
        # The client SHOULD NOT attempt to match a presented identifier
        # where the wildcard character is embedded within an A-label or
        # U-label of an internationalized domain name.
        pats.append(re.escape(leftmost))
    else:
        # Otherwise, '*' matches any dotless string, e.g. www*
        pats.append(re.escape(leftmost).replace(r'\*', '[^.]*'))

    # add the remaining fragments, ignore any wildcards
    for frag in remainder:
        pats.append(re.escape(frag))

    pat = re.compile(r'\A' + r'\.'.join(pats) + r'\Z', re.IGNORECASE)
    return pat.match(hostname)


# match_hostname tweaked to get dns names from pyopenssl x509 cert object
def match_hostname(cert, hostname):  # pragma: no cover
    san = []
    for i in range(cert.get_extension_count()):
        e = cert.get_extension(i)
        if e.get_short_name() == 'subjectAltName':
            san = [it.strip().split(':', 1) for it in str(e).split(',')]

    if not cert:
        raise ValueError(
            'empty or no certificate, match_hostname needs a '
            'SSL socket or SSL context with either '
            'CERT_OPTIONAL or CERT_REQUIRED'
        )
    dnsnames = []
    for key, value in san:
        if key == 'DNS':
            if _dnsname_match(value, hostname):
                return
            dnsnames.append(value)

    if not dnsnames:
        # The subject is only checked when there is no dNSName entry
        # in subjectAltName
        cn = cert.get_subject().commonName
        if _dnsname_match(cn, hostname):
            return
        dnsnames.append(value)

    if len(dnsnames) > 1:
        raise CertificateError("hostname {0} doesn't match either of {1}".format(hostname, ', '.join(map(repr, dnsnames))))
    elif len(dnsnames) == 1:
        raise CertificateError("hostname {0} doesn't match {1}".format(hostname, dnsnames[0]))
    else:
        raise CertificateError('no appropriate commonName or subjectAltName fields were found')


#####################
# end of ssl stdlib #
#####################


def main():
    parser = ArgumentParser(prog="kcarectl", description='Manage KernelCare patches for your kernel')
    parser.add_argument('--debug', help='', action='store_true')
    parser.add_argument(
        '-i',
        '--info',
        help='Display information about KernelCare. Use with --json parameter to get result in JSON format.',
        action='store_true',
    )
    parser.add_argument(
        '--app-info',
        help='Display information about KernelCare agent. Use with --json parameter to get result in JSON format.',
        action='store_true',
    )
    parser.add_argument('-u', '--update', help='Download latest patches and apply them to the current kernel', action='store_true')
    parser.add_argument('--unload', help='Unload patches', action='store_true')
    parser.add_argument('--smart-update', help='Patch kernel based on UPDATE POLICY settings', action='store_true')
    parser.add_argument('--auto-update', help='Check if update is available, if so -- update', action='store_true')
    parser.add_argument(
        '--local', help='Update from a server local directory; accepts a path where patches are located', metavar='PATH'
    )
    parser.add_argument('--patch-info', help='Return the list of applied patches', action='store_true')
    parser.add_argument('--freezer', help='Freezer type: full (default), smart, none', metavar='freezer')
    parser.add_argument('--nofreeze', help="[deprecated] Don't freeze tasks before patching", action='store_true')
    parser.add_argument('--uname', help='Return safe kernel version', action='store_true')
    parser.add_argument('--license-info', help='Return current license info', action='store_true')
    parser.add_argument('--status', help='Return status of updates', action='store_true')
    parser.add_argument('--register', help='Register using KernelCare Key', metavar='KEY')
    parser.add_argument(
        '--register-autoretry', help='Retry registering indefinitely if failed on the first attempt', action='store_true'
    )
    parser.add_argument('--unregister', help='Unregister from KernelCare (for key-based servers only)', action='store_true')
    parser.add_argument('--check', help='Check if new update available', action='store_true')
    parser.add_argument(
        '--latest-patch-info',
        help='Return patch info for the latest available patch. Use with --json parameter to get result in JSON format.',
        action='store_true',
    )
    parser.add_argument('--test', help='[deprecated] Use --prefix=test instead', action='store_true')
    parser.add_argument('--tag', help='Tag server with custom metadata, for ePortal users only', metavar='TAG')
    parser.add_argument(
        '--prefix',
        help='Patch source prefix used to test different builds by downloading builds from different locations based on prefix',
        metavar='PREFIX',
    )
    parser.add_argument('--nosignature', help='Do not check signature', action='store_true')
    parser.add_argument(
        '--set-monitoring-key', help='Set monitoring key for IP based licenses. 16 to 32 characters, alphanumeric only', metavar='KEY'
    )
    parser.add_argument('--doctor', help='Submits a vitals report to CloudLinux for analysis and bug-fixes', action='store_true')
    parser.add_argument('--enable-auto-update', help='Enable auto updates', action='store_true')
    parser.add_argument('--disable-auto-update', help='Disable auto updates', action='store_true')
    parser.add_argument(
        '--plugin-info',
        help='Provides the information shown in control panel plugins for KernelCare. '
        'Use with --json parameter to get result in JSON format.',
        action='store_true',
    )
    parser.add_argument(
        '--server-info',
        help='Provides information about the host in JSON format.',
        action='store_true',
    )
    parser.add_argument(
        '--json',
        help="Return '--plugin-info', '--latest-patch-info', '--patch-info', '--app-info' and '--info' results in JSON format",
        action='store_true',
    )

    parser.add_argument('--version', help='Return the current version of KernelCare', action='store_true')
    parser.add_argument('--kpatch-debug', help='Enable the debug mode', action='store_true')
    parser.add_argument('--no-check-cert', help='Disable the patch server SSL certificates checking', action='store_true')
    parser.add_argument(
        '--set-patch-level',
        help='Set patch level to be applied. To select latest patch level set -1',
        action='store',
        type=int,
        default=None,
        required=False,
    )
    parser.add_argument('--check-compatibility', help='Check compatibility.', action='store_true')
    parser.add_argument('--clear-cache', help='Clear all cached files', action='store_true')
    exclusive_group = parser.add_mutually_exclusive_group()
    exclusive_group.add_argument(
        '--set-patch-type', help="Set patch type feed. To select default feed use 'default' option", action='store'
    )
    exclusive_group.add_argument('--edf-enabled', help='Enable exploit detection framework', action='store_true')
    exclusive_group.add_argument('--edf-disabled', help='Disable exploit detection framework', action='store_true')
    parser.add_argument(
        '--set-sticky-patch',
        help='Set patch to stick to date in DDMMYY format, or retrieve it from KEY if set to KEY. Leave empty to unstick',
        action='store',
        default=None,
        required=False,
    )
    parser.add_argument(
        '-q', '--quiet', help='Suppress messages, provide only errors and warnings to stderr', action='store_true', required=False
    )

    parser.add_argument('--has-flags', help='Check agent features')

    parser.add_argument('--force', help='Force action and ignore several restristions.', action="store_true")
    parser.add_argument('--set-config', help='Change configuration option', action='append', metavar='KEY=VALUE')

    if not config.LIBCARE_DISABLED:
        parser.add_argument(
            '--disable-libcare', help='Disable libcare services', dest='enable_libcare', action='store_const', const=False
        )
        parser.add_argument(
            '--enable-libcare', help='Enable libcare services', dest='enable_libcare', action='store_const', const=True
        )
        parser.add_argument(
            '--lib-update', help='Download latest patches and apply them to the current userspace libraries', action='store_true'
        )
        parser.add_argument('--lib-unload', '--userspace-unload', help='Unload userspace patches', action='store_true')
        parser.add_argument('--lib-auto-update', help='Check if update is available, if so -- update', action='store_true')
        parser.add_argument('--lib-info', '--userspace-info', help='Display information about KernelCare+.', action='store_true')
        parser.add_argument(
            '--lib-patch-info', '--userspace-patch-info', help='Return the list of applied userspace patches', action='store_true'
        )
        parser.add_argument('--lib-version', '--userspace-version', help='Return safe package version', metavar='PACKAGENAME')

        parser.add_argument(
            '--userspace-update',
            metavar='USERSPACE_PATCHES',
            nargs='?',
            const="",
            help='Download latest patches and apply them to the corresponding userspace processes',
        )
        parser.add_argument(
            '--userspace-auto-update',
            help='Download latest patches and apply them to the corresponding userspace processes',
            action='store_true',
        )
        parser.add_argument('--userspace-status', help='Return status of userspace updates', action='store_true')

    args = parser.parse_args()

    config.__dict__.update(config_handlers.get_config_settings())

    if not config.LIBCARE_DISABLED:
        config.FLAGS += ['libcare-enabled']

    if args.has_flags is not None:
        if set(filter(None, args.has_flags.split(','))).issubset(config.FLAGS):
            return 0
        else:
            return 1

    # do not remove args.auto_update!
    # once added to machine, kcare-cron is never changed by package update;
    # old clients has no -q option in their cron,
    # so auto_update default silent mode must be saved forever
    if args.quiet or args.auto_update:
        if config.SILENCE_ERRORS:
            config.PRINT_LEVEL = constants.PRINT_CRITICAL
        else:
            config.PRINT_LEVEL = constants.PRINT_ERROR
    elif args.debug:
        config.PRINT_LEVEL = constants.PRINT_DEBUG

    if not args.uname:
        if os.getuid() != 0:
            print('Please run as root', file=sys.stderr)  # noqa: T201
            return 1

    level = logging.INFO
    if args.quiet:
        level = logging.WARNING
    elif args.debug:
        level = logging.DEBUG

    # should be after root role check to create a log file with correct rights
    log_utils.initialize_logging(level)

    if args.clear_cache:
        utils.clear_all_cache()

    if args.set_patch_level:
        if args.set_patch_level >= 0:
            config.PATCH_LEVEL = str(args.set_patch_level)  # type: ignore
            config_handlers.update_config(PATCH_LEVEL=config.PATCH_LEVEL)
        else:
            config.PATCH_LEVEL = None
            config_handlers.update_config(PATCH_LEVEL='')

    if args.set_sticky_patch is not None:
        config_handlers.update_config(STICKY_PATCH=args.set_sticky_patch)
        config.STICKY_PATCH = args.set_sticky_patch

    if args.nosignature:
        config.USE_SIGNATURE = False

    if args.no_check_cert:
        config.CHECK_SSL_CERTS = False

    if args.kpatch_debug:
        config.KPATCH_DEBUG = True

    if args.check_compatibility:
        check_compatibility()

    # EDF do nothing
    if args.edf_enabled:
        warnings.warn('Flag --edf-enabled has been deprecated and will be not available in future releases.', DeprecationWarning)
    elif args.edf_disabled:
        if config.PATCH_TYPE == 'edf':
            args.set_patch_type = ('' if config.PREV_PATCH_TYPE == 'edf' else config.PREV_PATCH_TYPE) or 'default'
            args.update = True

    if args.prefix:
        config.PREFIX = args.prefix
    if args.test:
        warnings.warn('Flag --test has been deprecated and will be not available in future releases.', DeprecationWarning)
        config.PREFIX = 'test'
    config.PREFIX = config.PREFIX.strip('/')

    if config.PREFIX and config.PREFIX not in EXPECTED_PREFIX:
        log_utils.kcarelog.warning('Prefix `{0}` is not in expected one {1}.'.format(config.PREFIX, ' '.join(EXPECTED_PREFIX)))

    if args.local:
        config.UPDATE_FROM_LOCAL = True
        config.PATCH_SERVER = 'file:' + args.local

    if args.set_patch_type:
        update_patch_type(args.set_patch_type)

    if config.PATCH_TYPE == 'edf':
        config.PATCH_TYPE = edf_fallback_ptype()
        warnings.warn('edf patches are deprecated. Fallback to {0}'.format(config.PATCH_TYPE or 'default'), DeprecationWarning)

    if args.app_info:
        utils.print_wrapper(platform_utils.app_info(is_json=args.json))
        return

    if args.server_info:
        info = server_info.server_info(reason='debug', secure_boot_info=True, perf_metrics=True)
        utils.print_wrapper(json.dumps(info))
        return

    apply_ptype(config.PATCH_TYPE)

    if args.doctor:
        kcdoctor()
        return

    if args.plugin_info:
        if args.json:
            plugin_info(fmt='json')
        else:
            plugin_info()
        return

    if args.enable_auto_update:
        config_handlers.update_config(AUTO_UPDATE='YES')
        return

    if args.disable_auto_update:
        config_handlers.update_config(AUTO_UPDATE='NO')
        return

    if args.set_config:
        config_handlers.update_config_from_args(args.set_config)
        return

    if args.set_monitoring_key:
        return set_monitoring_key_for_ip_license(args.set_monitoring_key)
    if args.unregister:
        auth.unregister()
    if args.register:
        if config.PATCH_TYPE == 'free':
            config_handlers.update_config(PATCH_TYPE='extra')
        return auth.register(args.register, args.register_autoretry)
    if args.license_info:
        # license_info returns zero if no valid license found and non-zero otherwise
        if auth.license_info() != 0:
            return 0
        else:
            return 1

    if args.tag is not None:
        return tag_server(args.tag)

    if args.version:
        utils.print_wrapper(constants.VERSION)

    if getattr(args, 'enable_libcare', None) is not None:
        libcare.set_libcare_status(args.enable_libcare)
        return 0

    if not config.LIBCARE_DISABLED:
        if args.userspace_status:
            return libcare.get_userspace_update_status()
        if args.lib_update:
            if libcare.do_userspace_update() is not None:
                log_utils.loginfo('Userspace patches are applied.')
        if args.lib_auto_update:
            libcare.do_userspace_update(mode=constants.UPDATE_MODE_AUTO)
        elif args.lib_unload:
            libcare.libcare_unload()
            log_utils.loginfo('Userspace patches are unloaded.')
        if args.lib_info:
            utils.print_wrapper(libcare.libcare_info())
        if args.lib_patch_info:
            utils.print_wrapper(libcare.libcare_patch_info())
        if args.lib_version and libcare.libcare_server_started():
            utils.print_wrapper(libcare.libcare_version(args.lib_version))

        if args.userspace_update is not None:
            if args.userspace_update == '':
                # Get from config or defaults
                limit = config.USERSPACE_PATCHES or list(libcare.USERSPACE_MAP.keys())
            else:
                limit = [ptch.strip().lower() for ptch in args.userspace_update.split(',')]
            if libcare.do_userspace_update(limit=sorted(limit)) is not None:
                log_utils.loginfo('Userspace patches are applied.')
        if args.userspace_auto_update:
            libcare.do_userspace_update(mode=constants.UPDATE_MODE_AUTO, limit=None)

    if args.info:
        utils.print_wrapper(kcare_info(is_json=args.json))
    freezer = ''
    if args.nofreeze:
        warnings.warn('Flag --nofreeze has been deprecated and will be not available in future releases.', DeprecationWarning)
        freezer = 'none'
    if args.freezer:
        freezer = args.freezer
    if args.smart_update:
        do_update(freezer, mode=constants.UPDATE_MODE_SMART, policy=config.UPDATE_POLICY)
    if args.update:
        do_update(freezer, mode=constants.UPDATE_MODE_MANUAL)
        log_utils.loginfo('Kernel is safe')
    if args.uname:
        utils.print_wrapper(kcare.kcare_uname())
    if args.unload:
        kcare_unload(freezer, force=args.force)
        log_utils.loginfo('KernelCare protection disabled. Your kernel might not be safe')
    if args.auto_update:
        config.CHECK_CLN_LICENSE_STATUS = False
        # wait to prevent spikes at the beginning of each minute KPT-1874
        # bandit warns about using random.uniform for security which is not the case here
        time.sleep(random.uniform(0, 60))  # nosec B311
        do_update(freezer, mode=constants.UPDATE_MODE_AUTO)
    if args.patch_info:
        patch_info(is_json=args.json)
    if args.status:
        return get_update_status()
    if args.latest_patch_info:
        kcare_latest_patch_info(is_json=args.json)
    if args.check:
        kcare_check()

    # No arg were provided
    if len(sys.argv) == 1:
        show_generic_info()

