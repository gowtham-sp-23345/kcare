# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT

import os
import re

from . import config, constants, http_utils, log_utils, utils
from .py23 import ConfigParser

if False:  # pragma: no cover
    from typing import List, Optional, Set  # noqa: F401

CONFIG = '/etc/sysconfig/kcare/kcare.conf'
FEATURE_FLAGS_WHITELIST = [
    # signatures-related things
    'USE_CONTENT_FILE_V3',
    'FORCE_JSON_SIG_V3',
    # kernel module - related things
    'ENABLE_CRASHREPORTER',
    'KCORE_OUTPUT',
    'KMSG_OUTPUT',
]

CONFIG_OPTIONS = set()  # type: Set[str]   # options were read from config file


def bool_converter(value):  # type: (str) -> bool
    return value.upper() in ('1', 'TRUE', 'YES', 'Y')


POSSIBLE_CONFIG_OPTIONS = {
    # name: convert function (could be None)
    'AFTER_UPDATE_COMMAND': lambda v: v.strip(),
    'AUTO_STICKY_PATCHSET': None,
    'AUTO_UPDATE': bool_converter,
    'AUTO_UPDATE_DELAY': None,
    'BEFORE_UPDATE_COMMAND': lambda v: v.strip(),
    'CHECK_SSL_CERTS': bool_converter,
    'ENABLE_CRASHREPORTER': bool_converter,
    'FORCE_GID': None,
    'FORCE_IPV4': bool_converter,
    'FORCE_IPV6': bool_converter,
    'FORCE_JSON_SIG_V3': bool_converter,
    'HTTP_TIMEOUT': int,
    'IGNORE_UNKNOWN_KERNEL': bool_converter,
    'KCORE_OUTPUT': bool_converter,
    'KCORE_OUTPUT_SIZE': int,
    'KDUMPS_DIR': lambda v: v.rstrip('/'),
    'KMSG_OUTPUT': bool_converter,
    'LIBCARE_DISABLED': bool_converter,
    'LIBCARE_PIDLOGS_MAX_TOTAL_SIZE_MB': int,
    'LIBCARE_SOCKET_TIMEOUT': int,
    'LIB_AUTO_UPDATE': bool_converter,
    'PATCH_LEVEL': lambda v: v or None,
    'PATCH_METHOD': str.upper,
    'PATCH_SERVER': lambda v: v.rstrip('/'),
    'PATCH_SERVER_IPV6': lambda v: v.rstrip('/'),
    'PATCH_TYPE': str.lower,
    'PREFIX': None,
    'PREV_PATCH_TYPE': str.lower,
    'REGISTRATION_URL': lambda v: v.rstrip('/'),
    'REGISTRATION_URL_IPV6': lambda v: v.rstrip('/'),
    'PRINT_LEVEL': int,
    'REPORT_FQDN': bool_converter,
    'SILENCE_ERRORS': bool_converter,
    'STATUS_CHANGE_GAP': int,
    'STICKY_PATCH': str.upper,
    'STICKY_PATCHSET': None,
    'UPDATE_DELAY': None,
    'UPDATE_POLICY': str.upper,
    'UPDATE_SYSCTL_CONFIG': bool_converter,
    'USERSPACE_PATCHES': lambda v: [ptch.strip().lower() for ptch in v.split(',')],
    'USE_CONTENT_FILE_V3': bool_converter,
    'KERNEL_VERSION_FILE': None,
    'KCARE_UNAME_FILE': None,
    'SUCCESS_TIMEOUT': int,
}  # pragma: no py2 cover


def update_config(**kwargs):
    cf = open(CONFIG)
    lines = cf.readlines()
    cf.close()
    for prop, value in kwargs.items():
        updated = False
        prop_eq = prop + '='
        prop_sp = prop + ' '
        for i in range(len(lines)):
            if lines[i].startswith(prop_eq) or lines[i].startswith(prop_sp):
                if value is None:
                    del lines[i]
                else:
                    lines[i] = prop + ' = ' + str(value) + '\n'
                updated = True
                break
        if not updated:
            lines.append(prop + ' = ' + str(value) + '\n')
    utils.atomic_write(CONFIG, ''.join(lines))


def update_config_from_args(params):  # type: (List[str]) -> None
    params_for_update = {}
    pattern = re.compile(r'^([^=]+)=([^=]*)$')
    for param in params:
        match = pattern.match(param)
        if match:
            key, value = match.groups()
            if not value:
                value = None
        else:
            raise SystemExit('Invalid parameter format: %s. Format should be KEY=VALUE' % param)
        params_for_update[key] = value

    unknown_params = set(params_for_update) - set(POSSIBLE_CONFIG_OPTIONS)
    if unknown_params:
        raise SystemExit('Unknown parameter: %s' % ', '.join(sorted(unknown_params)))

    for var_name, value in params_for_update.items():
        convert = POSSIBLE_CONFIG_OPTIONS[var_name]
        if value is None or convert is None:
            continue
        try:
            convert(value)
        except Exception:
            raise SystemExit('Bad value for %s: %s' % (var_name, value))

    update_config(**params_for_update)


class FakeSecHead(object):
    def __init__(self, fp):
        self.fp = fp
        self.sechead = '[asection]\n'  # type: Optional[str]

    def readline(self):  # pragma: no py3 cover
        if self.sechead:
            try:
                return self.sechead
            finally:
                self.sechead = None
        else:
            return self.fp.readline()

    def __iter__(self):  # pragma: no py2 cover
        if self.sechead:
            yield self.sechead
            self.sechead = None
        for line in self.fp:
            yield line


def get_config_settings():
    CONFIG_OPTIONS.clear()

    result = {}
    cp = ConfigParser(defaults={'HTTP_PROXY': '', 'HTTPS_PROXY': ''})

    try:
        config = FakeSecHead(open(CONFIG))
        if constants.PY2:  # pragma: no py3 cover
            cp.readfp(config)
        else:  # pragma: no py2 cover
            cp.read_file(config)
    except Exception:
        return {}

    def read_var(name, default=None, convert=None):
        try:
            value = cp.get('asection', name)
        except Exception:
            value = default
        if value is not None:
            if convert:
                value = convert(value)

            result[name] = value
            CONFIG_OPTIONS.add(name)

    for scheme, variable in [('http', 'HTTP_PROXY'), ('https', 'HTTPS_PROXY')]:
        # environment settings take precedence over kcare.config ones
        if not http_utils.get_proxy_from_env(scheme):
            proxy = cp.get('asection', variable)
            if proxy:
                os.environ[variable] = proxy

    for var_name, convert in POSSIBLE_CONFIG_OPTIONS.items():
        read_var(var_name, convert=convert)

    return result


def get_config_options_from_feature_flags(headers):
    """
    Checking headers for feature flags which start with 'KC-Flag-' and
    reformat it to dictionary with keys in upper case and without 'KC-Flag-' prefix
    and dashes replaced with underscores. For unification all header keys are checking in upper case.
    For example:
    'KC-Flag-Some-Value' -> 'SOME_VALUE'
    :return: dict {'SOME_VALUE': 'value', ...}
    """
    # there is no dict comprehension in python 2.6
    flags = {}
    for key, value in headers.items():
        key_upper = key.upper()
        if key_upper.startswith('KC-FLAG-'):
            formatted_key = key_upper.replace('KC-FLAG-', '').replace('-', '_').upper()
            flags[formatted_key] = value
    return flags


def set_config_from_patchserver(headers):
    """
    Set global variables using feature flag from patchserver headers.
    Checks that option is allowed by whitelist and update global variable
    using globals()
    :param headers: Response headers from patchserver
    :return: None
    """
    options_from_ps = get_config_options_from_feature_flags(headers)
    for key, value in options_from_ps.items():
        if key not in FEATURE_FLAGS_WHITELIST:
            continue
        if value is not None and key not in CONFIG_OPTIONS:
            try:
                config.__dict__[key] = bool(int(value))
                log_utils.kcarelog.info('patchserver config override: %s with %s', key, value)
            except ValueError:
                log_utils.kcarelog.error('Invalid value during attempt to override config from patchserver %s: %s', key, value)

