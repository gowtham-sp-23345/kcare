# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT

import ast
import glob
import hashlib
import json
import os
import platform

from . import config, constants, log_utils, process_utils, utils
from .errors import SafeExceptionWrapper
from .py23 import json_loads_nstr

if False:  # pragma: no cover
    from typing import Optional, Tuple  # noqa: F401

UNAME_LABEL = 'uname: '


def is_uname_char(c):  # type: (str) -> bool
    return str.isalnum(c) or c in '.-_+'


def parse_uname(patch_level):
    khash = get_kernel_hash()
    f = open(get_cache_path(khash, patch_level, config.PATCH_INFO), 'r')
    try:
        for line in f.readlines():
            if line.startswith(UNAME_LABEL):
                return ''.join(filter(is_uname_char, line[len(UNAME_LABEL) :].strip()))
    finally:
        f.close()
    return ''


def kcare_update_effective_version(new_version):
    if os.path.exists(config.KCARE_UNAME_FILE):
        try:
            f = open(config.KCARE_UNAME_FILE, 'w')
            f.write(new_version)
            f.close()
            return True
        except Exception:
            pass
    return False


def get_kernel_hash():  # type: () -> str
    f = open(config.KERNEL_VERSION_FILE, 'rb')
    try:
        # sha1 is not used for security, turn off bandit warning
        # bandit issues a warning that B324 has no test when `nosec B324` is
        # set here. Using broad `nosec` here to bypass the warning.
        return hashlib.sha1(f.read()).hexdigest()  # nosec B324
    finally:
        f.close()


def get_last_stop():  # type: () -> str
    """Returns timestamp from PATCH_CACHE/stoped.at if its exsits"""
    stopped_at_filename = os.path.join(constants.PATCH_CACHE, 'stopped.at')
    if os.path.exists(stopped_at_filename):
        with open(stopped_at_filename, 'r') as fh:
            value = fh.read().rstrip()
            try:
                int(value)
            except ValueError:
                return str(int(os.path.getctime(stopped_at_filename)))
            except Exception:  # pragma: no cover, it should not happen
                return 'error'
            return value

    return '-1'


def get_cache_path(khash, plevel, fname):
    prefix = config.PREFIX or 'none'
    ptype = config.PATCH_TYPE or 'default'
    patch_dir = '-'.join([prefix, khash, str(plevel), ptype])
    result = (constants.PATCH_CACHE, 'patches', patch_dir)  # type: Tuple[str, ...]
    if fname:
        result += (fname,)
    return os.path.join(*result)


def get_kernel_prefixed_url(*parts):
    return utils.get_patch_server_url(config.PREFIX, *parts)


class BaseKernelPatchLevel(int):
    def cache_path(self, *parts):
        return get_cache_path(self.khash, str(self), *parts)  # type: ignore[attr-defined]

    def as_dict(self):
        return {
            'level': self.level,
            'khash': self.khash,
            'baseurl': self.baseurl,
            'release': self.release,
        }


class KernelPatchLevel(BaseKernelPatchLevel):
    def __new__(cls, khash, level, baseurl, release=None):
        return super(cls, cls).__new__(cls, level)

    def __init__(self, khash, level, baseurl, release=None):
        self.level = level
        self.khash = khash
        self.baseurl = baseurl
        self.release = release

    def kmod_url(self, *parts):
        return utils.get_patch_server_url(self.baseurl, self.khash, *parts)

    def file_url(self, *parts):
        return utils.get_patch_server_url(self.baseurl, self.khash, str(self), *parts)


class LegacyKernelPatchLevel(BaseKernelPatchLevel):
    def __new__(cls, khash, level):
        try:
            return super(cls, cls).__new__(cls, level)
        except ValueError as exc:
            # common error with this class
            raise SafeExceptionWrapper(exc)

    def __init__(self, khash, level):
        self.level = level
        self.khash = khash
        self.baseurl = None
        self.release = None

    def kmod_url(self, *parts):
        if 'patches.kernelcare.com' in config.PATCH_SERVER:
            return get_kernel_prefixed_url(self.khash, str(self), *parts)
        # ePortal workaround, it doesn't support leveled links to kmod
        return get_kernel_prefixed_url(self.khash, *parts)

    def file_url(self, *parts):
        return get_kernel_prefixed_url(self.khash, str(self), *parts)

    def upgrade(self, baseurl):
        return KernelPatchLevel(self.khash, int(self), baseurl)


def dump_kernel_patch_level(kernel_patch_level):  # type: (BaseKernelPatchLevel) -> None
    try:
        with open(os.path.join(constants.PATCH_CACHE, 'kernel_patch_level.json'), 'w') as f:
            json.dump(kernel_patch_level.as_dict(), f)
    except Exception:
        log_utils.logexc('failed to dump kernel patch level', print_msg=False)


def read_dumped_kernel_patch_level():
    try:
        with open(os.path.join(constants.PATCH_CACHE, 'kernel_patch_level.json')) as f:
            return json_loads_nstr(f.read())
    except Exception:
        log_utils.logexc('failed to read dumped kernel patch level', print_msg=False)


@utils.cached
def kdumps_latest_event_timestamp():
    kdump_path = "/var/crash"
    result = None
    if os.path.isfile("/etc/kdump.conf"):
        with open("/etc/kdump.conf", 'r') as kdump_conf:
            for line in kdump_conf:
                line = line.strip()
                if line.startswith('path '):
                    _, kdump_path = line.split(None, 1)
    if os.path.isdir(kdump_path):
        vmcore_list = glob.glob(os.path.join(kdump_path, '*/vmcore'))
        if vmcore_list:
            result = max(os.path.getctime(it) for it in vmcore_list)
    return result


@utils.cached
def kdump_status():
    if constants.SKIP_SYSTEMCTL_CHECK or os.path.isfile(constants.SYSTEMCTL):
        _, stdout, _ = process_utils.run_command([constants.SYSTEMCTL, 'is-active', 'kdump'], catch_stdout=True, catch_stderr=True)
        return stdout.strip()
    return 'systemd-absent'


@utils.cached
def crashreporter_latest_event_timestamp():  # type: () -> Optional[float]
    if not os.path.isdir(config.KDUMPS_DIR):
        return None

    files_list = os.listdir(config.KDUMPS_DIR)
    if not files_list:
        return None

    return max(os.path.getctime(os.path.join(config.KDUMPS_DIR, it)) for it in files_list)


def get_current_kmod_version():
    kmod_version_file = '/sys/module/kcare/version'
    if not os.path.exists(kmod_version_file):
        return

    with open(kmod_version_file, 'r') as f:
        version = f.read().strip()
    return version


def is_kmod_version_changed(khash, plevel):
    old_version = get_current_kmod_version()
    if not old_version:
        return True

    new_version = process_utils.check_output(
        ['/sbin/modinfo', '-F', 'version', get_cache_path(khash, plevel, constants.KMOD_BIN)]
    ).strip()
    return old_version != new_version


def kcare_uname_su():
    patch_level = loaded_patch_level()
    if not patch_level:
        return platform.release()
    return parse_uname(patch_level)


def kcare_uname():
    if os.path.exists(config.KCARE_UNAME_FILE):
        return open(config.KCARE_UNAME_FILE, 'r').read().strip()
    else:
        # TODO: talk to @kolshanov about runtime results from KPATCH_CTL info
        #  (euname from kpatch-description -- not from kpatch.info file)
        return kcare_uname_su()


def loaded_patch_level():  # mocked: tests/unit
    utils.print_wrapper("[DEBUG] [file: kcarectl/kcare.py, function: loaded_patch_level] start")
    desc = loaded_patch_description()
    utils.print_wrapper("[DEBUG] loaded patch description: {0!r}".format(desc))
    pl = parse_patch_description(desc)['patch-level']
    utils.print_wrapper("[DEBUG] parsed patch-level: {0!r}".format(pl))
    if pl:
        try:
            int(pl)
        except ValueError as e:
            utils.print_wrapper("[DEBUG] patch-level {0!r} is not an integer, raising SafeExceptionWrapper".format(pl))
            raise SafeExceptionWrapper(e, 'Unexpected patch state', _patch_info())
        utils.print_wrapper("[DEBUG] returning LegacyKernelPatchLevel for level {0}".format(pl))
        return LegacyKernelPatchLevel(get_kernel_hash(), pl)
    utils.print_wrapper("[DEBUG] no patch level loaded, returning None")


def _patch_info():
    return process_utils.check_output([constants.KPATCH_CTL, 'info'])


@utils.cached
def get_loaded_modules():
    try:
        return [line.split()[0] for line in open('/proc/modules')]
    except (OSError, IOError) as ex:
        log_utils.logerror('Error getting loaded modules list: ' + str(ex), print_msg=False)
        return []


def loaded_patch_description():
    if 'kcare' not in get_loaded_modules():
        return None
    # example: 28-:1532349972;4.4.0-128.154
    # (patch level: number)-(patch type: free/extra/empty):(timestamp);(effective kernel version from kpatch.info)
    return get_patch_value(_patch_info(), 'kpatch-description')


def get_patch_value(info, label):
    return utils.data_as_dict(info).get(label)


def parse_patch_description(desc):
    result = {'patch-level': None, 'patch-type': 'default', 'last-update': '', 'kernel-version': ''}

    if not desc:
        return result

    level_type_timestamp, _, kernel = desc.partition(';')
    level_type, _, timestamp = level_type_timestamp.partition(':')
    patch_level, _, patch_type = level_type.partition('-')

    # need to return patch_level=None not to break old code
    # TODO: refactor all loaded_patch_level() usages to work with empty string instead of None
    result['patch-level'] = patch_level or None
    result['patch-type'] = patch_type or 'default'
    result['last-update'] = timestamp
    result['kernel-version'] = kernel

    return result


def get_state():
    state_file = os.path.join(constants.PATCH_CACHE, 'kcare.state')
    if os.path.exists(state_file):
        with open(state_file, 'r') as f:
            try:
                state = f.read()
                return ast.literal_eval(state)
            except (SyntaxError, OSError, ValueError, TypeError, UnicodeDecodeError):
                pass

