# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT

import json
import os
import re
import shutil
import socket

from . import (
    auth,
    capabilities,
    config,
    config_handlers,
    constants,
    errors,
    fetch,
    log_utils,
    process_utils,
    selinux,
    server_info,
    update_utils,
    utils,
)
from .py23 import HTTPError, json_loads_nstr, urlquote

if False:  # pragma: no cover
    from typing import Dict, List, Tuple  # noqa: F401

LIBCARE_CLIENT = '/usr/libexec/kcare/libcare-client'
LIBCARE_SOCKET = (
    "/run/libcare/libcare.sock",
    "/var/run/libcare.sock",
)
LIBCARE_PATCHES = '/var/cache/kcare/libcare_patches'
LIBCARE_CVE_LIST = '/var/cache/kcare/libcare_cvelist'
LIBCARE_LOGROTATE_CONFIG = '/etc/sysconfig/kcare/libcare.logrotate'

LIBNAME_MAP = {'mysqld': 'db', 'mariadbd': 'db', 'postgres': 'db', 'qemu-kvm': 'qemu', 'qemu-system-x86_64': 'qemu'}
USERSPACE_MAP = {
    'db': ['mysqld', 'mariadbd', 'postgres'],
    'qemu': ['qemu-kvm', 'qemu-system-x86_64'],
    'libs': ['libc', 'libssl', 'nscd', 'libm'],
}


def get_userspace_cache_path(libname, *parts):
    return os.path.join(constants.PATCH_CACHE, 'userspace', libname, *parts)


def clear_libcare_cache(clbl):
    def wrapper(*args, **kwargs):
        try:
            return clbl(*args, **kwargs)
        finally:
            try:
                libcare_client('clearcache')
            except Exception as err:
                # We don't want to show the error to the user but want to see it in logs
                log_utils.logerror("Libcare cache clearing failed: '{0}'".format(err), print_msg=False)

    return wrapper


class UserspacePatchLevel(int):
    def __new__(cls, libname, buildid, level, baseurl=None):
        return super(cls, cls).__new__(cls, level)

    def __init__(self, libname, buildid, level, baseurl=None):
        self.level = level
        self.libname = libname
        self.buildid = buildid
        self.baseurl = baseurl

    def cache_path(self, *parts):
        return get_userspace_cache_path(self.libname, self.buildid, str(self), *parts)


def refresh_applied_patches_list(clbl):
    def save_current_state(info):
        '''KPT-1543 Save info about applyed patches'''
        versions, cves = '', ''
        try:
            if info is None:
                info = _libcare_info()
            packages = {}
            cves_list = []
            for rec in _get_patches_info(info):
                packages[rec.get('package')] = rec.get('latest-version', '')
                for patch in rec.get('patches', []):
                    cves_list.append(patch.get('cve'))
            versions = '\n'.join([' '.join(rec) for rec in packages.items()])
            cves = '\n'.join(cves_list)
        finally:
            utils.atomic_write(LIBCARE_PATCHES, versions, ensure_dir=True)
            utils.atomic_write(LIBCARE_CVE_LIST, cves, ensure_dir=True)

    def wrapper(*args, **kwargs):
        info = None
        try:
            info = clbl(*args, **kwargs)
            return info
        finally:
            save_current_state(info)

    return wrapper


def fetch_userspace_patch(libname, build_id, patch_level=None):
    prefix = config.PREFIX or 'main'
    libname = urlquote(libname)
    build_id = urlquote(build_id.strip())
    url = utils.get_patch_server_url(LIBNAME_MAP.get(libname, 'u'), prefix, libname, build_id, 'latest.v1')
    url += '?info=' + server_info.encoded_server_lib_info('update', patch_level)
    cache_dst = LIBNAME_MAP.get(libname, 'libs')
    try:
        response = fetch.wrap_with_cache_key(auth.urlopen_auth)(url, check_license=False)
    except errors.NotFound:
        # There is no latest info, so we need to clear cache for corresponding
        # build_id to prevent updates by "-ctl" utility.
        shutil.rmtree(get_userspace_cache_path(cache_dst, build_id), ignore_errors=True)
        raise

    config_handlers.set_config_from_patchserver(response.headers)
    meta = json_loads_nstr(utils.nstr(response.read()))
    required_capabilities = meta.get('capabilities', [])
    if not capabilities.has_lc_capabilities(required_capabilities):
        raise errors.CapabilitiesMismatch(
            'Latest LibCare patchset for {0} is incompatible '
            'with the current kernecare package version, please upgrade.'.format(libname)
        )

    level = UserspacePatchLevel(cache_dst, build_id, meta['level'], meta.get('baseurl'))
    plevel = str(meta['level'])

    patch_path = get_userspace_cache_path(cache_dst, build_id, plevel, 'patch.tar.gz')
    if not os.path.exists(patch_path) or os.path.getsize(patch_path) == 0:
        url = utils.get_patch_server_url(meta['patch_url'])
        try:
            fetch.fetch_url(url, patch_path, check_signature=config.USE_SIGNATURE, hash_checker=fetch.get_hash_checker(level))
        except HTTPError as ex:
            # No license - no access
            if ex.code in (403, 401):
                raise errors.NoLibcareLicenseException('KC+ licence is required')
            raise

    dst = get_userspace_cache_path(cache_dst, build_id, plevel)
    cmd = ['tar', 'xf', patch_path, '-C', dst, '--no-same-owner']
    code, stdout, stderr = process_utils.run_command(cmd, catch_stdout=True, catch_stderr=True)
    if code:
        raise errors.KcareError("Patches unpacking error: '{0}' '{1}' {2}".format(stderr, stdout, code))

    link_name = get_userspace_cache_path(cache_dst, build_id, 'latest')
    if not os.path.islink(link_name) and os.path.isdir(link_name):
        shutil.rmtree(link_name)
    os.symlink(plevel, link_name + '.tmp')
    os.rename(link_name + '.tmp', link_name)


def set_libcare_status(enabled):
    config.LIBCARE_DISABLED = not enabled
    if not enabled:
        libcare_server_stop()
    config_handlers.update_config(LIBCARE_DISABLED=('FALSE' if enabled else 'YES'))
    if enabled:
        libcare_server_start()
    log_utils.kcarelog.info('libcare service is ' + ('enabled' if enabled else 'disabled'))


def libcare_server_stop():
    try:
        cmd = [process_utils.find_cmd('service', ('/usr/sbin/', '/sbin/')), 'libcare', 'stop']
    except Exception:  # pragma: no cover unit
        return
    process_utils.run_command(cmd)


def libcare_server_start():
    # we should reset libcare service status here and restart libcare.socket
    # they can be in failed state and prevent connection to a socket
    if constants.SKIP_SYSTEMCTL_CHECK or os.path.exists(constants.SYSTEMCTL):
        process_utils.run_command([constants.SYSTEMCTL, 'reset-failed', 'libcare'])
        process_utils.run_command([constants.SYSTEMCTL, 'restart', 'libcare.socket'])
    else:
        try:
            cmd = [process_utils.find_cmd('service', ('/usr/sbin/', '/sbin/')), 'libcare', 'start']
        except Exception:  # pragma: no cover unit
            return
        process_utils.run_command(cmd)


def _libcare_info(patched=True, limit=None):
    regexp = '|'.join("({0})".format(proc) for proc in sorted(limit or []))
    cmd = ['info', '-j']
    if not patched:
        cmd += ['-l', '-r', regexp]

    try:
        lines = libcare_client(*cmd)
    except Exception as err:
        raise errors.KcareError("Gathering userspace libraries info error: '{0}'".format(err))

    result = []
    for line in lines.split('\n'):
        if line:
            try:
                result.append(json.loads(line))
            except ValueError:
                # We have to do that because socket's output isn't separated to stderr and stdout
                # so there are chances that will be non-json lines
                pass

    # FIXME: remove that libe when library names will be separated to lower
    # level from process name and pid
    result = [{'comm': line.pop('comm'), 'pid': line.pop('pid'), 'libs': line} for line in result]

    for line in result:
        line['libs'] = dict((k, v) for k, v in line['libs'].items() if ('patchlvl' in v or not patched))

    return result


def _get_patches_info(info):
    patches = set()
    for rec in info:
        for _, data in rec['libs'].items():
            patches.add((data['buildid'], data['patchlvl']))
    result = []
    for cache_dst in USERSPACE_MAP:
        for build_id, patchlvl in patches:
            patch_info_filename = get_userspace_cache_path(cache_dst, build_id, str(patchlvl), 'info.json')
            if os.path.isfile(patch_info_filename):
                with open(patch_info_filename, 'r') as fd:
                    result.append(json.load(fd))
    return result


def libcare_patch_info_basic():
    return _get_patches_info(_libcare_info())


@clear_libcare_cache
def libcare_patch_info():
    result = libcare_patch_info_basic()
    if not result:
        log_utils.logerror("No patched processes.")
    return json.dumps({'result': result})


@clear_libcare_cache
def libcare_info():
    result = _libcare_info()
    if not result:
        log_utils.logerror("No patched processes.")
    return json.dumps({'result': result})


def _libcare_version():
    result = {}
    for rec in libcare_patch_info_basic():
        result[rec.get('package')] = rec.get('latest-version', '')
    return result


def libcare_version(libname):
    for package, version in _libcare_version().items():
        if libname.startswith(package):
            return version
    return ''


def libcare_client_format(params):
    return b''.join(utils.bstr(p) + b'\0' for p in params) + b'\0'


def get_available_libcare_socket():
    for libcare_socket in LIBCARE_SOCKET:
        if os.path.exists(libcare_socket):
            return libcare_socket
    raise errors.KcareError("Libcare socket is not found.")


def libcare_client(*params):
    if config.LIBCARE_DISABLED:
        raise errors.KcareError('Libcare is disabled.')
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    sock.settimeout(10)  # connect timeout
    res = b''
    try:
        sock.connect(get_available_libcare_socket())
        sock.settimeout(config.LIBCARE_SOCKET_TIMEOUT)
        cmd = libcare_client_format(params)
        log_utils.logdebug("Libcare socket send: {cmd}".format(cmd=params))
        sock.sendall(cmd)
        while True:
            data = sock.recv(4096)
            if not data:
                break
            res += data
        result = res.decode('utf-8', 'replace')
        log_utils.logdebug("Libcare socket recieved: {result}".format(result=result))
        return result
    finally:
        sock.close()


def libcare_patch_apply(limit):
    for dst in limit:
        try:
            libcare_client('storage', get_userspace_cache_path(dst))
        except Exception as err:
            raise errors.KcareError("Userspace storage switching error: '{0}'".format(err))

        try:
            libcare_client('update')
        except Exception as err:
            raise errors.KcareError("Userspace patch applying error: '{0}'".format(err))


@clear_libcare_cache
@refresh_applied_patches_list
def libcare_unload():
    try:
        libcare_client('unload')
    except Exception as err:
        raise errors.KcareError("Userspace patch unloading error: '{0}'".format(err))


@selinux.skip_if_no_selinux_module
@clear_libcare_cache
@refresh_applied_patches_list
def do_userspace_update(mode=constants.UPDATE_MODE_MANUAL, limit=None):
    """Patch userspace processes to the latest version."""

    process_utils.log_all_parent_processes()
    rotate_libcare_logs()

    # Auto-update means cron-initiated run and if no
    # LIB_AUTO_UPDATE flag in the config - nothing will happen.
    if mode == constants.UPDATE_MODE_AUTO and not config.LIB_AUTO_UPDATE:
        return None

    if limit is None:
        limit = list(USERSPACE_MAP.keys())

    process_filter = []
    for userspace_patch in limit:
        process_filter.extend(USERSPACE_MAP.get(userspace_patch, []))

    if not process_filter:
        # Unknown limits were defined. Do nothing
        log_utils.loginfo('No such userspace patches: {0}'.format(limit))
        return None

    failed, something_found, _, before = check_userspace_updates(limit=process_filter)

    if failed:
        raise errors.KcareError('There was an errors while patches downloading (unpacking).')

    if not something_found:
        log_utils.loginfo('No patches were found.')
        return None

    selinux.restore_selinux_context(os.path.join(constants.PATCH_CACHE, 'userspace'))
    rotate_libcare_logs()

    try:
        # Batch apply for all collected patches
        libcare_patch_apply(limit)
        # TODO: clear userspace cache. We need the same logic as for kernel, lets do
        # it later to reduce this patch size.
    except errors.KcareError as ex:
        log_utils.logerror(str(ex))
        raise errors.KcareError('There was an errors while patches applying.')

    data_after = _libcare_info()
    after = _get_userspace_procs(data_after)

    if not any(list(item['libs'] for item in data_after)):
        # No patches were applied
        return None

    # Info on how many patches were actually patched via before and after diff
    log_utils.logdebug("Patched before: {before}".format(before=before))
    log_utils.logdebug("Patched after: {after}".format(after=after))
    uniq_procs_after = set(v for items in after.values() for v in items)
    uniq_procs_before = set(v for items in before.values() for v in items)
    diff = uniq_procs_after - uniq_procs_before

    overall = sum(len(v) for v in after.values())
    log_utils.loginfo(
        "The patches have been successfully applied to {count} newly "
        "discovered processes. The overall amount of applied patches "
        "is {overall}.".format(count=len(diff), overall=overall)
    )

    for k, v in after.items():
        log_utils.loginfo("Object `{0}` is patched for {1} processes.".format(k, len(v)))

    return data_after


@clear_libcare_cache
def get_userspace_update_status():
    try:
        failed, _, libs_not_patched, _ = check_userspace_updates()
    except errors.KcareError:
        return 3

    if failed:
        return 3

    if libs_not_patched:
        return 1

    return 2 if update_utils.status_gap_passed(filename='.libcarestatus') else 0


def _get_userspace_procs(info):
    result = {}  # type: Dict[str, List[Tuple[int, str]]]
    for item in info:
        for libname, rec in item['libs'].items():
            if rec.get('patchlvl'):
                if libname not in result:
                    result[libname] = []
                result[libname].append((item['pid'], item['comm']))
    return result


def _get_userspace_libs(info):
    result = set()
    for item in info:
        for libname, rec in item['libs'].items():
            result.add((libname, rec['buildid'], rec.get('patchlvl', 0)))
    return result


def check_userspace_updates(limit=None):
    if not limit:
        limit = []
        [limit.extend(libs) for libs in USERSPACE_MAP.values()]

    data_before = _libcare_info(patched=False, limit=limit)
    before = _get_userspace_procs(data_before)

    failed = something_found = False
    libs_not_patched = True
    for rec in _get_userspace_libs(data_before):
        # Download and unpack patches
        libname, build_id, patchlvl = rec
        try:
            fetch_userspace_patch(libname, build_id, patchlvl)
            something_found = True
            if patchlvl != 0:
                libs_not_patched = False
        except errors.CapabilitiesMismatch as e:
            failed = True
            log_utils.logwarn(str(e))
        except (errors.NotFound, errors.NoLibcareLicenseException):
            pass
        except errors.AlreadyTrialedException:
            raise
        except errors.KcareError as ex:
            failed = True
            log_utils.logerror(str(ex))

    update_utils.touch_status_gap_file(filename='.libcarestatus')

    return failed, something_found, libs_not_patched, before


def rotate_libcare_logs():
    rc = 0
    stderr = ''

    logrotate_path = process_utils.find_cmd('logrotate', raise_exc=False)
    if logrotate_path:
        try:
            rc, _, stderr = process_utils.run_command([logrotate_path, LIBCARE_LOGROTATE_CONFIG], catch_stderr=True)
        except Exception as e:
            rc = 1
            stderr = str(e)

        if rc:
            log_utils.logerror('failed to run logrotate for libcare logs, stderr: {0}'.format(stderr), print_msg=False)
    else:
        log_utils.logwarn("logrotate utility wasn't found", print_msg=False)

    libcare_log_directory = '/var/log/libcare/'
    if not os.path.isdir(libcare_log_directory):
        return

    max_total_size = config.LIBCARE_PIDLOGS_MAX_TOTAL_SIZE_MB * (1024**2)
    try:
        log_files = os.listdir(libcare_log_directory)
        pidlog_re = re.compile(r'^\d+\.log.*')  # both .log and .log.x.gz
        pidlog_files = [os.path.join(libcare_log_directory, fn) for fn in log_files if pidlog_re.match(fn)]

        pidlog_files_with_ct = [(os.path.getctime(fp), fp) for fp in pidlog_files]
        pidlog_files_with_ct.sort(reverse=True)  # newest files first

        # delete old files if we have overflow
        total_size = 0
        for _, filepath in pidlog_files_with_ct:
            total_size += os.path.getsize(filepath)
            if total_size >= max_total_size:
                os.remove(filepath)
                log_utils.kcarelog.info('Removed %s because of logs size limit', filepath)

    except Exception:  # pragma: no cover
        log_utils.logexc('Failed to cleanup libcare server logfiles', print_msg=False)


def libcare_server_started():
    """Assume that whenever the service is not running, we did not patch anything."""
    try:
        cmd = [process_utils.find_cmd('service', ('/usr/sbin/', '/sbin/')), 'libcare', 'status']
    except Exception:  # pragma: no cover unit
        return False

    code, _, _ = process_utils.run_command(cmd, catch_stdout=True, catch_stderr=True)
    return code == 0

