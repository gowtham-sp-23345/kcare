# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT

import base64
import json
import os
import platform
import re
import socket
import sys

from . import config, constants, log_utils, process_utils, selinux, utils

if False:  # pragma: no cover
    from typing import Any, Dict, Optional, Tuple  # noqa: F401

VIRTWHAT = '/usr/libexec/kcare/virt-what'
PROC_DIR = '/proc'


def get_distro():
    if sys.version_info[:2] < (3, 6):  # pragma: no py3 cover
        return platform.linux_distribution()
    else:  # pragma: no distro cover
        import distro

        return distro.linux_distribution(full_distribution_name=False)


@utils.cached
def get_system_uname():
    return platform.uname()[2]


def get_python_version():  # type: () -> str
    return '%s.%s' % (sys.version_info[0], sys.version_info[1])


def app_info(is_json=False):  # type: (bool) -> str
    info = {
        'python_version': get_python_version(),
        'agent_version': constants.VERSION,
    }

    if selinux.is_selinux_enabled():
        rc, stdout, stderr = process_utils.run_command(['ps', '-Z', '--no-headers', '--pid', str(os.getpid())], catch_stdout=True)
        if not rc:
            selinux_context = stdout.split()[0]
        else:
            selinux_context = 'error: %s' % stderr

        info['selinux_context'] = selinux_context

    if is_json:
        return json.dumps(info)

    info_keys = sorted(info)
    info_str = ''
    for info_key in info_keys:
        info_str += '%s: %s\n' % (info_key, info[info_key])

    return info_str.rstrip()


EFIVARS_PATH = '/sys/firmware/efi/efivars'
EFI_VENDORS = {
    'global': '8be4df61-93ca-11d2-aa0d-00e098032b8c',
    'shim': '605dab50-e046-4300-abb6-3dd810dd8b23',
}


def _read_uefi_var(name, vendor, max_bytes=256):
    # type: (str, str, Optional[int]) -> Optional[bytes]
    var_path = os.path.join(EFIVARS_PATH, '%s-%s' % (name, vendor))
    if not os.path.exists(var_path):
        return None
    with open(var_path, 'rb') as var:
        return var.read(max_bytes)


def is_secure_boot():  # mocked: tests/unit/test_load_kmod.py
    # type: () -> bool
    try:
        secure_boot_var = _read_uefi_var('SecureBoot', EFI_VENDORS['global'])
        if secure_boot_var:
            return secure_boot_var[-1:] == b'\x01'  # Get last byte
    except Exception:  # pragma: no cover
        pass
    return False


def _get_uefi_var_encoded(name, vendor):
    # type: (str, str) -> Optional[str]
    try:
        value_bytes = _read_uefi_var(name, vendor)
        if value_bytes is None:
            return None
    except Exception as e:
        value_bytes = str(e).encode()
    return utils.nstr(base64.urlsafe_b64encode(value_bytes))


def secure_boot_info():
    # type: () -> dict[str, Any]
    cmdline = utils.try_to_read(os.path.join(PROC_DIR, 'cmdline'))
    if cmdline and len(cmdline) > 1024:  # pragma: no cover
        cmdline = cmdline[:1024]
    info = {'cmdline': cmdline, 'has_efi': os.path.exists(os.path.dirname(EFIVARS_PATH))}  # type: dict[str, Any]
    if not info['has_efi']:
        return info

    try:
        info['global'] = dict((var, _get_uefi_var_encoded(var, EFI_VENDORS['global'])) for var in ('SecureBoot', 'SetupMode'))
        shim_vars = sorted(
            [var[0 : -len(EFI_VENDORS['shim']) - 1] for var in os.listdir(EFIVARS_PATH) if var.endswith(EFI_VENDORS['shim'])]
        )
        info['shim'] = {'vars': shim_vars}
        shim_exclude_vars = set(['MokListRT', 'MokListXRT', 'MokListTrustedRT', 'SbatLevelRT'])
        for var in shim_vars:
            if var in ('HSIStatus', 'MokIgnoreDB') or (var.endswith('RT') and var not in shim_exclude_vars):
                info['shim'][var] = _get_uefi_var_encoded(var, EFI_VENDORS['shim'])
    except Exception as err:
        log_utils.logwarn(err)
    return info


@utils.cached
def get_hostname():
    # type: () -> str
    # KCARE-1165  If fqdn gathering is forced
    if config.REPORT_FQDN:
        try:
            # getaddrinfo() -> [(family, socktypeget_hostname, proto, canonname, sockaddr), ...]
            hostname = socket.getaddrinfo(socket.gethostname(), 0, 0, 0, 0, socket.AI_CANONNAME)[0][3]
        except socket.gaierror as ge:
            log_utils.logerror(ge)
            hostname = platform.node()
    else:
        hostname = platform.node()
    return hostname


@utils.cached
def get_uptime():
    # type: () -> str
    uptime_file = os.path.join(PROC_DIR, 'uptime')
    if os.path.isfile(uptime_file):
        f = open(uptime_file, 'r')
        line = f.readline()
        result = str(int(float(line.split()[0])))
        f.close()
        return result
    return '-1'


@utils.cached
def get_virt():
    if os.path.isfile(VIRTWHAT):
        return process_utils.check_output([VIRTWHAT]).strip()
    return 'no-virt-what'  # pragma: no cover


def is_cpanel():
    return os.path.isfile('/usr/local/cpanel/cpanel')


def inside_vz_container():  # mocked: tests/unit/test_load_kmod.py
    return os.path.exists(os.path.join(PROC_DIR, 'vz', 'veinfo')) and not os.path.exists(os.path.join(PROC_DIR, 'vz', 'version'))


def inside_lxc_container():  # mocked: tests/unit/test_load_kmod.py
    return '/lxc/' in open(os.path.join(PROC_DIR, '1', 'cgroup')).read()


def inside_docker_container():  # mocked: tests/unit/test_load_kmod.py
    return os.path.isfile('/.dockerenv')


@utils.catch_errors(logger=log_utils.logwarn)
def get_load_average():
    # type: () -> Optional[Tuple[float, float, float]]
    loadavg = utils.try_to_read(os.path.join(PROC_DIR, 'loadavg'))
    if not loadavg:
        return None
    m1, m5, m15, _ = loadavg.split(' ', 3)
    return (float(m1), float(m5), float(m15))


@utils.catch_errors(logger=log_utils.logwarn)
def get_mem_info():
    # type: () -> Optional[Dict[str, int]]
    """Returns dict of memory info in kB"""

    meminfo = utils.try_to_read(os.path.join(PROC_DIR, 'meminfo'))
    if not meminfo:
        return None
    filter_params = ('MemTotal', 'MemFree', 'SwapTotal', 'SwapFree')
    # optional units are ignored (assumed to be always kB for mem size)
    return dict((k, int(v)) for k, v in (re.split(r'[\s:]+', line)[:2] for line in meminfo.splitlines()) if k in filter_params)


@utils.cached
@utils.catch_errors(logger=log_utils.logwarn)
def get_cpu_info():
    # type: () -> Optional[Dict[str, Any]]
    cpuinfo = utils.try_to_read(os.path.join(PROC_DIR, 'cpuinfo'))
    if not cpuinfo:
        return None
    cpus = [
        dict(re.split(r'\s*:\s*', line) for line in cpu_lines.splitlines())
        for cpu_lines in cpuinfo.split('\n\n')  # cpu records are separated by an empty line
        if cpu_lines
    ]
    return {
        'logical_cores': len(cpus),
        'physical_cores': len(set((cpu.get('physical id'), cpu.get('core id')) for cpu in cpus)),
        'vendor_id': cpus[0].get('vendor_id'),
        'model': int(cpus[0].get('model', 0)),
        'model_name': cpus[0].get('model name'),
        'cpu_family': int(cpus[0].get('cpu family', 0)),
        'stepping': int(cpus[0].get('stepping', 0)),
        'microcode': cpus[0].get('microcode'),
        'flags': cpus[0].get('flags', '').split(),
    }


@utils.catch_errors(logger=log_utils.logwarn, default_return=(0, 0))
def get_proc_files_count():
    # type: () -> Tuple[int, int]
    """Return tuple of total processes and total opened files"""
    total_processes = total_opened_files = 0
    for _root, dirs, _files in os.walk(PROC_DIR):
        for pid_dir in dirs:
            if not pid_dir.isdigit():
                continue
            try:
                total_opened_files += len(os.listdir(os.path.join(PROC_DIR, pid_dir, 'fd')))
                total_processes += 1
            except Exception:
                pass
    return total_processes, total_opened_files


@utils.catch_errors(logger=log_utils.logwarn)
def get_vm_count_kvm():
    # type: () -> Optional[int]
    for _root, dirs, _files in os.walk('/sys/kernel/debug/kvm'):
        return len(dirs)
    return None


@utils.catch_errors(logger=log_utils.logwarn, default_return=(0, 0))
def get_network_connections_count():
    # type: () -> Tuple[int, int]
    """Return tuple of total numbers of TCP and UDP connections"""

    def conn_records_count(proto):
        # type: (str) -> int
        records = utils.try_to_read(os.path.join(PROC_DIR, 'net', proto))
        if not records:
            return 0
        return max(len(records.splitlines()) - 1, 0)

    return conn_records_count('tcp') + conn_records_count('tcp6'), conn_records_count('udp') + conn_records_count('udp6')


def get_performance_metrics():
    # type: () -> Dict[str, Any]
    # FIXME KPT-5363: disable get_proc_files_count()
    proc_count, files_count = -1, -1
    conn_tcp, conn_udp = get_network_connections_count()
    return {
        'load_average': get_load_average(),
        'mem_info': get_mem_info(),
        'cpu_info': get_cpu_info(),
        'vm_count': get_vm_count_kvm(),
        'processes': proc_count,
        'open_files': files_count,
        'tcp_connections': conn_tcp,
        'udp_connections': conn_udp,
    }

