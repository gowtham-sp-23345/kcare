# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT

import base64
import json
import os
import platform
import time
import zlib

from . import capabilities, constants, http_utils, kcare, platform_utils, serverid, utils

if False:  # pragma: no cover
    from typing import Any, Dict  # noqa: F401


def server_info(reason, now=None, secure_boot_info=False, perf_metrics=False):
    data = dict()  # type: Dict[str, Any]
    data['ts'] = int(now or time.time())
    data['reason'] = reason

    data['machine'] = platform.machine()
    data['processor'] = platform.processor()
    data['release'] = platform.release()
    data['system'] = platform.system()
    data['version'] = platform.version()

    distro = platform_utils.get_distro()
    data['distro'] = distro[0]
    data['distro_version'] = distro[1]

    data['euname'] = kcare.kcare_uname()
    data['kcare_version'] = utils.strip_version_timestamp(constants.VERSION)
    data['last_stop'] = kcare.get_last_stop()
    data['node'] = platform_utils.get_hostname()
    data['uptime'] = platform_utils.get_uptime()
    data['virt'] = platform_utils.get_virt()
    data['proxy'] = http_utils.proxy_is_used()

    description = kcare.parse_patch_description(kcare.loaded_patch_description())
    data['ltimestamp'] = description['last-update']
    data['patch_level'] = description['patch-level']
    data['patch_type'] = description['patch-type']
    data['kmod'] = kcare.get_current_kmod_version() or ''
    data['crashreporter_ts'] = kcare.crashreporter_latest_event_timestamp()
    data['kdump_status'] = kcare.kdump_status()
    data['capabilities'] = capabilities.get_kc_capabilites_bits()

    try:
        data['kdump_ts'] = kcare.kdumps_latest_event_timestamp()
    except Exception:
        # Not critical data
        pass

    server_id = serverid.get_serverid()
    if server_id:
        data['server_id'] = server_id

    state = kcare.get_state()
    if state is not None:
        data['state'] = state

    if secure_boot_info:
        data['secure_boot'] = platform_utils.secure_boot_info()
    if perf_metrics:
        data['perf_metrics'] = platform_utils.get_performance_metrics()
    return data


def server_lib_info(reason, patch_level, now=None):
    data = dict()  # type: Dict[str, Any]
    data['ts'] = int(now or time.time())
    data['reason'] = reason
    data['patch_level'] = patch_level

    distro = platform_utils.get_distro()
    data['distro'] = distro[0]
    data['distro_version'] = distro[1]
    data['machine'] = platform.machine()

    data['kcare_version'] = utils.strip_version_timestamp(constants.VERSION)
    data['node'] = platform_utils.get_hostname()
    data['uptime'] = platform_utils.get_uptime()
    data['virt'] = platform_utils.get_virt()
    data['capabilities'] = capabilities.get_lc_capabilites_bits()

    stop_ts = 0.0
    if os.path.exists('/var/lib/libcare/stop'):
        stop_ts = os.path.getctime('/var/lib/libcare/stop')
    data['stop_ts'] = stop_ts

    return data


def encoded_server_info(reason, b64_encoding, secure_boot_info=False, perf_metrics=False):
    info = server_info(reason, secure_boot_info=secure_boot_info, perf_metrics=perf_metrics)
    return encode_checkin_payload(info, b64_encoding=b64_encoding)


def encoded_server_lib_info(reason, patch_level, now=None):
    info = server_lib_info(reason=reason, patch_level=patch_level, now=now)
    return encode_checkin_payload(info, b64_encoding=True)


def encode_checkin_payload(data, b64_encoding):
    # type: (Dict[str, Any], bool) -> str
    if b64_encoding:
        data_str = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
        return utils.nstr(base64.urlsafe_b64encode(zlib.compress(utils.bstr(data_str, 'utf-8'))))
    else:
        # legacy serialization
        return utils.nstr(base64.b16encode(utils.bstr(str(data))))

