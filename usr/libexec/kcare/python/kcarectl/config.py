# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT

from . import constants

if False:  # pragma: no cover
    from typing import Optional  # noqa: F401


AFTER_UPDATE_COMMAND = None
AUTO_STICKY_PATCHSET = None
AUTO_UPDATE = True
AUTO_UPDATE_DELAY = None
BEFORE_UPDATE_COMMAND = None
BLACKLIST_FILE = 'kpatch.blacklist'
CHECK_CLN_LICENSE_STATUS = True
CHECK_SSL_CERTS = True
FIXUPS_FILE = 'kpatch.fixups'
FLAGS = ['keep-registration', 'manage-libcare']
FORCE_GID = None
FORCE_JSON_SIG_V3 = False
HTTP_TIMEOUT = 20
IGNORE_UNKNOWN_KERNEL = False
KPATCH_DEBUG = False

# crash reporter
ENABLE_CRASHREPORTER = False
KDUMPS_DIR = constants.PATCH_CACHE + '/dumps'
KMSG_OUTPUT = True
KCORE_OUTPUT = True
KCORE_OUTPUT_SIZE = 100  # 100Mb

PATCH_LEVEL = None  # a level to 'stick on' (if 0 then use latest level)
LIBCARE_DISABLED = False
LIBCARE_PIDLOGS_MAX_TOTAL_SIZE_MB = 500
LIBCARE_SOCKET_TIMEOUT = 60
LIB_AUTO_UPDATE = True
PATCH_BIN = 'kpatch.bin'
PATCH_DONE = '.done'
PATCH_INFO = 'kpatch.info'
PATCH_METHOD = ''
PATCH_TYPE = ''
PREV_PATCH_TYPE = 'default'
REPORT_FQDN = False
SILENCE_ERRORS = True
STATUS_CHANGE_GAP = 4 * 60 * 60 + 5 * 60  # 4 hours
STICKY_PATCH = False
STICKY_PATCHSET = None
PREFIX = ''
UPDATE_DELAY = None
UPDATE_FROM_LOCAL = False
UPDATE_POLICY = constants.POLICY_REMOTE
USERSPACE_PATCHES = None
USE_CONTENT_FILE_V3 = False  # type: Optional[bool]
USE_SIGNATURE = True
PRINT_LEVEL = constants.PRINT_INFO
UPDATE_SYSCTL_CONFIG = True

KERNEL_VERSION_FILE = '/proc/version'
KCARE_UNAME_FILE = '/proc/kcare/effective_version'
SUCCESS_TIMEOUT = 5 * 60

# external services communication
FORCE_IPV4 = False
FORCE_IPV6 = False
PATCH_SERVER = 'https://patches.kernelcare.com'
PATCH_SERVER_IPV6 = 'https://ipv6.patches.kernelcare.com'
REGISTRATION_URL = 'https://cln.cloudlinux.com/api/kcare'
REGISTRATION_URL_IPV6 = 'https://ipv6.cln.cloudlinux.com/api/kcare'

