# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT

import sys

PRINT_DEBUG = 0
PRINT_INFO = 1
PRINT_WARN = 2
PRINT_ERROR = 3
PRINT_CRITICAL = 4
PY2 = sys.version_info[0] == 2
PY2_6 = PY2 and sys.version_info[1] == 6
PATCH_CACHE = '/var/cache/kcare'
CACHE_KEY_HEADER = 'Kc-Cache-Key'
CACHE_KEY_DUMP_PATH = '/etc/sysconfig/kcare/cache_key'
POLICY_REMOTE = 'REMOTE'
POLICY_LOCAL = 'LOCAL'
POLICY_LOCAL_FIRST = 'LOCAL_FIRST'
KC_PATCH_VERSION = '3'
LOG_FILE = '/var/log/kcarectl.log'

SIG = '.sig'
SIG_JSON = '.json-sig'

# false positives by bandit based on the `TOKEN` keyword in name
AUTH_TOKEN_HEADER = 'Kc-Auth-Token'  # nosec hardcoded_password_string
AUTH_TOKEN_DUMP_PATH = '/etc/sysconfig/kcare/auth_token'  # nosec hardcoded_password_string

# urlopen retry options
RETRY_DELAY = 3
RETRY_MAX_DELAY = 30
RETRY_BACKOFF = 2
RETRY_COUNT = 4

# helper vars for tests
SKIP_SYSTEMCTL_CHECK = False
SYSTEMCTL = '/usr/bin/systemctl'

UPDATE_MODE_MANUAL = 'manual'  # update is launched manually by `kcarectl -u`
UPDATE_MODE_AUTO = 'auto'  # update is launched by cron
UPDATE_MODE_SMART = 'smart'  # update is launched by kcare daemon

KMOD_BIN = 'kcare.ko'
KPATCH_CTL = '/usr/libexec/kcare/kpatch_ctl'

VERSION = '3.2-3'

