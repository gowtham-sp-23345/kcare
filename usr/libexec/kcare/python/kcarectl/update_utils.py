# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT

import os
import time

from . import config, constants, utils

STATUS_CHANGE_GAP_DELAY = 5 * 60  # 5 minute


def touch_status_gap_file(filename='.kcarestatus'):
    status_filepath = os.path.join(constants.PATCH_CACHE, filename)
    utils.atomic_write(status_filepath, utils.timestamp_str())


def status_gap_passed(filename='.kcarestatus'):
    status_filepath = os.path.join(constants.PATCH_CACHE, filename)
    if os.path.isfile(status_filepath):
        with open(status_filepath, 'r') as sfile:
            try:
                timestamp = int(sfile.read())
                if int(timestamp) + config.STATUS_CHANGE_GAP + STATUS_CHANGE_GAP_DELAY > time.time():
                    return False
            except Exception:
                pass
    return True

