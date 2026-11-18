# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT

from __future__ import print_function

import logging
import logging.handlers
import os
import sys
import traceback

from . import config, constants

kcarelog = logging.getLogger('kcare')  # mocked: tests/unit


def logdebug(message):
    # type: (str) -> None
    _printlvl(message, constants.PRINT_DEBUG)
    kcarelog.debug(message)


def loginfo(message, print_msg=True):
    # type: (str, bool) -> None
    if print_msg:
        _printlvl(message, constants.PRINT_INFO)
    kcarelog.info(message)


def logwarn(message, print_msg=True):
    if print_msg:
        _printlvl(message, constants.PRINT_WARN, file=sys.stderr)  # pragma: no cover
    kcarelog.warning(message)


def logerror(message, print_msg=True):
    if print_msg:
        _printlvl(message, constants.PRINT_ERROR, file=sys.stderr)
    kcarelog.error(message)


def logexc(message, print_msg=True):
    if print_msg and constants.PRINT_ERROR >= config.PRINT_LEVEL:
        traceback.print_exc()
    kcarelog.exception(message)


def _printlvl(message, level, file=None):
    if level >= config.PRINT_LEVEL:
        print(message, file=file)  # noqa: T201


def get_syslog_handler():
    syslog_formatter = logging.Formatter('kcare %(levelname)s: %(message)s')
    syslog_handler = logging.handlers.SysLogHandler(address='/dev/log', facility=logging.handlers.SysLogHandler.LOG_USER)
    syslog_handler.setLevel(logging.INFO)
    syslog_handler.setFormatter(syslog_formatter)
    return syslog_handler


def get_kcare_handler(level):
    kcare_formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
    if os.getuid() == 0:
        kcare_handler = logging.handlers.RotatingFileHandler(
            constants.LOG_FILE, maxBytes=1024**2, backupCount=2
        )  # type: logging.Handler
        # We need at least INFO level logs at all times
        kcare_handler.setLevel(min(level, logging.INFO))
        kcare_handler.setFormatter(kcare_formatter)
        return kcare_handler
    else:
        kcare_handler = logging.StreamHandler()
        kcare_handler.setLevel(level)
        kcare_handler.setFormatter(kcare_formatter)
        return kcare_handler


def initialize_logging(level):
    kcarelog.handlers[:] = []

    try:
        kcare_handler = get_kcare_handler(level)
        kcarelog.addHandler(kcare_handler)
    except Exception as ex:
        kcarelog.exception(ex)

    if os.path.exists('/dev/log'):
        try:
            syslog_handler = get_syslog_handler()
            kcarelog.addHandler(syslog_handler)
        except Exception as ex:
            kcarelog.exception(ex)


def print_cln_http_error(ex, url=None, stdout=True):
    url = url or '<route cannot be logged>'
    logerror('Unable to fetch {0}. Please try again later (error: {1})'.format(url, str(ex)), stdout)
