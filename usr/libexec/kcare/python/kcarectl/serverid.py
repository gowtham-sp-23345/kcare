# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT

import os

from . import errors, utils
from .py23 import json_loads_nstr

SYSTEMID = '/etc/sysconfig/kcare/systemid'
ALMA_SYSTEMID = '/etc/sysconfig/kcare/systemid.almacare'
IM360_LICENSE_FILE = '/var/imunify360/license.json'

if False:  # pragma: no cover
    from typing import Optional  # noqa: F401


def _systemid():
    # type: () -> Optional[str]
    if not os.path.exists(SYSTEMID):
        return None

    with open(SYSTEMID, 'r') as fd:
        for line in fd:
            param, _, value = line.partition('=')
            if param.strip() == 'server_id':
                return value.strip()
            raise errors.KcareError('Unable to parse {0}.'.format(SYSTEMID))

    return None


def _alma_systemid():
    # type: () -> Optional[str]
    if not os.path.exists(ALMA_SYSTEMID):
        return None
    with open(ALMA_SYSTEMID, 'r') as f:
        return f.readline().strip()


def _im360_systemid():
    # type: () -> Optional[str]
    if not os.path.exists(IM360_LICENSE_FILE):
        return None

    data = {}
    with open(IM360_LICENSE_FILE) as f:
        content = f.read()
        if content:
            try:
                data = json_loads_nstr(content)
            except Exception:
                pass  # we are not interested why lic file can't be parsed
    return data.get('id')


@utils.cached
def get_serverid():
    # type: () -> Optional[str]
    """Get server_id or None if not present.

    Lookup order: SYSTEMID then IM360_LICENSE_FILE then ALMA_SYSTEMID
    """
    return _systemid() or _im360_systemid() or _alma_systemid()


def rm_serverid():
    # type: () -> None
    os.unlink(SYSTEMID)


def set_server_id(server_id):
    # type: (str) -> None
    utils.atomic_write(SYSTEMID, 'server_id={0}\n'.format(server_id))

