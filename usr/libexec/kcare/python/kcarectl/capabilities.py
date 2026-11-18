# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT


if False:  # pragma: no cover
    from typing import List  # noqa: F401


def get_kc_capabilites_bits():
    # type: () -> int

    # a stub, will be encoded as int when we have some capabilities
    return 0


def get_lc_capabilites_bits():
    # type: () -> int

    # a stub, will be encoded as int when we have some capabilities
    return 0


def has_kc_capabilities(required_capabilities):
    # type: (List[str]) -> bool

    # currently agent doesn't have any capabilities
    # so we fail this check if there are any required capabilities
    return not required_capabilities


def has_lc_capabilities(required_capabilities):
    # type: (List[str]) -> bool

    # currently agent doesn't have any capabilities
    # so we fail this check if there are any required capabilities
    return not required_capabilities

