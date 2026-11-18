# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT

from . import config, http_utils, log_utils, serverid, utils

if False:  # pragma: no cover
    from typing import Optional  # noqa: F401

# from CLN sources:
# code: 0 -> valid license (for key based, or ip based)
# code: 1 -> trial license, unexpired
# code: 2 -> no valid license, but there is expired trial license
# code: 3 -> no valid or trial license

CLN_VALID_LICENSE = 0
CLN_TRIAL_ACTIVE_LICENSE = 1
CLN_NO_LICENSE = 3


class IPProtoSelector(object):
    def __init__(self):
        # type: () -> None
        self._cached_result = None  # type: Optional[bool]

    def is_ipv6_preferred(self):
        # type: () -> bool
        """
        Choose ipv6 if it is more suitable.
        Checks order:
        - check config values (it is faster) - eportal setup and FORCE_IPVx
        - then check each proto availability using HEAD requests
        - then check if we have server_id, it means we don't expect an ip license
        - and finally we need to check if there is an ip license
        """
        # each case is in a separate block for better coverage check
        if config.FORCE_IPV4:
            log_utils.logdebug('decided to use ipv4 because of config values')
            return False
        elif not config.PATCH_SERVER.endswith('kernelcare.com'):
            # eportal setup, we don't need to change urls
            log_utils.logdebug('decided to use ipv4 because of config values')
            return False
        elif config.FORCE_IPV6:
            log_utils.logdebug('decided to use ipv6 because of config values')
            return True

        # further checks are more expensive, use cached value if it is set
        if self._cached_result is not None:
            return self._cached_result

        result = None
        if not self._is_url_reachable(config.PATCH_SERVER_IPV6):
            log_utils.logdebug('decided to use ipv4 because ipv6 is not available')
            result = False
        elif not self._is_url_reachable(config.PATCH_SERVER):
            log_utils.logdebug('decided to use ipv6 because ipv4 is not available')
            result = True
        elif serverid.get_serverid():
            log_utils.logdebug('decided to use ipv4 because server id was found')
            result = False

        if result is not None:
            self._cached_result = result
            return result

        ipv4_license = self._get_cln_license(ipv6=False)
        ipv6_license = self._get_cln_license(ipv6=True)

        if ipv4_license == CLN_VALID_LICENSE:
            log_utils.logdebug('decided to use ipv4 because ipv4 license was found')
            result = False
        elif ipv6_license == CLN_VALID_LICENSE:
            log_utils.logdebug('decided to use ipv6 because ipv6 license was found')
            result = True
        elif ipv4_license == CLN_TRIAL_ACTIVE_LICENSE:
            log_utils.logdebug('decided to use ipv4 because ipv4 trial license was found')
            result = False
        elif ipv6_license == CLN_TRIAL_ACTIVE_LICENSE:
            log_utils.logdebug('decided to use ipv6 because ipv6 trial license was found')
            result = True
        else:
            # we don't have any license yet
            result = False

        self._cached_result = result
        return result

    @staticmethod
    def _is_url_reachable(url):
        # type: (str) -> bool
        request = http_utils.http_request(url, method='HEAD', auth_string=None)  # type: ignore[no-untyped-call]
        try:
            http_utils.urlopen(request, timeout=10, retry_on_500=False, retry_count=2)  # type: ignore[no-untyped-call]
            return True
        except Exception as e:
            log_utils.logdebug('error during HEAD request to {0}: {1}'.format(url, str(e)))
            return False

    @staticmethod
    def _get_cln_license(ipv6):
        # type: (bool) -> int
        base_url = config.REGISTRATION_URL_IPV6 if ipv6 else config.REGISTRATION_URL

        # a comment from auth.py:
        # do not retry in case of 500 from CLN!
        # otherwise, CLN will die in pain because of too many requests
        url = base_url + '/check.plain'
        content = utils.nstr(http_utils.urlopen(url, retry_on_500=False).read())  # type: ignore[no-untyped-call]
        info = utils.data_as_dict(content)
        if not info or not info.get('code'):
            log_utils.kcarelog.error('Unexpected CLN response: {0}'.format(content))
            return CLN_NO_LICENSE

        try:
            return int(info['code'])
        except ValueError:
            return CLN_NO_LICENSE


ip_proto_selector = IPProtoSelector()


def get_patch_server():
    # type: () -> str
    return config.PATCH_SERVER_IPV6 if ip_proto_selector.is_ipv6_preferred() else config.PATCH_SERVER


def get_registration_url():
    # type: () -> str
    return config.REGISTRATION_URL_IPV6 if ip_proto_selector.is_ipv6_preferred() else config.REGISTRATION_URL

