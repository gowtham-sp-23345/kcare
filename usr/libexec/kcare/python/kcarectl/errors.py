# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT

from .py23 import HTTPError


class SafeExceptionWrapper(Exception):
    def __init__(self, inner, etype=None, details=None):
        self.inner = inner
        self.etype = etype
        self.details = details


class KcareError(Exception):
    """Base kernelcare exception which will be considered as expected
    error and the full traceback will not be shown.
    """

    pass


class NotFound(HTTPError):
    pass


class NoLibcareLicenseException(KcareError):
    pass


class CapabilitiesMismatch(KcareError):
    pass


class AlreadyTrialedException(KcareError):
    def __init__(self, ip, created, *args, **kwargs):
        super(AlreadyTrialedException, self).__init__(*args, **kwargs)
        self.created = created[0 : created.index('T')]
        self.ip = ip

    def __str__(self):
        return 'The IP {0} was already used for a trial license on {1}'.format(self.ip, self.created)


class UnableToGetLicenseException(KcareError):
    def __init__(self, code):
        Exception.__init__(self, 'Unknown Issue when getting trial license. Error code: ' + str(code))


class BadSignatureException(KcareError):
    pass


def check_exc(*exc_list):
    def inner(e, state):
        return isinstance(e, exc_list)

    return inner

