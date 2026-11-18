# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT

import hashlib
import json
import os

import kcsig_verify  # noqa: E402

from . import auth, config, constants, errors, http_utils, selinux, utils

SIG_VERIFY_ORDER = [constants.SIG, constants.SIG_JSON]
GPG_BIN = '/usr/bin/gpg'
GPG_KEY_DIR = '/var/lib/kcare/gpg'
CONTENT_FILE = 'release.content.json'


def fetch_signature(url, dst, do_auth=False):
    urlopen_local = http_utils.urlopen
    if do_auth:
        urlopen_local = auth.urlopen_auth
    if config.FORCE_JSON_SIG_V3:
        sig_exts = SIG_VERIFY_ORDER[::-1]
    else:
        sig_exts = SIG_VERIFY_ORDER

    for sig_ext in sig_exts:
        try:
            signature = urlopen_local(url + sig_ext)
            break
        except errors.NotFound as nf:
            if sig_ext == sig_exts[-1]:
                raise nf  # pragma: no cover

    sig_dst = dst + sig_ext  # pragma: no cover
    utils.save_to_file(signature, sig_dst)
    return sig_dst


def check_gpg_bin():
    if not os.path.isfile(GPG_BIN):
        raise errors.KcareError('No {0} present. Please install gnupg'.format(GPG_BIN))


def check_gpg_signature(file_path, signature):  # mocked: tests/unit
    """
    Check a file signature using the gpg tool.
    If signature is wrong BadSignatureException will be raised.

    :param file_path: path to file which signature will be checked
    :param signature: a file with the signature
    :return: True in case of valid signature
    :raises: BadSignatureException
    """
    check_gpg_bin()

    if signature.endswith(constants.SIG_JSON):
        root_keys = os.path.join(GPG_KEY_DIR, 'root-keys.json')
        try:
            kcsig_verify.verify(signature, file_path, root_keys)
        except kcsig_verify.Error as e:
            raise errors.BadSignatureException('Bad Signature: {0}: {1}'.format(file_path, str(e)))
    else:
        with open(signature, 'rb') as f:
            sigdata = f.read()

        keyring = os.path.join(GPG_KEY_DIR, 'kcare_pub.key')
        try:
            kcsig_verify.run_gpg_verify(keyring, file_path, sigdata)
        except Exception as e:
            raise errors.BadSignatureException('Bad Signature: {0}: {1}'.format(file_path, str(e)))


# BadSignatureException is the only side effect of interrupted connection,
# should retry file extraction in this case
@utils.retry(errors.check_exc(errors.BadSignatureException), count=3, delay=0)
def fetch_url(url, dst, check_signature=False, hash_checker=None):
    response = auth.urlopen_auth(url)
    tmp = selinux.selinux_safe_tmpname(dst)
    utils.save_to_file(response, tmp)

    if hash_checker:
        hash_checker.check(url, tmp)
    elif check_signature:
        signature = fetch_signature(url, tmp, do_auth=True)
        check_gpg_signature(tmp, signature)

    os.rename(tmp, dst)
    return response


class HashChecker(object):
    def __init__(self, baseurl, content_file):
        self.content_file = content_file
        self.url_prefix = utils.get_patch_server_url(baseurl).rstrip('/') + '/'
        self.hashes = json.loads(utils.read_file(content_file))['files']

    def check(self, url, fname):
        cfname = url[len(self.url_prefix) :]

        if cfname not in self.hashes:
            raise errors.KcareError('Invalid checksum: {0} not found in content file {1}'.format(cfname, self.content_file))

        hsh = hashlib.sha256(utils.read_file_bin(fname)).hexdigest()
        expected_hsh = self.hashes[cfname]['sha256']
        if hsh != expected_hsh:
            raise errors.BadSignatureException(
                'Invalid checksum: {0} has invalid checksum {1}, expected {2}'.format(fname, hsh, expected_hsh)
            )


@utils.cached
def get_hash_checker(level):
    if not config.USE_CONTENT_FILE_V3:
        return None
    if not level.baseurl:
        return None
    dst = level.cache_path(CONTENT_FILE)
    if not os.path.exists(dst):
        try:
            # here we also implicitly check content file signature
            fetch_url(utils.get_patch_server_url(level.baseurl, CONTENT_FILE), dst, config.USE_SIGNATURE)
        except errors.NotFound:
            return None
    return HashChecker(level.baseurl, dst)


def wrap_with_cache_key(clbl):
    """Enrish request with a cache key, and save it if responce had."""

    def wrapper(*args, **kwargs):
        cache_key = utils.get_cache_key()
        if cache_key is not None:
            if 'headers' not in kwargs:
                kwargs['headers'] = {}
            kwargs['headers'][constants.CACHE_KEY_HEADER] = cache_key
        resp = clbl(*args, **kwargs)
        new_cache_key = resp.headers.get(constants.CACHE_KEY_HEADER)
        if new_cache_key is not None and new_cache_key != cache_key:
            utils.atomic_write(constants.CACHE_KEY_DUMP_PATH, new_cache_key)
        return resp

    return wrapper

