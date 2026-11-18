# COPY of scripts/kcsig/kcsig/verify.py from 4fdf3255d5490df60f7dd
import base64
import contextlib
import json
import os
import shutil
import subprocess
import tempfile

if False:
    from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple, Union  # noqa: F401

    from .types import AnyKey, ReleaseKey, RootKey, RootKeys, Signature, anystr  # noqa: F401

AVAILABLE_KINDS = ['rsa4096']
PAE_FIELDS = {'gpg': ('type', 'kind', 'role', 'serial', 'key')}
TMPDIR = '/dev/shm'

btype = type(b'')
utype = type(u'')
ntype = type('')


class Error(Exception):
    pass


def to_bytes(data, encoding='latin1'):
    # type: (Union[str, bytes, int], str) -> bytes
    dtype = type(data)
    if dtype is btype:
        return data  # type: ignore
    elif dtype is utype:
        return data.encode(encoding)  # type: ignore
    elif dtype is int:
        return to_bytes(str(data))
    raise ValueError('Unsupported pae type ' + str(dtype))


def nstr(data):  # type: (anystr) -> str
    dtype = type(data)
    if dtype is ntype:
        return data  # type: ignore
    elif dtype is btype:
        return data.decode('utf-8')  # type: ignore
    elif dtype is utype:  # pragma: no cover, used only in py2
        return data.encode('utf-8')  # type: ignore
    raise NotImplementedError  # pragma: no cover


def atomic_write(fname, content, mode='w'):
    # type: (str, anystr, str) -> None
    tmp_fname = fname + '.tmp'
    with open(tmp_fname, mode) as f:
        f.write(content)
    os.rename(tmp_fname, fname)


def read_file(fname):  # type: (str) -> str
    with open(fname) as f:
        return f.read()


def read_json(fname):  # type: (str) -> Any
    return json.loads(read_file(fname))


def pae(*parts):
    # type: (Union[str, bytes, int]) -> bytes
    result = b'%d' % len(parts)
    for p in parts:
        bp = to_bytes(p)
        result += b'%d%s' % (len(bp), bp)
    return result


def pae_fields(data, fields):
    # type: (Mapping[str, Any], Sequence[str]) -> bytes
    return pae(*[data[f] for f in fields])


def pae_type(data):  # type: (ReleaseKey) -> bytes
    return pae_fields(data, PAE_FIELDS[data['type']])


def check_key(key):  # type: (AnyKey) -> None
    if key['type'] not in PAE_FIELDS:
        raise ValueError('invalid key type: ' + nstr(key['type']))


@contextlib.contextmanager
def temp_datafile(data, data_is_file):  # type: (anystr, bool) -> Iterator[str]
    if data_is_file:
        yield data  # type: ignore
    else:
        with tempfile.NamedTemporaryFile(dir=TMPDIR, prefix='kcsig-data-') as f:
            f.write(to_bytes(data))
            f.flush()
            yield f.name


@contextlib.contextmanager
def temp_directory(prefix, dir):  # type: (str, str) -> Iterator[str]
    temp_dir = tempfile.mkdtemp(prefix=prefix, dir=dir)
    try:
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir)


def run_gpg_verify(keyfile, datafile, sigdata):
    # type: (str, str, bytes) -> None
    with temp_directory(dir=TMPDIR, prefix='kcsig-gpgtmp-') as tmp_dir:
        cmd = ['gpg', '--homedir', tmp_dir, '--keyring', keyfile, '--verify', '-', datafile]
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate(sigdata)
        if p.returncode != 0:
            raise Exception('Verify error: ' + nstr(stderr) + '\n' + nstr(stdout))


def verify_key(signature, key, data, data_is_file):
    # type: (str, AnyKey, anystr, bool) -> None
    check_key(key)
    with tempfile.NamedTemporaryFile(dir=TMPDIR, prefix='kcsig-key-') as key_file:
        key_file.write(base64.b64decode(to_bytes(key['key'])))
        key_file.flush()
        with temp_datafile(data, data_is_file) as datafile:
            sigdata = base64.b64decode(to_bytes(signature))
            run_gpg_verify(key_file.name, datafile, sigdata)


def verify_count(signatures, keys, data, data_is_file=False):
    # type: (Mapping[str, str], Mapping[str, RootKey], anystr, bool) -> Tuple[int, Mapping[str, str]]
    count = 0
    errors = {}
    for keyid, sig in signatures.items():
        if keyid not in keys:
            errors[keyid] = 'no corresponding root key'
            continue

        try:
            verify_key(sig, keys[keyid], data, data_is_file)
        except Exception as e:
            errors[keyid] = str(e)
        else:
            count += 1

    return count, errors


def _verify(sigdata, datafile, root_keys, kinds=None):
    # type: (Signature, str, RootKeys, Optional[List[str]]) -> None
    threshold = root_keys.get('threshold', 9999)
    min_serial = root_keys.get('min_serial', 99999999)

    errors = {}  # type: Dict[str, Union[str, Mapping[str, str]]]
    kinds = kinds or AVAILABLE_KINDS

    applicable_keys = {}
    for keyid, key in sigdata['keys'].items():
        try:
            check_key(key)
            if key['kind'] not in kinds:
                errors[keyid] = 'invalid kind {0}, accepted list is {1}'.format(key['kind'], kinds)
            elif key['serial'] < min_serial:
                errors[keyid] = 'invalid serial {0}, current is {1}'.format(key['serial'], min_serial)
            else:
                applicable_keys[keyid] = key
        except Exception as e:
            errors[keyid] = str(e)
            continue

    verified_keys = {}
    for keyid, key in applicable_keys.items():
        count, root_errors = verify_count(key['signatures'], root_keys['keys'], data=pae_type(key))
        if count < threshold:
            errors[keyid] = root_errors
        else:
            verified_keys[keyid] = key

    count = 0
    for keyid, key in verified_keys.items():
        try:
            verify_key(sigdata['signatures'][keyid], key, data=datafile, data_is_file=True)
        except Exception as e:
            errors[keyid] = str(e)
        else:
            count += 1

    if not count:
        raise Error('Error validating file signature: ' + json.dumps(errors))


def verify(sigfile, datafile, rootfile, kinds=None):
    # type: (str, str, str, Optional[List[str]]) -> None
    sigdata = read_json(sigfile)  # type: Signature
    root_keys = read_json(rootfile)  # type: RootKeys
    _verify(sigdata, datafile, root_keys, kinds=kinds)

