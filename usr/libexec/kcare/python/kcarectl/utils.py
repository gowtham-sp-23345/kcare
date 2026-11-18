# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT

from __future__ import print_function

import fnmatch
import functools
import os
import random
import re
import shutil
import time
from datetime import datetime

from . import constants

if False:  # pragma: no cover
    from typing import Any, Callable, Optional, Tuple, TypeVar, Union  # noqa: F401

    T = TypeVar('T', bound=Callable[..., Any])


VERSION_RE = re.compile(r'^(\d+[.]\d+[-]\d+)')
CACHE_ENTRIES = 3


ntype = type('')
btype = type(b'')
utype = type(u'')


def atomic_write(fname, content, ensure_dir=False, mode='w'):
    # type: (str, Union[str, bytes], bool, str) -> None
    tmp_fname = fname + '.tmp'
    dname = os.path.dirname(tmp_fname)
    if ensure_dir and not os.path.exists(dname):
        os.makedirs(dname)
    with open(tmp_fname, mode) as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())

    # ensure folder is also updated
    # https://www.quora.com/When-should-you-fsync-the-containing-directory-in-addition-to-the-file-itself
    # https://www.reddit.com/r/kernel/comments/1du6ot8/comment/lbgu46i/?utm_source=share&utm_medium=web3x&utm_name=web3xcss&utm_term=1&utm_content=share_button
    folder_fd = os.open(dname, os.O_RDONLY)
    try:
        os.fsync(folder_fd)
    finally:
        os.close(folder_fd)

    os.rename(tmp_fname, fname)


def nstr(data, encoding='utf-8'):  # pragma: no py2 cover
    # type: (Union[str, bytes, None], str) -> str
    if type(data) is ntype:
        return data
    elif type(data) is btype:
        return data.decode(encoding)
    else:
        return data.encode(encoding)  # type: ignore  # pragma: no py3 cover


def bstr(data, encoding='latin1'):  # pragma: no py2 cover
    # type: (Union[str, bytes], str) -> bytes
    if type(data) is utype:
        data = data.encode(encoding)
    return data  # type: ignore


def ustr(data, encoding='latin1'):  # pragma: no py2 cover
    # type: (Union[str, bytes], str) -> str
    if type(data) is btype:
        data = data.decode(encoding)
    return data  # type: ignore


def cached(fn):
    # type: (T) -> Any
    cache = {}  # type: dict[tuple[Any, ...], Any]

    @functools.wraps(fn)
    def inner(*args, **kwargs):  # type: (Any, Any) -> Any
        cache_key = (args, tuple(sorted(kwargs.items())))
        try:
            return cache[cache_key]
        except KeyError:
            pass
        result = cache[cache_key] = fn(*args, **kwargs)
        return result

    inner.cache = cache  # type: ignore[attr-defined]
    inner.clear = cache.clear  # type: ignore[attr-defined]
    inner.orig = fn  # type: ignore[attr-defined]
    return inner


def retry(check_retry, count=None, delay=None, backoff=None):
    # type: (Callable[[Exception, dict[str, Any]], bool], Optional[int], Optional[float], Optional[float]) -> Callable[..., Any]
    if delay is None:
        delay = constants.RETRY_DELAY
    if count is None:
        count = constants.RETRY_COUNT
    if backoff is None:
        backoff = constants.RETRY_BACKOFF

    state = {}  # type: dict[str, Any]

    def decorator(fn):  # type: (Callable[..., Any]) -> Callable[..., Any]
        def inner(*args, **kwargs):  # type: (Any, Any) -> Any
            ldelay = delay
            for _ in range(count):
                try:
                    return fn(*args, **kwargs)
                except Exception as ex:
                    if not check_retry(ex, state):
                        raise

                time.sleep(ldelay)
                # bandit warns about using random.uniform for security which is not the case here
                ldelay = min(ldelay * random.uniform(1, backoff), constants.RETRY_MAX_DELAY)  # nosec B311
            # last try
            try:
                return fn(*args, **kwargs)
            except Exception as final_ex:
                setattr(final_ex, 'attempts', count)
                raise

        return inner

    return decorator


def clean_directory(directory, exclude_path=None, keep_n=CACHE_ENTRIES, pattern=None):
    # type: (str, Optional[str], int, Optional[str]) -> None
    if not os.path.exists(directory):
        return
    data = []
    items = os.listdir(directory)
    if pattern is not None:
        items = fnmatch.filter(items, pattern)
    for item in items:
        full_path = os.path.join(directory, item)
        if full_path != exclude_path:
            data.append((os.stat(full_path).st_mtime, full_path))
        data.sort(reverse=True)
    for _, entry in data[keep_n:]:
        if os.path.isfile(entry) or os.path.islink(entry):
            os.remove(entry)
        else:
            shutil.rmtree(entry)


def clear_all_cache():
    # type: () -> None
    clean_directory(os.path.join(constants.PATCH_CACHE, 'modules'), keep_n=0)
    clean_directory(os.path.join(constants.PATCH_CACHE, 'patches'), keep_n=0)
    if os.path.exists(constants.CACHE_KEY_DUMP_PATH):
        os.unlink(constants.CACHE_KEY_DUMP_PATH)


def save_to_file(response, dst):
    # type: (Any, str) -> None
    parent_dir = os.path.dirname(dst)
    if not os.path.exists(parent_dir):
        os.makedirs(parent_dir)
    with open(dst, 'wb') as f:
        shutil.copyfileobj(response, f)
        f.flush()
        os.fsync(f.fileno())


def strip_version_timestamp(version):
    # type: (str) -> str
    match = VERSION_RE.match(version)
    return match and match.group(1) or version


def parse_response_date(str_raw):
    # type: (str) -> datetime
    # Try to split it by T
    str_date, sep, _ = str_raw.partition('T')
    # No success - split by space
    if not sep:
        str_date, _, _ = str_raw.partition(' ')
    return datetime.strptime(str_date, '%Y-%m-%d')


def get_patch_server_url(*parts):
    # type: (*str) -> str
    from . import ipv6_support  # TODO fix circular import

    return '/'.join(it.strip('/') for it in filter(None, (ipv6_support.get_patch_server(),) + parts))


def try_to_read(filename):
    # type: (str) -> Optional[str]
    if not os.path.exists(filename):
        return None

    with open(filename) as f:
        return f.read().strip()


@cached
def get_cache_key():
    # type: () -> Optional[str]
    return try_to_read(constants.CACHE_KEY_DUMP_PATH)


def _read_file(fname, mode, default):
    # type: (str, str, Optional[Union[str, bytes]]) -> Union[str, bytes]
    if not os.path.exists(fname):
        return default  # type: ignore
    with open(fname, mode) as f:
        return f.read()  # type: ignore


def read_file(fname, default=None):
    # type: (str, Optional[str]) -> str
    result = _read_file(fname, 'r', default)  # type: str  # type: ignore[assignment]
    return result


def read_file_bin(fname, default=None):
    # type: (str, Optional[bytes]) -> bytes
    result = _read_file(fname, 'rb', default)  # type: bytes  # type: ignore[assignment]
    return result


def data_as_dict(data):
    # type: (str) -> dict[str, str]
    result = {}
    data_lines = data.splitlines()  # type: list[str]
    for line in data_lines:
        if line:
            key, delimiter, value = line.partition(':')
            if delimiter:
                result[key] = value.strip()
    return result


def timestamp_str():
    # type: () -> str
    return str(int(time.time()))


def print_wrapper(*values):
    # type: (object) -> None
    """a workaround to fix T201"""
    print(*values)  # noqa: T201


def catch_errors(logger=None, errors=(Exception,), default_return=None):
    # type: (Optional[Callable[[str], None]], Tuple[Any, ...], Any) -> Callable[..., Any]

    def decorator(fn):
        # type: (T) -> Callable[..., Any]
        @functools.wraps(fn)
        def inner(*args, **kwargs):
            # type: (Any, Any) -> Any
            try:
                return fn(*args, **kwargs)
            except errors as e:
                if logger:  # pragma: no branch
                    arg_list = [str(a) for a in args] + ['{0}={1}'.format(k, v) for k, v in kwargs.items()]
                    logger('{0}({1}) failed: {2}'.format(fn.__name__, ', '.join(arg_list), e))
                return default_return

        return inner

    return decorator
