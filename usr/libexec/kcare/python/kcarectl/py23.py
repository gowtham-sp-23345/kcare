# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT

import json

from . import constants

if constants.PY2:  # pragma: no py3 cover
    import httplib  # isort: skip - skipped because isort incorrectly treats it as third-party
    from urllib import quote as urlquote
    from urllib import urlencode

    from ConfigParser import ConfigParser
    from urllib2 import HTTPError
    from urllib2 import Request as StdRequest
    from urllib2 import URLError
    from urllib2 import urlopen as std_urlopen

    class Request(StdRequest):
        def __init__(self, *args, **kwargs):
            method = kwargs.pop('method', None)
            StdRequest.__init__(self, *args, **kwargs)
            if method == 'HEAD':
                # Older versions of mypy supporting 2.x do not infer type of
                # the `method` variable correctly here. Cast to str explicitly.
                self.get_method = lambda: str(method)  # type: ignore[assignment]

    # json.loads returns unicode strings and they can contaminate following
    # calls. Functions converts all unicode strings into native
    def _convert(data):
        dtype = type(data)
        if dtype is type(u''):
            return data.encode('utf-8')
        elif dtype is list:
            return [_convert(it) for it in data]
        elif dtype is dict:
            return dict((_convert(k), _convert(v)) for k, v in data.items())
        return data

    def json_loads_nstr(json_str):
        return _convert(json.loads(json_str))

else:  # pragma: no py2 cover
    from configparser import ConfigParser
    from http import client as httplib
    from urllib.error import HTTPError, URLError
    from urllib.parse import quote as urlquote
    from urllib.parse import urlencode
    from urllib.request import Request
    from urllib.request import urlopen as std_urlopen

    json_loads_nstr = json.loads

