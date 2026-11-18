# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT

import os
import sys

from . import errors, log_utils, main, send_exc
from .py23 import URLError

# The scanner interface should skip us
os.environ['KCARE_SCANNER_INTERFACE_DO_NOTHING'] = '1'

if __name__ == '__main__':
    try:
        sys.exit(main())
    except URLError as err:
        log_utils.logerror('{0}: {1}'.format(err, getattr(err, 'url', 'unknown')))
    except errors.KcareError as err:
        log_utils.logerror(str(err))
        sys.exit(1)
    except Exception as err:
        if isinstance(err, errors.SafeExceptionWrapper):
            log_utils.logexc(err.inner)
        else:
            log_utils.logexc(err)
        send_exc()
        sys.exit(1)

