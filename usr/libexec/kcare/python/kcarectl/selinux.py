# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT

import os

from . import errors, log_utils, process_utils, utils


def selinux_safe_tmpname(fname):
    head, tail = os.path.split(fname)
    return os.path.join(head, 'tmp.' + tail)


def restore_selinux_context(dname):
    if is_selinux_enabled():
        # Try to restore selinux context
        cmd = [process_utils.find_cmd('restorecon', ('/usr/sbin', '/sbin')), '-R', dname]
        code, _, stderr = process_utils.run_command(cmd, catch_stdout=True, catch_stderr=True)
        if code:
            log_utils.logerror(
                "SELinux context restoration for {0} failed with {1}: {2}".format(dname, code, stderr), print_msg=False
            )


def is_selinux_module_present(semodule_name):
    code, out, err = process_utils.run_command(['/usr/sbin/semodule', '-l'], catch_stdout=True)
    if code:
        raise errors.KcareError("SELinux modules list gathering error: '{0}' {1}".format(err, code))
    for line in out.split('\n'):
        if semodule_name in line:
            return True
    return False


def skip_if_no_selinux_module(clbl):
    def wrapper(*args, **kwargs):
        if is_selinux_enabled() and not is_selinux_module_present('libcare'):
            raise errors.KcareError('SELinux is enabled but libcare policy module is not loaded')
        return clbl(*args, **kwargs)

    return wrapper


@utils.cached
def is_selinux_enabled():
    if os.path.isfile('/usr/sbin/selinuxenabled'):
        code, _, _ = process_utils.run_command(['/usr/sbin/selinuxenabled'])
    else:
        return False
    return code == 0

