# Copyright (c) Cloud Linux Software, Inc
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENCE.TXT

import os
import subprocess
import textwrap

from . import log_utils, utils

if False:  # pragma: no cover
    from typing import List, Optional, Tuple, Union  # noqa: F401


@utils.cached
def find_cmd(name, paths=None, raise_exc=True):  # type: (str, Optional[tuple[str, ...]], bool) -> Optional[str]
    paths = paths or ('/usr/sbin', '/sbin', '/usr/bin', '/bin')

    for it in paths:
        fname = os.path.join(it, name)
        if os.path.isfile(fname):
            return fname

    if raise_exc:
        raise Exception('{0} could not be found at {1}'.format(name, paths))
    else:
        return None


def run_command(command, catch_stdout=False, catch_stderr=False, shell=False):  # mocked: tests/unit/conftest.py
    stdout = subprocess.PIPE if catch_stdout else None
    stderr = subprocess.PIPE if catch_stderr else None

    # We need to eventually keep shell=True as it might break customer's hooks, skip this bandit check.
    p = subprocess.Popen(command, stdout=stdout, stderr=stderr, shell=shell)  # nosec B602
    stdout_captured, stderr_captured = p.communicate()  # type: Union[bytes, str, None], Union[bytes, str, None]
    code = p.returncode

    if stdout_captured is not None:
        stdout_captured = utils.nstr(stdout_captured)
    if stderr is not None:
        stderr_captured = utils.nstr(stderr_captured)

    log_utils.logdebug(
        textwrap.dedent(
            """
       Call result for `{cmd}`:
       exit code {exit_code}
       === STDOUT ===
       {stdout}
       === STDERR ===
       {stderr}
       === END ===
    """
        ).format(exit_code=p.returncode, stdout=stdout_captured, stderr=stderr_captured, cmd=' '.join(command))
    )
    return code, stdout_captured, stderr_captured


def check_output(args):  # types: (Iterable[str]) -> str
    _, stdout, _ = run_command(args, catch_stdout=True)
    return stdout


def _get_parent_pid_and_process_name(pid):  # type: (int) -> tuple[Optional[int], Optional[str]]
    try:
        # use two subprocesses for ppid and comm to prevent parsing problems (there could be any symbols in comm)
        cmd_ppid = ['ps', '--no-headers', '-o', 'ppid', '-p', str(pid)]
        code, stdout, _ = run_command(cmd_ppid, catch_stdout=True)
        if code:
            log_utils.loginfo("Could not retrieve process parent PID for PID {pid}".format(pid=pid), print_msg=False)
            return None, None

        ppid = stdout.strip()

        cmd_comm = ['ps', '--no-headers', '-o', 'comm', '-p', str(pid)]
        code, stdout, _ = run_command(cmd_comm, catch_stdout=True)
        if code:
            log_utils.loginfo("Could not retrieve process name for PID {pid}".format(pid=pid), print_msg=False)
            return None, None

        name = stdout.strip()
        return int(ppid), name
    except Exception as e:
        log_utils.loginfo(
            "Could not retrieve process name and parent PID for PID {pid}, error: {err}".format(pid=pid, err=e), print_msg=False
        )
        return None, None


def log_all_parent_processes():  # type: () -> None
    process_chain = []  # type: list[tuple[int, Optional[str]]]
    current_pid = os.getpid()
    utils.print_wrapper(
        "[DEBUG] [file: kcarectl/process_utils.py, function: log_all_parent_processes] start, current pid: {0}".format(current_pid)
    )
    while current_pid != 1 and current_pid != 0:
        ppid, process_name = _get_parent_pid_and_process_name(current_pid)
        utils.print_wrapper("[DEBUG] pid: {0}, ppid: {1}, name: {2}".format(current_pid, ppid, process_name))
        process_chain.append((current_pid, process_name))

        if ppid is None:
            utils.print_wrapper("[DEBUG] ppid is None, stopping the chain walk")
            break
        current_pid = ppid

    log_utils.loginfo("Agent parent processes chain:", print_msg=False)
    utils.print_wrapper("[DEBUG] Agent parent processes chain:")
    for level, (pid, name) in enumerate(reversed(process_chain)):
        prefix = "-" * level + "->"
        log_utils.loginfo(
            '{prefix} "{name}" (pid: {pid})'.format(prefix=prefix, name=name or 'unknown', pid=pid or 'unknown'), print_msg=False
        )
        utils.print_wrapper(
            '[DEBUG] {prefix} "{name}" (pid: {pid})'.format(prefix=prefix, name=name or 'unknown', pid=pid or 'unknown')
        )

