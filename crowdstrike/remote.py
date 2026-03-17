import contextlib
import random
import socket
import threading

from crowdstrike.obfuscate import obfuscate_script, is_encoded

# Prepended to every PowerShell block sent over WinRM to ensure scripts
# are not blocked by a restrictive execution policy on the remote host.
_PS_BYPASS = 'Set-ExecutionPolicy Bypass -Scope Process -Force; '


def check_and_install_remote(
    host: str,
    cid: str,
    server_url: str,
    username: str,
    password: str = None,
    ssh_key: str = None,
    domain: str = None,
    winrm_auth: str = 'ntlm',
    psexec_path: str = None,
    obfuscate: str = 'none',
    pivot: list = None,
    ssh_username: str = None,
    ssh_password: str = None,
):
    """
    pivot (optional): list of dicts, each with keys ip, username, password, ssh_key,
    winrm_auth, transport.  Ordered from nearest to furthest hop (operator → ... → target).
    When set, connections are routed through the chain.

    ssh_username / ssh_password (optional): separate credentials for SSH targets.
    Fall back to username / password if not set.
    """
    # Resolve SSH creds before domain formatting so we never pass DOMAIN\user to SSH.
    ssh_user = ssh_username or username
    ssh_pass = ssh_password or password

    # Format username for domain auth if a domain was supplied.
    # Accepts DOMAIN\\user, user@domain.com, or bare username for local accounts.
    if domain and username and '\\' not in username and '@' not in username:
        username = f'{domain}\\{username}'

    # For pivot hosts, port reachability was already confirmed via probe_via_pivot;
    # skip the direct _port_open checks and trust the HostInfo flags instead.
    if pivot:
        # We know which ports are open from the pivot probe — caller passes this
        # info implicitly through the fact that we reached here.  Attempt transports
        # in priority order; each handler will fail fast if the port is wrong.
        if not _handle_winrm(host, cid, server_url, username, password, winrm_auth, obfuscate, pivot=pivot):
            if not _handle_ssh(host, cid, server_url, ssh_user, ssh_pass, ssh_key, pivot=pivot):
                chain_str = ' → '.join(h['ip'] for h in pivot)
                print(f'[!] {host}: No usable remoting transport via chain {chain_str}.')
        return

    if _port_open(host, 5985) or _port_open(host, 5986):
        _handle_winrm(host, cid, server_url, username, password, winrm_auth, obfuscate)
    elif _port_open(host, 22):
        _handle_ssh(host, cid, server_url, ssh_user, ssh_pass, ssh_key)
    elif psexec_path and _port_open(host, 445):
        _handle_psexec(host, cid, server_url, username, password, psexec_path, obfuscate)
    else:
        print(f'[!] {host}: No usable remoting transport (WinRM/SSH/PsExec) — skipping.')


def _port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _run_ps(session, script: str, obfuscate: str):
    """
    Send a PowerShell script over an active WinRM session.

    - none/light/heavy: pass script content directly to run_ps() — pywinrm
      already base64-encodes it internally via -EncodedCommand, so our
      string-level transformations still apply cleanly.
    - base64: we do our own UTF-16LE encoding and send via run_cmd() so the
      remote host receives a fully self-contained powershell invocation.
    """
    obf = obfuscate_script(script, obfuscate)
    if is_encoded(obf):
        # obf is "powershell.exe -NonInteractive -NoProfile -EncodedCommand <b64>"
        return session.run_cmd(obf)
    else:
        return session.run_ps(obf)



@contextlib.contextmanager
def _ssh_chain(pivot_chain: list):
    """
    Build nested paramiko SSH connections through a chain of SSH pivots.
    Each hop after the first is reached via the previous hop's direct-tcpip channel.
    Yields the innermost connected SSHClient.  All clients are closed on exit.
    """
    if not pivot_chain:
        raise ValueError('_ssh_chain requires a non-empty pivot_chain')
    import paramiko
    clients = []
    sock = None
    try:
        for i, hop in enumerate(pivot_chain):
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            kw = {'username': hop['username'], 'timeout': 10}
            if hop.get('ssh_key'):
                kw['key_filename'] = hop['ssh_key']
            elif hop.get('password'):
                kw['password'] = hop['password']
            if sock is not None:
                kw['sock'] = sock
            client.connect(hop['ip'], **kw)
            clients.append(client)
            if i + 1 < len(pivot_chain):
                next_ip = pivot_chain[i + 1]['ip']
                sock = client.get_transport().open_channel(
                    'direct-tcpip', (next_ip, 22), ('127.0.0.1', 0)
                )
        yield clients[-1]
    finally:
        for c in reversed(clients):
            try:
                c.close()
            except Exception:
                pass


@contextlib.contextmanager
def _ssh_chain_winrm_tunnel(pivot_chain: list, target_host: str, target_port: int):
    """
    Build an SSH chain and then expose target_host:target_port as a local TCP port
    via a threading bridge.  Yields ('127.0.0.1', local_port).
    Used for SSH-chain → WinRM target.
    """
    import socket as _socket

    with _ssh_chain(pivot_chain) as last_client:
        # Bind a random local port for pywinrm to connect to
        srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        srv.bind(('127.0.0.1', 0))
        local_port = srv.getsockname()[1]
        srv.listen(5)
        srv.settimeout(0.5)
        stop = threading.Event()

        def _serve():
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                except _socket.timeout:
                    continue
                except Exception:
                    break
                try:
                    chan = last_client.get_transport().open_channel(
                        'direct-tcpip', (target_host, target_port), ('127.0.0.1', 0)
                    )
                except Exception:
                    conn.close()
                    continue

                def _bridge(src, dst):
                    try:
                        while True:
                            data = src.recv(4096)
                            if not data:
                                break
                            dst.sendall(data)
                    except Exception:
                        pass
                    finally:
                        try:
                            src.close()
                        except Exception:
                            pass

                threading.Thread(target=_bridge, args=(conn, chan), daemon=True).start()
                threading.Thread(target=_bridge, args=(chan, conn), daemon=True).start()

        threading.Thread(target=_serve, daemon=True).start()
        try:
            yield '127.0.0.1', local_port
        finally:
            stop.set()
            srv.close()


@contextlib.contextmanager
def _winrm_portproxy_chain(pivot_chain: list, target_host: str, target_port: int):
    """
    Build cascading netsh portproxy rules through a WinRM pivot chain so the operator
    can reach target_host:target_port by connecting to pivot_chain[0].ip:relay_port.

    Access portproxies are set up first so WinRM sessions can be opened on each hop
    to configure their respective data portproxies.  All rules are cleaned up on exit.

    Yields (pivot_chain[0].ip, operator_relay_port).
    """
    import winrm as _winrm

    cleanup_tasks = []   # (session, relay_port, rule_name) in creation order

    def _add_portproxy(session, dest_host, dest_port):
        relay = random.randint(49152, 65534)
        rule  = f'WormstrikePivot{relay}'
        session.run_cmd(
            f'netsh interface portproxy add v4tov4 '
            f'listenport={relay} listenaddress=0.0.0.0 '
            f'connectport={dest_port} connectaddress={dest_host}'
        )
        session.run_cmd(
            f'netsh advfirewall firewall add rule name="{rule}" '
            f'protocol=TCP dir=in localport={relay} action=allow'
        )
        cleanup_tasks.append((session, relay, rule))
        return relay

    def _open_session(host, port, hop):
        proto = 'https' if port == 5986 else 'http'
        return _winrm.Session(
            f'{proto}://{host}:{port}',
            auth=(hop['username'], hop.get('password')),
            transport=hop.get('winrm_auth', 'ntlm'),
            server_cert_validation='ignore',
        )

    try:
        h0 = pivot_chain[0]
        h0_port = 5986 if _port_open(h0['ip'], 5986) else 5985
        sessions = [_open_session(h0['ip'], h0_port, h0)]

        # Phase A: build access path to each subsequent pivot through H0.
        # For pivot[i], we set portproxy on pivot[i-1] → pivot[i]:5985,
        # then chain back through pivot[i-2]..H0 so H0:relay reaches pivot[i].
        for i in range(1, len(pivot_chain)):
            relay = _add_portproxy(sessions[i - 1], pivot_chain[i]['ip'], 5985)
            current_dest_host = pivot_chain[i - 1]['ip']
            current_dest_port = relay
            for j in range(i - 2, -1, -1):
                relay = _add_portproxy(sessions[j], current_dest_host, current_dest_port)
                current_dest_host = pivot_chain[j]['ip']
                current_dest_port = relay
            # current_dest_port is now a relay on H0 reaching pivot[i]:5985
            sessions.append(_open_session(h0['ip'], current_dest_port, pivot_chain[i]))

        # Phase B: data portproxy chain from innermost pivot → target.
        # Work backwards so each hop forwards to the next's relay port.
        next_host, next_port = target_host, target_port
        data_relays = []
        for i in range(len(pivot_chain) - 1, -1, -1):
            relay = _add_portproxy(sessions[i], next_host, next_port)
            data_relays.insert(0, relay)
            next_host = pivot_chain[i]['ip']
            next_port = relay

        # Operator connects to H0:data_relays[0] → H1:data_relays[1] → ... → target
        yield h0['ip'], data_relays[0]

    finally:
        for session, relay, rule in reversed(cleanup_tasks):
            try:
                session.run_cmd(
                    f'netsh interface portproxy delete v4tov4 '
                    f'listenport={relay} listenaddress=0.0.0.0'
                )
                session.run_cmd(
                    f'netsh advfirewall firewall delete rule name="{rule}"'
                )
            except Exception:
                pass


def _winrm_detect_and_install(
    host: str,
    cid: str,
    server_url: str,
    username: str,
    password: str,
    auth_type: str,
    obfuscate: str,
    connect_url: str,
    via: str,
    winrm,
) -> bool:
    """Create a WinRM session at connect_url and run detect + install. Returns True."""
    obf_label = f', obfuscation={obfuscate}' if obfuscate != 'none' else ''
    print(f'[*] {host}: Connecting via WinRM ({auth_type}{obf_label}{via}) as "{username}"...')
    session = winrm.Session(
        connect_url,
        auth=(username, password),
        transport=auth_type,
        server_cert_validation='ignore',
    )
    detect_ps = (
        _PS_BYPASS +
        'if (Get-Service CSFalconService -ErrorAction SilentlyContinue) '
        '{ "INSTALLED" } else { "NOT_INSTALLED" }'
    )
    result = session.run_ps(detect_ps)
    status = result.std_out.decode().strip()

    if status == 'INSTALLED':
        print(f'[+] {host}: CrowdStrike already installed.')
        return True

    print(f'[-] {host}: Not installed — deploying...')
    base = server_url.rstrip('/')
    install_ps = (
        _PS_BYPASS +
        f'$tmp = "$env:TEMP\\WindowsSensor.exe"; '
        f'[Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}}; '
        f'Invoke-WebRequest -Uri "{base}/windows/WindowsSensor.exe" -OutFile $tmp -UseBasicParsing; '
        f'Start-Process -FilePath $tmp -ArgumentList "/install /quiet /norestart CID={cid}" -Wait; '
        f'Remove-Item $tmp -Force'
    )
    result = _run_ps(session, install_ps, obfuscate)
    if result.status_code == 0:
        print(f'[+] {host}: CrowdStrike installed successfully.')
    else:
        print(f'[!] {host}: Install failed — {result.std_err.decode().strip()}')
    return True


def _handle_winrm(
    host: str,
    cid: str,
    server_url: str,
    username: str,
    password: str,
    auth_type: str = 'ntlm',
    obfuscate: str = 'none',
    pivot: list = None,
):
    """
    auth_type:
      'ntlm'     — works for both local accounts and domain accounts (DOMAIN\\user)
      'kerberos' — domain accounts only; requires krb5 libs on the machine running this tool
      'basic'    — local accounts only; only safe over HTTPS (port 5986)
    Returns True if a connection was successfully established (regardless of install outcome),
    False if WinRM is not available on this host (used by the pivot path to fall through to SSH).
    """
    try:
        import winrm
    except ImportError:
        print(f'[!] {host}: pywinrm not installed — cannot connect via WinRM.')
        return False

    try:
        if pivot:
            last = pivot[-1]
            if not last.get('winrm_https') and not last.get('winrm_http'):
                return False  # target has no WinRM — let caller try SSH
            winrm_port = 5986 if last.get('winrm_https') else 5985
            protocol   = 'https' if last.get('winrm_https') else 'http'
            via        = ' via ' + ' → '.join(h['ip'] for h in pivot)
            transports = [h.get('transport', 'ssh') for h in pivot]
            if all(t == 'winrm' for t in transports):
                ctx = _winrm_portproxy_chain(pivot, host, winrm_port)
            else:
                # SSH chain (possibly mixed ending in SSH pivot that can forward WinRM)
                ctx = _ssh_chain_winrm_tunnel(pivot, host, winrm_port)
            with ctx as (connect_host, connect_port):
                return _winrm_detect_and_install(
                    host, cid, server_url, username, password,
                    auth_type, obfuscate,
                    f'{protocol}://{connect_host}:{connect_port}',
                    via, winrm,
                )
        else:
            use_https = _port_open(host, 5986)
            protocol  = 'https' if use_https else 'http'
            if auth_type == 'basic' and not use_https:
                print(f'[!] {host}: basic auth over plain HTTP is insecure — skipping. Use HTTPS or switch to ntlm.')
                return False
            return _winrm_detect_and_install(
                host, cid, server_url, username, password,
                auth_type, obfuscate, f'{protocol}://{host}', '', winrm,
            )

    except Exception as exc:
        print(f'[!] {host}: WinRM error — {exc}')
        return False


def _handle_psexec(
    host: str,
    cid: str,
    server_url: str,
    username: str,
    password: str,
    psexec_path: str,
    obfuscate: str = 'none',
):
    """
    Uses Sysinternals PsExec to run commands on the remote Windows host over SMB.
    Requires PsExec.exe to be present on the machine running this tool.
    psexec_path: full path to PsExec.exe (e.g. C:\\Tools\\PsExec64.exe)
    """
    import subprocess

    def _psexec(cmd: str) -> subprocess.CompletedProcess:
        """Run a cmd.exe command on the remote host via PsExec."""
        return subprocess.run(
            [
                psexec_path,
                f'\\\\{host}',
                '-u', username,
                '-p', password,
                '-s',           # run as SYSTEM
                '-accepteula',  # suppress the EULA dialog
                '-n', '10',     # connect timeout in seconds
                'cmd', '/c', cmd,
            ],
            capture_output=True,
            text=True,
        )

    obf_label = f', obfuscation={obfuscate}' if obfuscate != 'none' else ''
    try:
        print(f'[*] {host}: Connecting via PsExec as "{username}"{obf_label}...')

        # Detect CrowdStrike (plain — sc.exe is not PS, no obfuscation applies)
        result = _psexec('sc query CSFalconService')
        if result.returncode == 0:
            print(f'[+] {host}: CrowdStrike already installed.')
            return

        print(f'[-] {host}: Not installed — deploying...')
        base = server_url.rstrip('/')

        # Build the raw install script, then obfuscate it
        raw_ps = (
            f'[Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}}; '
            f'Invoke-WebRequest -Uri \'{base}/windows/WindowsSensor.exe\' '
            f'-OutFile $env:TEMP\\sensor.exe -UseBasicParsing; '
            f'Start-Process $env:TEMP\\sensor.exe '
            f'-ArgumentList \'/install /quiet /norestart CID={cid}\' -Wait; '
            f'Remove-Item $env:TEMP\\sensor.exe -Force'
        )

        obf_ps = obfuscate_script(raw_ps, obfuscate)

        if is_encoded(obf_ps):
            # obf_ps is already a full "powershell.exe -EncodedCommand ..." invocation
            cmd = obf_ps
        else:
            # Wrap in a standard powershell -Command call
            cmd = f'powershell -ExecutionPolicy Bypass -Command "{obf_ps}"'

        result = _psexec(cmd)
        if result.returncode == 0:
            print(f'[+] {host}: CrowdStrike installed successfully.')
        else:
            print(f'[!] {host}: Install failed (exit {result.returncode}) — {result.stderr.strip()}')

    except FileNotFoundError:
        print(f'[!] {host}: PsExec not found at "{psexec_path}".')
    except Exception as exc:
        print(f'[!] {host}: PsExec error — {exc}')


def _sftp_upload(client, local_path: str, remote_path: str) -> bool:
    """Upload a file via SFTP over an existing paramiko connection. Returns True on success."""
    try:
        sftp = client.open_sftp()
        try:
            sftp.put(local_path, remote_path)
        finally:
            sftp.close()
        return True
    except Exception as exc:
        print(f'    [!] SFTP upload failed ({exc}) — will try curl download instead')
        return False


def _ssh_detect_and_install(host: str, cid: str, server_url: str, client,
                            ssh_password: str = None) -> bool:
    """
    Run OS detection and CrowdStrike install on an already-connected paramiko client.
    Prefers SFTP to push the installer directly over the SSH channel; falls back to
    curl download from server_url if the local installer file is not present.
    """
    from pathlib import Path
    from server.serve import INSTALLERS_DIR

    _, stdout, _ = client.exec_command('uname -s 2>/dev/null || echo Unknown')
    os_type = stdout.read().decode().strip()  # 'Linux', 'Darwin', or something unexpected

    if os_type not in ('Linux', 'Darwin'):
        print(f'[!] {host}: Unexpected OS type "{os_type}" via SSH — skipping.')
        return False

    if os_type == 'Darwin':
        detect_cmd = (
            'test -f /Library/CS/falconctl '
            '&& echo INSTALLED || echo NOT_INSTALLED'
        )
    else:
        detect_cmd = (
            '(systemctl is-active falcon-sensor >/dev/null 2>&1 '
            '|| test -f /opt/CrowdStrike/falconctl) '
            '&& echo INSTALLED || echo NOT_INSTALLED'
        )

    _, stdout, _ = client.exec_command(detect_cmd)
    status = stdout.read().decode().strip()

    if status == 'INSTALLED':
        print(f'[+] {host}: CrowdStrike already installed.')
        return True

    print(f'[-] {host}: Not installed — deploying...')
    base = server_url.rstrip('/')

    def _download(url, dest):
        """curl fallback — blocks until download completes."""
        _, out, _ = client.exec_command(f'curl -fsSLk "{url}" -o {dest}')
        out.channel.recv_exit_status()

    if os_type == 'Darwin':
        local_file = INSTALLERS_DIR / 'macos' / 'FalconSensorMacOS.pkg'
        remote_tmp = '/tmp/falcon.pkg'
        if local_file.exists() and _sftp_upload(client, str(local_file), remote_tmp):
            print(f'    [*] {host}: Installer uploaded via SFTP.')
        else:
            _download(f'{base}/macos/FalconSensorMacOS.pkg', remote_tmp)
        install_cmd = (
            f'sudo installer -pkg {remote_tmp} -target / && '
            f'sudo /Library/CS/falconctl license --cid {cid} && '
            f'rm -f {remote_tmp}'
        )
    else:
        _, stdout, _ = client.exec_command(
            'ID_LIKE=$(grep -oP "(?<=^ID_LIKE=)[^\\n]+" /etc/os-release 2>/dev/null || true); '
            'ID=$(grep -oP "(?<=^ID=)[^\\n]+" /etc/os-release 2>/dev/null || true); '
            'combined="$ID_LIKE $ID"; '
            'case "$combined" in *debian*|*ubuntu*) echo deb ;; *) echo rpm ;; esac'
        )
        pkg_type = stdout.read().decode().strip()

        if pkg_type == 'rpm':
            local_file = INSTALLERS_DIR / 'linux' / 'falcon-sensor.x86_64.rpm'
            remote_tmp = '/tmp/falcon.rpm'
            if local_file.exists() and _sftp_upload(client, str(local_file), remote_tmp):
                print(f'    [*] {host}: Installer uploaded via SFTP.')
            else:
                _download(f'{base}/linux/falcon-sensor.x86_64.rpm', remote_tmp)
            install_cmd = (
                f'sudo rpm -ivh --force {remote_tmp} && '
                f'sudo /opt/CrowdStrike/falconctl set --cid={cid} && '
                f'sudo systemctl start falcon-sensor && '
                f'rm -f {remote_tmp}'
            )
        else:
            local_file = INSTALLERS_DIR / 'linux' / 'falcon-sensor_amd64.deb'
            remote_tmp = '/tmp/falcon.deb'
            if local_file.exists() and _sftp_upload(client, str(local_file), remote_tmp):
                print(f'    [*] {host}: Installer uploaded via SFTP.')
            else:
                _download(f'{base}/linux/falcon-sensor_amd64.deb', remote_tmp)
            install_cmd = (
                f'sudo dpkg -i {remote_tmp} && '
                f'sudo /opt/CrowdStrike/falconctl set --cid={cid} && '
                f'sudo systemctl start falcon-sensor && '
                f'rm -f {remote_tmp}'
            )

    _, stdout, stderr = client.exec_command(install_cmd)
    exit_code = stdout.channel.recv_exit_status()
    if exit_code == 0:
        print(f'[+] {host}: CrowdStrike installed successfully.')
        return True

    err = stderr.read().decode().strip()
    # Retry with sudo -S (password via stdin) if it looks like a permission error
    # and we have a password to offer.
    if ssh_password and ('sudo:' in err.lower() or 'permission denied' in err.lower()
                         or exit_code == 1):
        import shlex
        sudo_cmd = f'echo {shlex.quote(ssh_password)} | sudo -S -p "" sh -c {shlex.quote(install_cmd)}'
        print(f'    [*] {host}: Retrying with sudo -S...')
        _, stdout2, stderr2 = client.exec_command(sudo_cmd)
        exit_code2 = stdout2.channel.recv_exit_status()
        if exit_code2 == 0:
            print(f'[+] {host}: CrowdStrike installed successfully (via sudo).')
            return True
        err = stderr2.read().decode().strip()
        print(f'[!] {host}: Install failed after sudo retry (exit {exit_code2}) — {err}')
    else:
        print(f'[!] {host}: Install failed (exit {exit_code}) — {err}')
    return True


def _handle_ssh(
    host: str,
    cid: str,
    server_url: str,
    username: str,
    password: str = None,
    ssh_key: str = None,
    pivot: list = None,
):
    try:
        import paramiko
    except ImportError:
        print(f'[!] {host}: paramiko not installed — cannot connect via SSH.')
        return False

    if pivot and not pivot[-1].get('ssh'):
        return False  # target has no SSH — nothing to try

    try:
        via = (' via ' + ' → '.join(h['ip'] for h in pivot)) if pivot else ''
        print(f'[*] {host}: Connecting via SSH{via}...')
        kwargs = {'username': username, 'timeout': 10}
        if ssh_key:
            kwargs['key_filename'] = ssh_key
        elif password:
            kwargs['password'] = password

        if pivot:
            transports = [h.get('transport', 'ssh') for h in pivot]
            if all(t == 'winrm' for t in transports):
                # WinRM-only chain: use cascading portproxies to expose port 22
                with _winrm_portproxy_chain(pivot, host, 22) as (connect_host, connect_port):
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(connect_host, port=connect_port, **kwargs)
                    try:
                        return _ssh_detect_and_install(host, cid, server_url, client, ssh_password=password)
                    finally:
                        client.close()
            else:
                # SSH chain: build nested paramiko connections, open channel to target
                with _ssh_chain(pivot) as last_client:
                    channel = last_client.get_transport().open_channel(
                        'direct-tcpip', (host, 22), ('127.0.0.1', 0)
                    )
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    kwargs['sock'] = channel
                    client.connect(host, **kwargs)
                    try:
                        return _ssh_detect_and_install(host, cid, server_url, client, ssh_password=password)
                    finally:
                        client.close()
        else:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, **kwargs)
            try:
                return _ssh_detect_and_install(host, cid, server_url, client, ssh_password=password)
            finally:
                client.close()

    except Exception as exc:
        print(f'[!] {host}: SSH error — {exc}')
        return False
