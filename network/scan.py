import ipaddress
import platform
import socket
import subprocess
import concurrent.futures
from dataclasses import dataclass, field
from typing import Dict, List, Optional


REMOTING_PORTS = {
    'winrm_http':  5985,
    'winrm_https': 5986,
    'ssh':         22,
    'smb':         445,   # PsExec uses SMB
    'rdp':         3389,  # detected but not usable for automation
}


@dataclass
class HostInfo:
    ip: str
    winrm_http: bool = False
    winrm_https: bool = False
    ssh: bool = False
    smb: bool = False
    rdp: bool = False
    # Set when this host is only reachable via another host, not directly.
    # Each dict has keys: ip, username, password, ssh_key, winrm_auth, transport.
    # Ordered nearest → furthest (operator → ... → this host's parent pivot).
    pivot: Optional[List[Dict]] = field(default=None, repr=False)

    @property
    def has_winrm(self) -> bool:
        return self.winrm_http or self.winrm_https

    @property
    def has_ssh(self) -> bool:
        return self.ssh

    @property
    def has_psexec(self) -> bool:
        """PsExec requires SMB (445)."""
        return self.smb

    @property
    def reachable(self) -> bool:
        return self.has_winrm or self.has_ssh or self.has_psexec

    @property
    def transport_label(self) -> str:
        parts = []
        if self.winrm_https:
            parts.append('WinRM HTTPS')
        elif self.winrm_http:
            parts.append('WinRM HTTP')
        if self.ssh:
            parts.append('SSH')
        if self.smb and not self.has_winrm:
            parts.append('SMB/PsExec')
        if self.rdp and not parts:
            parts.append('RDP only — cannot automate')
        return ', '.join(parts) if parts else 'no remoting'


def _ping(host: str) -> bool:
    system = platform.system()
    cmd = (
        ['ping', '-n', '1', '-w', '1000', host]
        if system == 'Windows'
        else ['ping', '-c', '1', '-W', '1', host]
    )
    return subprocess.run(cmd, capture_output=True).returncode == 0


def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _probe_host(host: str) -> Optional[HostInfo]:
    """Ping then check remoting ports. Returns None if host is down."""
    if not _ping(host):
        return None

    info = HostInfo(ip=host)
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(REMOTING_PORTS)) as pool:
        results = {
            name: pool.submit(_port_open, host, port)
            for name, port in REMOTING_PORTS.items()
        }
        for name, future in results.items():
            try:
                setattr(info, name, future.result())
            except Exception:
                pass

    return info


def probe_via_pivot(
    pivot_ip: str,
    pivot_creds: dict,
    target_ip: str,
    via_chain: list = None,
) -> Optional[HostInfo]:
    """
    Check remoting ports on *target_ip* by running nc/Test-NetConnection on
    *pivot_ip* over SSH.  Returns a HostInfo (with pivot set) if any remoting
    port is open, otherwise None.

    pivot_creds keys: username, password (opt), ssh_key (opt)

    via_chain: if set, pivot_ip is not directly reachable — connect to it
    through this SSH chain first (list of pivot dicts, nearest → furthest).
    """
    try:
        import paramiko
    except ImportError:
        return None

    def _run_checks(client) -> Optional[HostInfo]:
        def _check(port: int) -> bool:
            cmd = (
                f'(bash -c "echo >/dev/tcp/{target_ip}/{port}" 2>/dev/null '
                f'|| nc -zw2 {target_ip} {port} 2>/dev/null) '
                f'&& echo OPEN || echo CLOSED'
            )
            _, stdout, _ = client.exec_command(cmd)
            return stdout.read().decode().strip() == 'OPEN'

        info = HostInfo(ip=target_ip)
        info.winrm_http  = _check(5985)
        info.winrm_https = _check(5986)
        info.ssh         = _check(22)
        info.smb         = _check(445)

        if not info.reachable:
            return None

        info.pivot = [{
            'ip':         pivot_ip,
            'username':   pivot_creds['username'],
            'password':   pivot_creds.get('password'),
            'ssh_key':    pivot_creds.get('ssh_key'),
            'winrm_auth': pivot_creds.get('winrm_auth', 'ntlm'),
            'transport':  'ssh',
            # Port flags from the probe — used by remote handlers to pick the right tunnel
            'winrm_https': info.winrm_https,
            'winrm_http':  info.winrm_http,
            'ssh':         info.ssh,
        }]
        return info

    try:
        kw = {'username': pivot_creds['username'], 'timeout': 10}
        if pivot_creds.get('ssh_key'):
            kw['key_filename'] = pivot_creds['ssh_key']
        elif pivot_creds.get('password'):
            kw['password'] = pivot_creds['password']

        if via_chain:
            # pivot_ip is behind an SSH chain — build the chain first, then
            # open a direct-tcpip channel to pivot_ip:22 through the last hop.
            from crowdstrike.remote import _ssh_chain
            with _ssh_chain(via_chain) as chain_client:
                channel = chain_client.get_transport().open_channel(
                    'direct-tcpip', (pivot_ip, 22), ('127.0.0.1', 0)
                )
                kw['sock'] = channel
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(pivot_ip, **kw)
                try:
                    return _run_checks(client)
                finally:
                    client.close()
        else:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(pivot_ip, **kw)
            try:
                return _run_checks(client)
            finally:
                client.close()

    except Exception:
        return None


def probe_via_winrm_pivot(pivot_ip: str, pivot_creds: dict, target_ip: str) -> Optional[HostInfo]:
    """
    Check remoting ports on *target_ip* by running Test-NetConnection on
    *pivot_ip* over WinRM.  Returns a HostInfo (with pivot set) if any remoting
    port is open, otherwise None.

    pivot_creds keys: username, password, winrm_auth (opt)
    """
    try:
        import winrm
    except ImportError:
        return None

    use_https = _port_open(pivot_ip, 5986)
    protocol = 'https' if use_https else 'http'

    try:
        session = winrm.Session(
            f'{protocol}://{pivot_ip}',
            auth=(pivot_creds['username'], pivot_creds.get('password')),
            transport=pivot_creds.get('winrm_auth', 'ntlm'),
            server_cert_validation='ignore',
        )

        def _check(port: int) -> bool:
            ps = (
                f'(Test-NetConnection -ComputerName {target_ip} -Port {port} '
                f'-InformationLevel Quiet -WarningAction SilentlyContinue).TcpTestSucceeded'
            )
            result = session.run_ps(ps)
            return result.std_out.decode().strip().lower() == 'true'

        info = HostInfo(ip=target_ip)
        info.winrm_http  = _check(5985)
        info.winrm_https = _check(5986)
        info.ssh         = _check(22)
        info.smb         = _check(445)

        if not info.reachable:
            return None

        info.pivot = [{
            'ip':         pivot_ip,
            'username':   pivot_creds['username'],
            'password':   pivot_creds.get('password'),
            'ssh_key':    None,
            'winrm_auth': pivot_creds.get('winrm_auth', 'ntlm'),
            'transport':  'winrm',
            # Port flags
            'winrm_https': info.winrm_https,
            'winrm_http':  info.winrm_http,
            'ssh':         info.ssh,
        }]
        return info

    except Exception:
        return None


def scan_cidr(cidr: str, max_workers: int = 100) -> List[HostInfo]:
    network = ipaddress.ip_network(cidr, strict=False)
    # network.hosts() excludes network/broadcast — returns empty for /32.
    # Fall back to the network address itself so single-host targets work.
    hosts = [str(h) for h in network.hosts()] or [str(network.network_address)]

    if not hosts:
        return []

    print(f'[*] Scanning {len(hosts)} host(s) in {cidr} (ping + remoting ports)...\n')

    found: List[HostInfo] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_probe_host, h): h for h in hosts}
        for future in concurrent.futures.as_completed(futures):
            try:
                info = future.result()
                if info is not None:
                    tag = f'[{info.transport_label}]' if info.reachable else '[up, no remoting]'
                    print(f'    [+] {info.ip}  {tag}')
                    found.append(info)
            except Exception:
                pass

    return sorted(found, key=lambda h: ipaddress.ip_address(h.ip))
