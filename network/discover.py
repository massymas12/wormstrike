"""
Post-install lateral discovery: run ARP / neighbor-table lookups on a
freshly-contacted host to surface additional targets on its local network
that the operator's machine may not be able to see directly.
"""

import re
import ipaddress
from typing import List

from crowdstrike.remote import _port_open

_IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')


def _is_usable(ip: str) -> bool:
    """True for private, non-loopback, non-link-local IPv4 addresses."""
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private and not a.is_loopback and not a.is_link_local
    except ValueError:
        return False


def _parse_ips(text: str) -> List[str]:
    """Extract unique usable IPv4 addresses from command output."""
    seen: set = set()
    result: List[str] = []
    for m in _IP_RE.finditer(text):
        ip = m.group(1)
        if ip not in seen and _is_usable(ip):
            seen.add(ip)
            result.append(ip)
    return result


def discover_from_host(
    host: str,
    username: str,
    password: str = None,
    ssh_key: str = None,
    domain: str = None,
    winrm_auth: str = 'ntlm',
    psexec_path: str = None,
    ssh_username: str = None,
    ssh_password: str = None,
    pivot_chain: list = None,
) -> List[str]:
    """
    Connect to *host* using whatever transport is available and run an
    ARP / neighbor-cache lookup.  Returns a list of private IPv4 addresses
    found in the output (excluding *host* itself).

    ssh_username / ssh_password: separate credentials for SSH targets.
    Fall back to username / password if not set.

    pivot_chain: if set, host is not directly reachable — connect via this
    chain (list of pivot dicts as used by crowdstrike.remote).  Only SSH
    chains are supported for discovery; WinRM-only chains are skipped.
    """
    # Resolve SSH creds before domain formatting so we never pass DOMAIN\user to SSH.
    ssh_user = ssh_username or username
    ssh_pass = ssh_password or password

    if domain and username and '\\' not in username and '@' not in username:
        username = f'{domain}\\{username}'

    ips: List[str] = []

    if pivot_chain:
        # Host not directly reachable — use the SSH chain if available.
        transports = [h.get('transport', 'ssh') for h in pivot_chain]
        if any(t == 'ssh' for t in transports):
            ips = _discover_ssh_via_chain(host, ssh_user, ssh_pass, ssh_key, pivot_chain)
        # WinRM-only chains: discovery not supported (would require another portproxy
        # session just for ARP — not worth the complexity).
    else:
        if _port_open(host, 5985) or _port_open(host, 5986):
            ips = _discover_winrm(host, username, password, winrm_auth)
        elif _port_open(host, 22):
            ips = _discover_ssh(host, ssh_user, ssh_pass, ssh_key)
        elif psexec_path and _port_open(host, 445):
            ips = _discover_psexec(host, username, password, psexec_path)

    return [ip for ip in ips if ip != host]


# ── Transport implementations ─────────────────────────────────────────────

def _discover_winrm(host: str, username: str, password: str, auth_type: str) -> List[str]:
    try:
        import winrm
    except ImportError:
        return []

    protocol = 'https' if _port_open(host, 5986) else 'http'

    try:
        session = winrm.Session(
            f'{protocol}://{host}',
            auth=(username, password),
            transport=auth_type,
            server_cert_validation='ignore',
        )
        # Prefer Get-NetNeighbor (Win8+/Server 2012+), fall back to arp -a
        ps = (
            'try { '
            '  Get-NetNeighbor -State Reachable -ErrorAction Stop | '
            '  Select-Object -ExpandProperty IPAddress '
            '} catch { arp -a }'
        )
        result = session.run_ps(ps)
        return _parse_ips(result.std_out.decode(errors='replace'))
    except Exception:
        return []


def _discover_ssh_via_chain(
    host: str, username: str, password: str, ssh_key: str, pivot_chain: list
) -> List[str]:
    """Run ARP discovery on host by tunnelling through an SSH pivot chain."""
    try:
        import paramiko
        from crowdstrike.remote import _ssh_chain
    except ImportError:
        return []

    try:
        with _ssh_chain(pivot_chain) as last_client:
            channel = last_client.get_transport().open_channel(
                'direct-tcpip', (host, 22), ('127.0.0.1', 0)
            )
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            kw = {'username': username, 'timeout': 10, 'sock': channel}
            if ssh_key:
                kw['key_filename'] = ssh_key
            elif password:
                kw['password'] = password
            client.connect(host, **kw)
            try:
                _, stdout, _ = client.exec_command(
                    'ip neigh show 2>/dev/null || arp -a 2>/dev/null'
                )
                return _parse_ips(stdout.read().decode(errors='replace'))
            finally:
                client.close()
    except Exception:
        return []


def _discover_ssh(host: str, username: str, password: str, ssh_key: str) -> List[str]:
    try:
        import paramiko
    except ImportError:
        return []

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        kwargs = {'username': username, 'timeout': 10}
        if ssh_key:
            kwargs['key_filename'] = ssh_key
        elif password:
            kwargs['password'] = password
        client.connect(host, **kwargs)
        # ip neigh on Linux, arp -a on macOS (both understood by arp -a as fallback)
        _, stdout, _ = client.exec_command(
            'ip neigh show 2>/dev/null || arp -a 2>/dev/null'
        )
        return _parse_ips(stdout.read().decode(errors='replace'))
    except Exception:
        return []
    finally:
        client.close()


def _discover_psexec(host: str, username: str, password: str, psexec_path: str) -> List[str]:
    import subprocess
    try:
        result = subprocess.run(
            [
                psexec_path,
                f'\\\\{host}',
                '-u', username,
                '-p', password,
                '-s', '-accepteula', '-n', '10',
                'cmd', '/c', 'arp -a',
            ],
            capture_output=True,
            text=True,
        )
        return _parse_ips(result.stdout)
    except Exception:
        return []
