#!/usr/bin/env python3
"""
wormstrike — CrowdStrike Falcon deployment tool

Usage examples:

  # Scan a subnet and deploy to all live hosts
  wormstrike --cid ABC123-DEF456 --target 10.0.1.0/24 --username admin --password secret

  # Use a config file (recommended for mixed Windows/Linux environments)
  wormstrike --config wormstrike.toml

  # Config file with CLI overrides
  wormstrike --config wormstrike.toml --target 10.0.2.0/24 --auto

  # Use SSH key for Linux/macOS targets
  wormstrike --cid ABC123-DEF456 --target 192.168.1.0/24 --username ubuntu --ssh-key ~/.ssh/id_rsa

  # Use HTTP (not HTTPS) for the embedded server
  wormstrike --cid ABC123-DEF456 --target 10.0.0.0/24 --username admin --no-tls
"""

import argparse
import concurrent.futures
import ipaddress
import sys
from collections import deque
from itertools import groupby


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='wormstrike',
        description='CrowdStrike Falcon deployment tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    p.add_argument(
        '--config', metavar='PATH',
        help='Path to a TOML config file. CLI arguments override config file values.',
    )
    p.add_argument(
        '--cid',
        help='CrowdStrike Customer ID (CID). Can also be set via config [general] cid.',
    )

    server_group = p.add_mutually_exclusive_group()
    server_group.add_argument(
        '--server',
        help='Base HTTPS URL of an existing installer server '
             '(e.g. https://deploy.internal). '
             'If omitted, an embedded server is started on this machine.',
    )
    server_group.add_argument(
        '--server-port', type=int, default=None, metavar='PORT',
        help='Port for the embedded installer server (default: 8443).',
    )

    p.add_argument(
        '--no-tls', action='store_true',
        help='Use plain HTTP for the embedded server instead of HTTPS.',
    )
    p.add_argument(
        '--target', metavar='CIDR',
        help='CIDR range to scan and deploy to (e.g. 10.0.1.0/24).',
    )
    p.add_argument(
        '--username',
        help='WinRM/PsExec username. For domain accounts: "DOMAIN\\\\user" or use --domain.',
    )
    p.add_argument(
        '--domain',
        help='Windows domain name. Automatically formats --username as DOMAIN\\\\username.',
    )
    p.add_argument(
        '--password',
        help='WinRM/PsExec password.',
    )
    p.add_argument(
        '--winrm-auth', default=None,
        choices=['ntlm', 'kerberos', 'basic'],
        help='WinRM authentication type (default: ntlm).',
    )
    p.add_argument(
        '--ssh-key', metavar='PATH',
        help='Path to SSH private key for Linux/macOS targets.',
    )
    p.add_argument(
        '--obfuscate', default=None,
        choices=['none', 'light', 'heavy', 'base64'],
        help='PowerShell obfuscation level for Windows payloads (default: none).',
    )
    p.add_argument(
        '--psexec', metavar='PATH',
        help='Path to PsExec.exe. Enables PsExec as a fallback transport for Windows hosts '
             'that have SMB (445) open but no WinRM.',
    )
    p.add_argument(
        '--scan-workers', type=int, default=None, metavar='N',
        help='Max parallel ping workers for the network scan (default: 100).',
    )
    p.add_argument(
        '--deploy-workers', type=int, default=None, metavar='N',
        help='Max parallel deployment workers within each hop level (default: 10).',
    )
    p.add_argument(
        '--auto', action='store_true',
        help='Skip per-host confirmation prompts and deploy to all reachable hosts automatically.',
    )

    return p


def _load_config(path: str) -> dict:
    try:
        import tomllib
    except ImportError:
        print(f'[!] tomllib not available (requires Python 3.11+). Cannot load config file.')
        sys.exit(1)
    try:
        with open(path, 'rb') as f:
            return tomllib.load(f)
    except FileNotFoundError:
        print(f'[!] Config file not found: {path}')
        sys.exit(1)
    except Exception as e:
        print(f'[!] Failed to parse config file: {e}')
        sys.exit(1)


def _merge_config(args, cfg: dict):
    """
    Merge config file values into args. CLI arguments always win.
    Populates args.ssh_username and args.ssh_password from [ssh] section.
    """
    gen    = cfg.get('general', {})
    winrm  = cfg.get('winrm', {})
    ssh    = cfg.get('ssh', {})
    psexec = cfg.get('psexec', {})
    server = cfg.get('server', {})
    scan   = cfg.get('scan', {})

    def _first(*values):
        for v in values:
            if v is not None:
                return v
        return None

    args.cid          = _first(args.cid,          gen.get('cid'))
    args.target       = _first(args.target,        gen.get('target'))
    args.auto         = args.auto or             gen.get('auto', False)
    args.obfuscate    = _first(args.obfuscate,     gen.get('obfuscate'),   'none')

    args.username     = _first(args.username,      winrm.get('username'))
    args.password     = _first(args.password,      winrm.get('password'))
    args.domain       = _first(args.domain,        winrm.get('domain'))
    args.winrm_auth   = _first(args.winrm_auth,    winrm.get('auth'),      'ntlm')

    # SSH-specific creds — fall back to WinRM creds if not set
    args.ssh_username = _first(ssh.get('username'), args.username)
    args.ssh_password = _first(ssh.get('password'), args.password)
    args.ssh_key      = _first(args.ssh_key,        ssh.get('key'))

    args.psexec       = _first(args.psexec,        psexec.get('path'))

    args.server       = _first(args.server,        server.get('url'))
    args.server_port  = _first(args.server_port,   server.get('port'),     8443)
    args.no_tls       = args.no_tls or (not server.get('tls', True))

    args.scan_workers    = _first(args.scan_workers,    scan.get('workers'),         100)
    args.deploy_workers  = _first(args.deploy_workers,  scan.get('deploy_workers'),   10)


def main():
    from banner import print_banner
    print_banner()

    parser = build_parser()
    args = parser.parse_args()

    # Load and merge config file if provided
    if args.config:
        cfg = _load_config(args.config)
        _merge_config(args, cfg)
    else:
        # Apply hardcoded defaults for fields with None default
        args.ssh_username = args.username
        args.ssh_password = args.password
        args.winrm_auth   = args.winrm_auth or 'ntlm'
        args.obfuscate    = args.obfuscate   or 'none'
        args.server_port  = args.server_port or 8443
        args.scan_workers   = args.scan_workers   or 100
        args.deploy_workers = args.deploy_workers or 10

    # Validate required fields
    if not args.cid:
        parser.error('--cid is required (or set [general] cid in config file)')
    if args.target and not (args.username or args.ssh_username):
        parser.error('--target requires --username (or set [winrm]/[ssh] username in config file)')

    # ── Privilege escalation ──────────────────────────────────────────────
    from privileges.escalate import ensure_privileges
    ensure_privileges()

    # ── Resolve installer server URL ──────────────────────────────────────
    if args.server:
        server_url = args.server.rstrip('/')
        print(f'[*] Using external installer server: {server_url}')
    else:
        from server.serve import start_embedded_server
        server_url = start_embedded_server(
            port=args.server_port,
            use_https=not args.no_tls,
        )

    # ── Network scan + remote deployment ─────────────────────────────────
    if args.target:
        from network.scan import scan_cidr, _probe_host, probe_via_pivot, probe_via_winrm_pivot
        from network.discover import discover_from_host
        from crowdstrike.remote import check_and_install_remote

        print(f'\n[*] Scanning {args.target}...')
        discovered = scan_cidr(args.target, max_workers=args.scan_workers)

        if not discovered:
            print('[-] No live hosts found.')
            return

        reachable = [h for h in discovered if h.reachable]
        unreachable = [h for h in discovered if not h.reachable]

        print(f'\n[+] {len(discovered)} host(s) up — '
              f'{len(reachable)} reachable via remoting, '
              f'{len(unreachable)} skipped (no WinRM/SSH).\n')

        if not reachable:
            print('[-] No hosts with WinRM or SSH open.')
            return

        # ── Phase 1: Discovery — map all reachable hosts before deploying ──
        # BFS outward from the operator, tracking hop depth.
        # No CS is deployed during this phase so pivot hosts remain clean
        # and available for lateral movement throughout the entire mapping pass.
        seen_ips = {h.ip for h in discovered}
        discovery_queue = deque((1, h) for h in reachable)
        all_hosts = []   # list of (depth, host_info) — populated during discovery

        ssh_pivot_creds = {
            'username':   args.ssh_username,
            'password':   args.ssh_password,
            'ssh_key':    args.ssh_key,
            'winrm_auth': args.winrm_auth,
        }
        winrm_pivot_creds = {
            'username':   args.username,
            'password':   args.password,
            'ssh_key':    args.ssh_key,
            'winrm_auth': args.winrm_auth,
        }

        # Subnets seen in the initial scan are pre-approved; anything else
        # requires explicit operator confirmation before we probe or deploy.
        def _subnet24(ip: str) -> str:
            return str(ipaddress.ip_network(f'{ip}/24', strict=False))

        approved_subnets = {_subnet24(h.ip) for h in discovered}
        declined_subnets: set = set()

        print('[*] Discovery phase — mapping reachable hosts before deployment...\n')

        while discovery_queue:
            depth, host_info = discovery_queue.popleft()
            all_hosts.append((depth, host_info))

            print(f'[*] Neighbor discovery from {host_info.ip} (hop {depth})...')
            new_ips = discover_from_host(
                host=host_info.ip,
                username=args.username,
                password=args.password,
                ssh_key=args.ssh_key,
                domain=args.domain,
                winrm_auth=args.winrm_auth,
                psexec_path=args.psexec,
                ssh_username=args.ssh_username,
                ssh_password=args.ssh_password,
                pivot_chain=host_info.pivot,  # None for directly-reachable hosts
            )
            new_ips = [ip for ip in new_ips if ip not in seen_ips]

            # ── Subnet gate ───────────────────────────────────────────────
            # Prompt before expanding into any /24 not covered by the initial
            # scan target.  --auto does NOT bypass this — lateral movement into
            # an unplanned subnet should always be a conscious decision.
            new_subnets = sorted({
                _subnet24(ip) for ip in new_ips
                if _subnet24(ip) not in approved_subnets and _subnet24(ip) not in declined_subnets
            })
            for subnet in new_subnets:
                ips_here = [ip for ip in new_ips if _subnet24(ip) == subnet]
                preview = ', '.join(ips_here[:4]) + ('...' if len(ips_here) > 4 else '')
                print(
                    f'\n[!] New subnet discovered: {subnet}  '
                    f'({len(ips_here)} host(s): {preview})\n'
                    f'    Expand into this subnet? [y/n]: ',
                    end='', flush=True,
                )
                try:
                    choice = input().strip().lower()
                except (EOFError, KeyboardInterrupt):
                    choice = 'n'
                if choice in ('y', 'yes'):
                    approved_subnets.add(subnet)
                    print(f'    [+] {subnet} approved.')
                else:
                    declined_subnets.add(subnet)
                    print(f'    [-] {subnet} skipped.')

            # Mark declined IPs as seen so they aren't re-surfaced from another
            # ARP table, then strip them from this round's probe list.
            for ip in new_ips:
                if _subnet24(ip) in declined_subnets:
                    seen_ips.add(ip)
            new_ips = [ip for ip in new_ips if _subnet24(ip) not in declined_subnets]

            if new_ips:
                print(f'    [+] {len(new_ips)} new neighbor(s) found — probing...')
                # Add all to seen_ips before submitting parallel probes so no
                # IP is probed twice if it shows up in multiple ARP tables.
                for ip in new_ips:
                    seen_ips.add(ip)

                # Default args capture the current loop values so each parallel
                # call sees the correct host_info regardless of GIL scheduling.
                def _probe_one(ip, _hi=host_info, _spc=ssh_pivot_creds, _wpc=winrm_pivot_creds):
                    info = _probe_host(ip) if not _hi.pivot else None
                    if info is not None and not info.reachable:
                        info = None
                    if info is None:
                        if _hi.ssh:
                            info = probe_via_pivot(
                                _hi.ip, _spc, ip,
                                via_chain=_hi.pivot or None,
                            )
                        elif _hi.has_winrm and not _hi.pivot:
                            info = probe_via_winrm_pivot(_hi.ip, _wpc, ip)
                        if info is not None:
                            info.pivot = (_hi.pivot or []) + info.pivot
                    return ip, info

                n = min(args.scan_workers, len(new_ips))
                with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
                    for ip, info in pool.map(_probe_one, new_ips):
                        if info is not None:
                            if info.pivot:
                                chain_str = ' → '.join(h['ip'] for h in info.pivot)
                                print(f'    [+] {ip} [{info.transport_label}] (chain: {chain_str})')
                            else:
                                print(f'    [+] {ip} [{info.transport_label}]')
                            discovery_queue.append((depth + 1, info))
                        else:
                            print(f'    [-] {ip} — not reachable via any path from {host_info.ip}')
            else:
                print(f'    (no new neighbors)')

        # ── Phase 2: Deploy furthest hosts first ──────────────────────────
        # Hosts at the same depth are independent — deploy them in parallel.
        # A deeper depth group must fully complete before the next shallower
        # group starts so CS on a pivot can't block hosts behind it.
        all_hosts.sort(key=lambda x: x[0], reverse=True)
        max_depth = all_hosts[0][0] if all_hosts else 0

        print(f'\n[*] Deployment phase — {len(all_hosts)} host(s) found across '
              f'{max_depth} hop(s).  Deploying furthest first.\n')

        deploy_all = args.auto
        aborted = False

        def _deploy(depth, host_info):
            via = (' via ' + ' → '.join(h['ip'] for h in host_info.pivot)) if host_info.pivot else ''
            print(f'\n[*] Deploying to {host_info.ip} [{host_info.transport_label}]{via} (hop {depth})...')
            check_and_install_remote(
                host=host_info.ip,
                cid=args.cid,
                server_url=server_url,
                username=args.username,
                password=args.password,
                ssh_key=args.ssh_key,
                domain=args.domain,
                winrm_auth=args.winrm_auth,
                psexec_path=args.psexec,
                obfuscate=args.obfuscate,
                pivot=host_info.pivot,
                ssh_username=args.ssh_username,
                ssh_password=args.ssh_password,
            )
            print()

        for depth_level, group in groupby(all_hosts, key=lambda x: x[0]):
            if aborted:
                break
            depth_hosts = list(group)
            approved = []   # hosts confirmed for deployment at this depth

            for depth, host_info in depth_hosts:
                if not deploy_all:
                    via_label = (' via ' + ' → '.join(h['ip'] for h in host_info.pivot)) if host_info.pivot else ''
                    print(
                        f'  Host: {host_info.ip}  [{host_info.transport_label}]{via_label}  (hop {depth})\n'
                        f'  Deploy CrowdStrike here? '
                        f'[y] yes  [n] skip  [a] yes to all  [q] quit: ',
                        end='', flush=True,
                    )
                    try:
                        choice = input().strip().lower()
                    except (EOFError, KeyboardInterrupt):
                        print('\n[*] Aborted.')
                        aborted = True
                        break
                    if choice == 'q':
                        print('[*] Quitting.')
                        aborted = True
                        break
                    elif choice == 'a':
                        deploy_all = True
                    elif choice != 'y':
                        print(f'    [-] Skipping {host_info.ip}.')
                        continue
                approved.append((depth, host_info))

            if aborted or not approved:
                continue

            n_workers = min(args.deploy_workers, len(approved))
            if n_workers > 1:
                print(f'[*] Deploying {len(approved)} host(s) at hop {depth_level} '
                      f'({n_workers} concurrent workers)...')
                with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as pool:
                    futures = [pool.submit(_deploy, d, h) for d, h in approved]
                    for f in concurrent.futures.as_completed(futures):
                        try:
                            f.result()
                        except Exception as exc:
                            print(f'[!] Deploy worker error: {exc}')
            else:
                for d, h in approved:
                    _deploy(d, h)

    print('[*] Done.')


if __name__ == '__main__':
    main()
