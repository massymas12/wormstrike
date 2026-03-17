# wormstrike

CrowdStrike Falcon mass-deployment tool. Scans a network, connects to each live host via WinRM, SSH, or PsExec, checks whether the Falcon sensor is already installed, and installs it if not. Supports multi-hop pivoting to any depth for hosts only reachable through intermediaries.

## Requirements

- Python 3.10+
- [uv](https://docs.astral.sh/uv/getting-started/installation/) (recommended) or pip
- CrowdStrike installer binaries (see Installers)
- Elevated privileges on the machine running the tool (auto-escalated on Windows)

## Setup

### Recommended — uv (installs `wormstrike` as a global command)

```powershell
# Install uv if you don't have it
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"

# Clone and install
git clone https://github.com/massymas12/wormstrike.git
cd wormstrike
uv tool install --editable .
```

After this, `wormstrike` is available from any directory without activating a venv.

### Alternative — pip

```powershell
git clone https://github.com/massymas12/wormstrike.git
cd wormstrike
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

## Installers

Place installer binaries in the `installers\` directory before running. The embedded HTTPS server serves these to remote hosts during deployment. For SSH targets, installers are pushed directly over the established SSH channel via SFTP (no outbound HTTP required from the target).

```
installers\
  windows\WindowsSensor.exe
  linux\falcon-sensor.x86_64.rpm
  linux\falcon-sensor_amd64.deb
  macos\FalconSensorMacOS.pkg
```

Only include the files needed for the OS types in your environment. Missing files will cause install failures on those platforms but won't affect other hosts.

## Usage

```
wormstrike [--config wormstrike.toml] [options]
```

CLI arguments always override config file values. `--cid` is required either on the CLI or via `[general] cid` in the config file.

### Config file (recommended)

Copy `wormstrike.toml.example` to `wormstrike.toml` and fill in your values. The config file lets you set separate credentials for Windows (WinRM/PsExec) and Linux/macOS (SSH) targets:

```toml
[general]
cid    = "ABC123-DEF456"
target = "10.0.1.0/24"
auto   = false

[winrm]
username = "CORP\\administrator"
password = "windows-password"
domain   = "CORP"
auth     = "ntlm"

[ssh]
username = "root"
password = "linux-password"
# key = "C:\\Users\\you\\.ssh\\id_rsa"

[psexec]
# path = "C:\\Tools\\PsExec64.exe"

[server]
port = 8443
tls  = true

[scan]
workers = 100
```

If no `[ssh]` section is present, SSH targets use the same credentials as `[winrm]`.

### CLI arguments

| Argument | Description |
|---|---|
| `--config PATH` | Path to TOML config file |
| `--cid` | CrowdStrike Customer ID |
| `--target CIDR` | Subnet to scan and deploy to, e.g. `10.0.1.0/24` |
| `--username` | WinRM/PsExec username |
| `--password` | WinRM/PsExec password |
| `--domain` | Windows domain — auto-formats username as `DOMAIN\user` |
| `--ssh-key PATH` | Path to SSH private key (Linux/macOS targets) |
| `--winrm-auth` | WinRM auth type: `ntlm` (default), `kerberos`, `basic` |
| `--psexec PATH` | Path to PsExec64.exe — enables SMB fallback transport |
| `--obfuscate` | PowerShell obfuscation: `none` (default), `light`, `heavy`, `base64` |
| `--auto` | Skip per-host confirmation prompts |
| `--server URL` | Use an existing installer server instead of the embedded one |
| `--server-port PORT` | Port for the embedded server (default: 8443) |
| `--no-tls` | Use plain HTTP for the embedded server instead of HTTPS |
| `--scan-workers N` | Max parallel ping workers for the scan (default: 100) |

### Examples

**Config file (mixed Windows/Linux environment):**
```powershell
wormstrike --config wormstrike.toml
```

**Config file with CLI override:**
```powershell
wormstrike --config wormstrike.toml --target 10.0.2.0/24 --auto
```

**CLI only — domain Windows targets:**
```powershell
wormstrike --cid ABC123 --target 10.0.1.0/24 --username admin --domain CORP --password secret
```

**CLI only — SSH key auth for Linux/macOS:**
```powershell
wormstrike --cid ABC123 --target 10.0.1.0/24 --username ubuntu --ssh-key C:\Users\you\.ssh\id_rsa
```

**Use an existing HTTPS server (no embedded server):**
```powershell
wormstrike --config wormstrike.toml --server https://deploy.internal
```

**PsExec fallback for hosts with SMB but no WinRM:**
```powershell
wormstrike --config wormstrike.toml --psexec C:\Tools\PsExec64.exe
```

**PowerShell obfuscation:**
```powershell
wormstrike --config wormstrike.toml --obfuscate heavy
```

## Transports

The tool probes each host and selects a transport automatically, in priority order:

1. **WinRM HTTPS** (port 5986) — preferred for Windows
2. **WinRM HTTP** (port 5985)
3. **SSH** (port 22) — Linux and macOS
4. **PsExec / SMB** (port 445) — Windows fallback, requires `--psexec`

## Two-phase operation

The tool separates discovery from deployment to avoid a race condition where installing Falcon on a pivot host could block lateral movement through it before downstream hosts are covered.

**Phase 1 — Discovery only:** Starting from the initial scan target, the tool performs a BFS expansion. After each host is probed, it runs an ARP/neighbor-cache lookup to find additional hosts on that network segment. Newly discovered hosts are added to the queue and explored in turn. No Falcon sensors are installed during this phase.

**Phase 2 — Deploy furthest-first:** All discovered hosts are sorted by network depth (number of hops from the operator), deepest first. Falcon is deployed to the most remote hosts first, working back toward the operator. By the time a pivot host receives Falcon, all hosts reachable through it are already protected.

## Pivoting

After probing a host, the tool runs an ARP/neighbor-cache lookup to discover additional hosts on that network segment. If a discovered host is not directly reachable, the tool routes through already-probed hosts in a chain of arbitrary depth.

### Pivot mechanisms

| Chain type | Target transport | Mechanism |
|---|---|---|
| SSH (any depth) | SSH | Nested paramiko `direct-tcpip` channels |
| SSH (any depth) | WinRM | SSH chain + threading local port bridge |
| WinRM (any depth) | WinRM | Cascading `netsh portproxy` rules across all hops |
| WinRM (any depth) | SSH | Cascading `netsh portproxy` on pivot (port 22) |

SSH chains use nested `direct-tcpip` channels — each hop opens a channel through the previous client's transport, requiring no additional listening ports. WinRM chains use `netsh portproxy` rules written to each pivot in sequence, with full cleanup after each connection.

### Installer delivery through pivots

For SSH targets reached via a pivot chain, the installer binary is pushed directly over the established SSH channel using SFTP. The target host does not need to reach the operator's installer server. A curl-based HTTP download is used as a fallback if SFTP transfer fails.

WinRM targets always download the installer from the embedded HTTPS server. The portproxy or port-bridge setup provides the necessary network path.

### Discovery through pivots

Neighbor discovery (ARP/`ip neigh`) is also chain-aware. When discovering neighbors of a pivoted host, the ARP command is run through the same SSH channel chain used for deployment. WinRM-only chains do not support chain-aware discovery (the WinRM session cannot forward a subsequent SSH connection without an additional portproxy, which is not set up during the discovery phase).

## Privilege escalation

The tool requires elevated privileges. If not already elevated, it attempts escalation in this order:

1. **Token duplication** — duplicates the token of a running SYSTEM process (no UAC prompt)
2. **Scheduled task as SYSTEM** — creates a one-shot `schtasks` entry (no UAC if user is local admin); output goes to `wormstrike.log`
3. **UAC ShellExecute** — interactive only; skipped in headless/non-TTY mode

On Linux/macOS the process re-execs under `sudo`.

## Running tests

```powershell
python tests.py
# or, if using pip install:
# .venv\Scripts\activate first
```

Tests cover IP parsing, `HostInfo` properties, and all obfuscation logic. No live hosts required.
