import hashlib
import os
import platform
import re
import subprocess
import tempfile

import requests

INSTALLER_PATHS = {
    'Windows':   'windows/WindowsSensor.exe',
    'Linux_rpm': 'linux/falcon-sensor.x86_64.rpm',
    'Linux_deb': 'linux/falcon-sensor_amd64.deb',
    'Darwin':    'macos/FalconSensorMacOS.pkg',
}

_CID_RE = re.compile(r'^[0-9A-Fa-f]{32}-[0-9A-Fa-f]{2}$')

_SUBPROCESS_TIMEOUT = 300  # 5 minutes for installer runs


def _validate_cid(cid: str):
    if not _CID_RE.match(cid):
        raise ValueError(
            f'Invalid CID format: {cid!r}. Expected 32 hex chars + 2-char checksum (e.g. ABCDEF...01).'
        )


def download_and_install(server_url: str, cid: str, hashes=None):
    """
    hashes: optional InstallerHashes (from config.load()), or any object with
            .windows / .linux_rpm / .linux_deb / .macos string attributes.
            Pass None to skip hash verification.
    """
    _validate_cid(cid)
    system = platform.system()
    base = server_url.rstrip('/')
    h = hashes  # shorthand

    if system == 'Windows':
        url = f"{base}/{INSTALLER_PATHS['Windows']}"
        _install_windows(url, cid, expected_sha256=h.windows if h else '')
    elif system == 'Linux':
        pkg_type = _linux_package_type()
        url = f"{base}/{INSTALLER_PATHS[f'Linux_{pkg_type}']}"
        pkg_hash = (h.linux_rpm if pkg_type == 'rpm' else h.linux_deb) if h else ''
        _install_linux(url, cid, pkg_type, expected_sha256=pkg_hash)
    elif system == 'Darwin':
        url = f"{base}/{INSTALLER_PATHS['Darwin']}"
        _install_macos(url, cid, expected_sha256=h.macos if h else '')
    else:
        raise OSError(f'Unsupported OS: {system}')


def _download(url: str, dest: str, expected_sha256: str = ''):
    print(f'[*] Downloading {url} ...')
    resp = requests.get(url, stream=True, verify=True, timeout=120)
    resp.raise_for_status()
    digest = hashlib.sha256()
    with open(dest, 'wb') as f:
        for chunk in resp.iter_content(chunk_size=65536):
            f.write(chunk)
            digest.update(chunk)
    print(f'[+] Saved to {dest}')
    if expected_sha256:
        actual = digest.hexdigest()
        if actual.lower() != expected_sha256.lower():
            os.unlink(dest)
            raise ValueError(
                f'SHA-256 mismatch for {url}\n'
                f'  expected: {expected_sha256.lower()}\n'
                f'  actual:   {actual}'
            )
        print(f'[+] Hash verified.')


def _linux_package_type() -> str:
    try:
        with open('/etc/os-release') as f:
            content = f.read().lower()
        # Debian/Ubuntu/Mint all set ID_LIKE or ID containing 'debian'
        if 'debian' in content or 'ubuntu' in content:
            return 'deb'
        if 'rhel' in content or 'fedora' in content or 'centos' in content or 'suse' in content:
            return 'rpm'
    except OSError:
        pass
    # Fallback: check for dpkg — more reliable than checking for rpm binary
    if os.path.exists('/usr/bin/dpkg'):
        return 'deb'
    return 'rpm'


def _install_windows(url: str, cid: str, expected_sha256: str = ''):
    with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
        tmp = f.name
    try:
        _download(url, tmp, expected_sha256)
        print('[*] Installing CrowdStrike Falcon on Windows...')
        result = subprocess.run(
            [tmp, '/install', '/quiet', '/norestart', f'CID={cid}'],
            capture_output=True, text=True, timeout=_SUBPROCESS_TIMEOUT,
        )
        # 0 = success, 1641/3010 = success + reboot required
        if result.returncode not in (0, 1641, 3010):
            raise RuntimeError(
                f'Installer exited with code {result.returncode}: {result.stderr}'
            )
        if result.returncode in (1641, 3010):
            print('[!] CrowdStrike Falcon installed — reboot required to complete.')
        else:
            print('[+] CrowdStrike Falcon installed.')
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _install_linux(url: str, cid: str, pkg_type: str, expected_sha256: str = ''):
    with tempfile.NamedTemporaryFile(suffix=f'.{pkg_type}', delete=False) as f:
        tmp = f.name
    try:
        _download(url, tmp, expected_sha256)
        print(f'[*] Installing CrowdStrike Falcon on Linux ({pkg_type})...')
        if pkg_type == 'rpm':
            subprocess.run(['rpm', '-ivh', '--force', tmp], check=True, timeout=_SUBPROCESS_TIMEOUT)
        else:
            subprocess.run(['dpkg', '-i', tmp], check=True, timeout=_SUBPROCESS_TIMEOUT)

        subprocess.run(
            ['/opt/CrowdStrike/falconctl', 'set', f'--cid={cid}'],
            check=True, timeout=30,
        )
        subprocess.run(['systemctl', 'start', 'falcon-sensor'], check=True, timeout=30)
        print('[+] CrowdStrike Falcon installed and started.')
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _install_macos(url: str, cid: str, expected_sha256: str = ''):
    with tempfile.NamedTemporaryFile(suffix='.pkg', delete=False) as f:
        tmp = f.name
    try:
        _download(url, tmp, expected_sha256)
        print('[*] Installing CrowdStrike Falcon on macOS...')
        subprocess.run(['installer', '-pkg', tmp, '-target', '/'], check=True, timeout=_SUBPROCESS_TIMEOUT)
        subprocess.run(['/Library/CS/falconctl', 'license', '--cid', cid], check=True, timeout=30)
        print('[+] CrowdStrike Falcon installed.')
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
