"""
Build fake installer stubs for end-to-end testing.

Run this once on each platform to populate the installers/ directory:
  python build_stubs.py

Requirements:
  Windows : pip install pyinstaller
  Linux   : dpkg-deb (for .deb) and/or rpmbuild (for .rpm)
  macOS   : pkgbuild (included with Xcode Command Line Tools)
"""

import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT       = Path(__file__).parent
STUBS_DIR  = ROOT / 'installers' / 'stubs'
WIN_OUT    = ROOT / 'installers' / 'windows'
LINUX_OUT  = ROOT / 'installers' / 'linux'
MACOS_OUT  = ROOT / 'installers' / 'macos'

FAKE_SENSOR_PY   = STUBS_DIR / 'fake_sensor.py'
FAKE_FALCONCTL   = STUBS_DIR / 'fake_falconctl.sh'


def _require(tool: str):
    if not shutil.which(tool):
        print(f'[!] Required tool not found: {tool}')
        sys.exit(1)


# ── Windows ───────────────────────────────────────────────────────────────────

def build_windows():
    print('[*] Building Windows stub (WindowsSensor.exe) via PyInstaller...')
    WIN_OUT.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            [
                sys.executable, '-m', 'PyInstaller',
                '--onefile',
                '--distpath', str(WIN_OUT),
                '--workpath', tmp,
                '--specpath', tmp,
                '--name', 'WindowsSensor',
                '--noconfirm',
                str(FAKE_SENSOR_PY),
            ],
            check=True,
        )

    out = WIN_OUT / 'WindowsSensor.exe'
    print(f'[+] {out}')
    _print_hash(out)


# ── Linux ─────────────────────────────────────────────────────────────────────

def _write_fake_falconctl(dest: Path):
    """Copy the falconctl stub to dest and make it executable."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(FAKE_FALCONCTL, dest)
    dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def build_linux_deb():
    print('[*] Building Linux DEB stub (falcon-sensor_amd64.deb)...')
    _require('dpkg-deb')
    LINUX_OUT.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        pkg = Path(tmp) / 'falcon-sensor'

        # DEBIAN/control
        ctrl = pkg / 'DEBIAN'
        ctrl.mkdir(parents=True)
        (ctrl / 'control').write_text(
            'Package: falcon-sensor\n'
            'Version: 0.0.1-stub\n'
            'Architecture: amd64\n'
            'Maintainer: stub\n'
            'Description: Fake CrowdStrike Falcon sensor stub for testing\n'
        )

        # Fake falconctl binary
        _write_fake_falconctl(pkg / 'opt' / 'CrowdStrike' / 'falconctl')

        out = LINUX_OUT / 'falcon-sensor_amd64.deb'
        subprocess.run(['dpkg-deb', '--build', str(pkg), str(out)], check=True)

    print(f'[+] {out}')
    _print_hash(out)


def build_linux_rpm():
    print('[*] Building Linux RPM stub (falcon-sensor.x86_64.rpm)...')
    _require('rpmbuild')
    LINUX_OUT.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for d in ('BUILD', 'RPMS', 'SOURCES', 'SPECS', 'SRPMS'):
            (tmp / d).mkdir()

        # Install the fake falconctl into a staging dir that rpmbuild will package
        install_root = tmp / 'BUILDROOT' / 'falcon-sensor-0.0.1-1.x86_64'
        _write_fake_falconctl(install_root / 'opt' / 'CrowdStrike' / 'falconctl')

        spec = tmp / 'SPECS' / 'falcon-sensor.spec'
        spec.write_text(
            '%define _topdir ' + str(tmp) + '\n'
            'Name:    falcon-sensor\n'
            'Version: 0.0.1\n'
            'Release: 1\n'
            'Summary: Fake CrowdStrike Falcon sensor stub for testing\n'
            'License: stub\n'
            'BuildArch: x86_64\n'
            '\n'
            '%description\n'
            'Fake CrowdStrike Falcon sensor stub for testing.\n'
            '\n'
            '%install\n'
            'mkdir -p %{buildroot}/opt/CrowdStrike\n'
            f'cp {FAKE_FALCONCTL} %{{buildroot}}/opt/CrowdStrike/falconctl\n'
            'chmod +x %{buildroot}/opt/CrowdStrike/falconctl\n'
            '\n'
            '%files\n'
            '/opt/CrowdStrike/falconctl\n'
        )

        subprocess.run(
            ['rpmbuild', '-bb', str(spec), '--define', f'_topdir {tmp}'],
            check=True,
        )

        rpms = list((tmp / 'RPMS' / 'x86_64').glob('*.rpm'))
        if not rpms:
            print('[!] rpmbuild succeeded but no .rpm found')
            sys.exit(1)

        out = LINUX_OUT / 'falcon-sensor.x86_64.rpm'
        shutil.copy(rpms[0], out)

    print(f'[+] {out}')
    _print_hash(out)


# ── macOS ─────────────────────────────────────────────────────────────────────

def build_macos():
    print('[*] Building macOS stub (FalconSensorMacOS.pkg)...')
    _require('pkgbuild')
    MACOS_OUT.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        payload = tmp / 'payload'
        _write_fake_falconctl(payload / 'Library' / 'CS' / 'falconctl')

        out = MACOS_OUT / 'FalconSensorMacOS.pkg'
        subprocess.run(
            [
                'pkgbuild',
                '--root', str(payload),
                '--identifier', 'com.crowdstrike.falcon.stub',
                '--version', '0.0.1',
                '--install-location', '/',
                str(out),
            ],
            check=True,
        )

    print(f'[+] {out}')
    _print_hash(out)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _print_hash(path: Path):
    import hashlib
    h = hashlib.sha256(path.read_bytes()).hexdigest()
    print(f'    SHA-256: {h}')
    print(f'    Add to config.toml if you want hash verification during testing.')


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    system = platform.system()

    if system == 'Windows':
        build_windows()
    elif system == 'Linux':
        build_linux_deb()
        build_linux_rpm()
    elif system == 'Darwin':
        build_macos()
    else:
        print(f'[!] Unsupported platform: {system}')
        sys.exit(1)

    print('\n[+] Done. Stubs are in installers/.')


if __name__ == '__main__':
    main()
