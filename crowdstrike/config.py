from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib          # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # pip install tomli
    except ImportError:
        raise ImportError(
            'tomllib is not available. On Python <3.11 run: pip install tomli'
        )


@dataclass
class InstallerHashes:
    windows:   str = ''
    linux_rpm: str = ''
    linux_deb: str = ''
    macos:     str = ''


@dataclass
class Config:
    server_url: str
    cid:        str
    hashes:     InstallerHashes = field(default_factory=InstallerHashes)


def load(path: str | Path = 'config.toml') -> Config:
    with open(path, 'rb') as f:
        data = tomllib.load(f)

    cs = data.get('crowdstrike', {})
    inst = data.get('installers', {})

    return Config(
        server_url=cs['server_url'],
        cid=cs['cid'],
        hashes=InstallerHashes(
            windows=inst.get('windows_sha256', ''),
            linux_rpm=inst.get('linux_rpm_sha256', ''),
            linux_deb=inst.get('linux_deb_sha256', ''),
            macos=inst.get('macos_sha256', ''),
        ),
    )
