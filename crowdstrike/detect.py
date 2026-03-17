import os
import platform
import subprocess


def is_installed() -> bool:
    system = platform.system()
    if system == 'Windows':
        return _detect_windows()
    elif system == 'Linux':
        return _detect_linux()
    elif system == 'Darwin':
        return _detect_macos()
    else:
        raise OSError(f'Unsupported OS: {system}')


def _detect_windows() -> bool:
    try:
        result = subprocess.run(
            ['sc', 'query', 'CSFalconService'],
            capture_output=True
        )
        return result.returncode == 0
    except Exception:
        return False


def _detect_linux() -> bool:
    # Try systemd first
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', '--quiet', 'falcon-sensor'],
            capture_output=True
        )
        if result.returncode == 0:
            return True
    except FileNotFoundError:
        pass

    # Fallback: check for falconctl binary
    return os.path.exists('/opt/CrowdStrike/falconctl')


def _detect_macos() -> bool:
    # Check launchd
    try:
        result = subprocess.run(
            ['launchctl', 'list'],
            capture_output=True, text=True
        )
        if 'com.crowdstrike' in result.stdout.lower():
            return True
    except Exception:
        pass

    # Fallback: check for falconctl binary
    return (
        os.path.exists('/Library/CS/falconctl') or
        os.path.exists('/Applications/Falcon.app')
    )
