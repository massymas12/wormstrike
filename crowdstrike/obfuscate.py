"""
PowerShell obfuscation helpers.

Levels:
  none    — plain script, no changes
  light   — random case + backtick insertion on known cmdlets/keywords
  heavy   — light + char-array substitution for sensitive string literals
  base64  — UTF-16LE base64 encode the entire script; use -EncodedCommand
             (compatible with both WinRM and PsExec transports)
"""

import base64
import random


# ── Techniques ────────────────────────────────────────────────────────────

def _random_case(s: str) -> str:
    """Randomly capitalize each character: InVoKe-WeBrEqUeSt"""
    return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in s)


def _insert_ticks(s: str) -> str:
    """
    Insert PowerShell backtick escapes at 1-3 random interior positions.
    Backticks are the PS escape char and are silently ignored inside identifiers,
    so `In` + `voke-WebRequest` is still valid and breaks static string matching.
    """
    if len(s) < 4:
        return s
    n_ticks = random.randint(1, min(3, len(s) - 2))
    positions = sorted(random.sample(range(1, len(s) - 1), n_ticks), reverse=True)
    result = list(s)
    for pos in positions:
        result.insert(pos, '`')
    return ''.join(result)


def _char_array(s: str) -> str:
    """
    Replace a bare string with a PowerShell char-array join that evaluates to
    the same string at runtime but contains no recognisable literal:

      WindowsSensor.exe  →  $([string]::Join('',(87,105,110,...|%{[char]$_})))
    """
    ords = ','.join(str(ord(c)) for c in s)
    return f"$([string]::Join('',({ords}|%{{[char]$_}})))"


# ── Targets ───────────────────────────────────────────────────────────────

# Cmdlets/keywords to mangle with case+ticks
_CMDLETS = [
    'Invoke-WebRequest',
    'Start-Process',
    'Remove-Item',
    'Get-Service',
    'Set-ExecutionPolicy',
    'ServicePointManager',
    'ServerCertificateValidationCallback',
    'UseBasicParsing',
    'ArgumentList',
]

# Sensitive string literals to replace with char-arrays
_SENSITIVE_STRINGS = [
    'WindowsSensor.exe',
    'falcon-sensor',
    'FalconSensorMacOS.pkg',
    'falcon.pkg',
    'falcon.rpm',
    'falcon.deb',
    'CSFalconService',
    'falconctl',
    'CrowdStrike',
]


# ── Public API ────────────────────────────────────────────────────────────

def obfuscate_script(script: str, level: str) -> str:
    """
    Transform a PowerShell script string according to the requested level.
    For 'base64', returns a full `powershell.exe -EncodedCommand <b64>` invocation
    rather than raw script content — callers must handle this differently.
    """
    if level == 'none':
        return script
    if level == 'light':
        return _apply_light(script)
    if level == 'heavy':
        return _apply_heavy(_apply_light(script))
    if level == 'base64':
        return _apply_base64(script)
    raise ValueError(f'Unknown obfuscation level: {level!r}')


def is_encoded(script: str) -> bool:
    """True when obfuscate_script returned an -EncodedCommand invocation."""
    return script.startswith('powershell')


def _apply_light(script: str) -> str:
    for kw in _CMDLETS:
        # Replace one occurrence at a time so each gets independently randomized
        while kw in script:
            script = script.replace(kw, _insert_ticks(_random_case(kw)), 1)
    return script


def _apply_heavy(script: str) -> str:
    for s in _SENSITIVE_STRINGS:
        for quote in ('"', "'"):
            literal = f'{quote}{s}{quote}'
            if literal in script:
                script = script.replace(literal, _char_array(s))
    return script


def _apply_base64(script: str) -> str:
    """
    UTF-16LE encode + base64 wrap.  The result is a complete PowerShell
    invocation string intended to be passed to cmd /c or PsExec.
    """
    b64 = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    return (
        'powershell.exe -NonInteractive -NoProfile '
        f'-EncodedCommand {b64}'
    )
