"""
Unit tests for pure-logic components (no network/host required).
Run: python tests.py
"""

import base64
import unittest


# ── network.discover ──────────────────────────────────────────────────────────

class TestParseIps(unittest.TestCase):
    from network.discover import _parse_ips, _is_usable

    def test_extracts_private_ips(self):
        from network.discover import _parse_ips
        text = 'Interface: 192.168.1.1 --- 0x2\n  10.0.0.5   00-11-22-33-44-55  dynamic'
        result = _parse_ips(text)
        self.assertIn('192.168.1.1', result)
        self.assertIn('10.0.0.5', result)

    def test_excludes_loopback(self):
        from network.discover import _parse_ips
        self.assertEqual(_parse_ips('127.0.0.1'), [])

    def test_excludes_link_local(self):
        from network.discover import _parse_ips
        self.assertEqual(_parse_ips('169.254.0.1'), [])

    def test_excludes_public(self):
        from network.discover import _parse_ips
        self.assertEqual(_parse_ips('8.8.8.8'), [])

    def test_deduplicates(self):
        from network.discover import _parse_ips
        result = _parse_ips('10.0.0.1 10.0.0.1 10.0.0.1')
        self.assertEqual(result.count('10.0.0.1'), 1)

    def test_empty_string(self):
        from network.discover import _parse_ips
        self.assertEqual(_parse_ips(''), [])

    def test_no_ips(self):
        from network.discover import _parse_ips
        self.assertEqual(_parse_ips('no addresses here'), [])

    def test_172_16_range_private(self):
        from network.discover import _parse_ips
        self.assertIn('172.16.0.1', _parse_ips('172.16.0.1'))

    def test_is_usable_private(self):
        from network.discover import _is_usable
        self.assertTrue(_is_usable('10.0.0.1'))
        self.assertTrue(_is_usable('192.168.1.1'))
        self.assertTrue(_is_usable('172.16.0.1'))

    def test_is_usable_rejects_loopback(self):
        from network.discover import _is_usable
        self.assertFalse(_is_usable('127.0.0.1'))

    def test_is_usable_rejects_public(self):
        from network.discover import _is_usable
        self.assertFalse(_is_usable('1.1.1.1'))

    def test_is_usable_rejects_garbage(self):
        from network.discover import _is_usable
        self.assertFalse(_is_usable('not-an-ip'))
        self.assertFalse(_is_usable('999.0.0.1'))


# ── network.scan ─────────────────────────────────────────────────────────────

class TestHostInfo(unittest.TestCase):

    def _make(self, **kwargs):
        from network.scan import HostInfo
        return HostInfo(ip='10.0.0.1', **kwargs)

    def test_has_winrm_http(self):
        self.assertTrue(self._make(winrm_http=True).has_winrm)

    def test_has_winrm_https(self):
        self.assertTrue(self._make(winrm_https=True).has_winrm)

    def test_no_winrm(self):
        self.assertFalse(self._make().has_winrm)

    def test_has_ssh(self):
        self.assertTrue(self._make(ssh=True).has_ssh)

    def test_has_psexec(self):
        self.assertTrue(self._make(smb=True).has_psexec)

    def test_reachable_via_winrm(self):
        self.assertTrue(self._make(winrm_http=True).reachable)

    def test_reachable_via_ssh(self):
        self.assertTrue(self._make(ssh=True).reachable)

    def test_reachable_via_smb(self):
        self.assertTrue(self._make(smb=True).reachable)

    def test_not_reachable(self):
        self.assertFalse(self._make(rdp=True).reachable)

    def test_transport_label_winrm_https(self):
        label = self._make(winrm_https=True).transport_label
        self.assertIn('WinRM HTTPS', label)

    def test_transport_label_winrm_http(self):
        label = self._make(winrm_http=True).transport_label
        self.assertIn('WinRM HTTP', label)

    def test_transport_label_ssh(self):
        label = self._make(ssh=True).transport_label
        self.assertIn('SSH', label)

    def test_transport_label_smb_no_winrm(self):
        label = self._make(smb=True).transport_label
        self.assertIn('SMB/PsExec', label)

    def test_transport_label_smb_hidden_when_winrm_present(self):
        # SMB label suppressed when WinRM is also available
        label = self._make(winrm_http=True, smb=True).transport_label
        self.assertNotIn('SMB', label)

    def test_transport_label_rdp_only(self):
        label = self._make(rdp=True).transport_label
        self.assertIn('RDP only', label)

    def test_transport_label_nothing(self):
        label = self._make().transport_label
        self.assertEqual(label, 'no remoting')

    def test_pivot_default_none(self):
        self.assertIsNone(self._make().pivot)


# ── crowdstrike.obfuscate ────────────────────────────────────────────────────

class TestObfuscate(unittest.TestCase):

    SCRIPT = "Invoke-WebRequest -Uri 'https://example.com' -OutFile $tmp"

    def test_none_unchanged(self):
        from crowdstrike.obfuscate import obfuscate_script
        result = obfuscate_script(self.SCRIPT, 'none')
        self.assertEqual(result, self.SCRIPT)

    def test_light_not_equal_to_original(self):
        from crowdstrike.obfuscate import obfuscate_script
        # Light transforms Invoke-WebRequest — result should differ
        result = obfuscate_script(self.SCRIPT, 'light')
        self.assertNotEqual(result, self.SCRIPT)

    def test_light_case_insensitive_match(self):
        from crowdstrike.obfuscate import obfuscate_script
        result = obfuscate_script(self.SCRIPT, 'light').lower()
        # After removing backticks, lowercased result should contain the cmdlet
        cleaned = result.replace('`', '')
        self.assertIn('invoke-webrequest', cleaned)

    def test_heavy_replaces_sensitive_strings(self):
        from crowdstrike.obfuscate import obfuscate_script
        script = "Invoke-WebRequest -Uri 'WindowsSensor.exe'"
        result = obfuscate_script(script, 'heavy')
        self.assertNotIn('WindowsSensor.exe', result)
        self.assertIn('[char]', result)

    def test_base64_starts_with_powershell(self):
        from crowdstrike.obfuscate import obfuscate_script
        result = obfuscate_script(self.SCRIPT, 'base64')
        self.assertTrue(result.startswith('powershell.exe'))
        self.assertIn('-EncodedCommand', result)

    def test_base64_roundtrip(self):
        from crowdstrike.obfuscate import obfuscate_script
        result = obfuscate_script(self.SCRIPT, 'base64')
        b64_part = result.split('-EncodedCommand ')[1].strip()
        decoded = base64.b64decode(b64_part).decode('utf-16-le')
        self.assertEqual(decoded, self.SCRIPT)

    def test_is_encoded_true_for_base64(self):
        from crowdstrike.obfuscate import obfuscate_script, is_encoded
        result = obfuscate_script(self.SCRIPT, 'base64')
        self.assertTrue(is_encoded(result))

    def test_is_encoded_false_for_plain(self):
        from crowdstrike.obfuscate import is_encoded
        self.assertFalse(is_encoded(self.SCRIPT))

    def test_is_encoded_false_for_light(self):
        from crowdstrike.obfuscate import obfuscate_script, is_encoded
        result = obfuscate_script(self.SCRIPT, 'light')
        self.assertFalse(is_encoded(result))

    def test_unknown_level_raises(self):
        from crowdstrike.obfuscate import obfuscate_script
        with self.assertRaises(ValueError):
            obfuscate_script(self.SCRIPT, 'bogus')

    def test_char_array_roundtrip(self):
        import re
        from crowdstrike.obfuscate import _char_array
        s = 'WindowsSensor.exe'
        expr = _char_array(s)
        # Extract the ordinal sequence: (...,87,105,...|%{[char]$_})
        match = re.search(r'\((\d+(?:,\d+)*)\|', expr)
        self.assertIsNotNone(match, f'Could not find ordinals in: {expr}')
        recovered = ''.join(chr(int(n)) for n in match.group(1).split(','))
        self.assertEqual(recovered, s)

    def test_insert_ticks_short_string_unchanged(self):
        from crowdstrike.obfuscate import _insert_ticks
        self.assertEqual(_insert_ticks('ab'), 'ab')

    def test_insert_ticks_adds_backtick(self):
        from crowdstrike.obfuscate import _insert_ticks
        s = 'InvokeWebRequest'
        result = _insert_ticks(s)
        self.assertIn('`', result)
        self.assertEqual(result.replace('`', ''), s)


if __name__ == '__main__':
    unittest.main(verbosity=2)
