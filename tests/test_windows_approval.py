import json
import subprocess
import unittest
from unittest import mock
import keygrant


class WindowsApproval(unittest.TestCase):
    def dialog(self, output, offer=True, code=0):
        with mock.patch.object(keygrant.subprocess, 'run', return_value=mock.Mock(
                returncode=code, stdout=output)) as run:
            result = keygrant._approval_dialog_win('Secret K\n$(not code) "quotes"', 1000, offer)
        return result, run.call_args

    def test_explicit_choices(self):
        for value in ('allow', 'deny', 'timeout', 'allow_session'):
            self.assertEqual(self.dialog(value + '\r\n')[0], value)

    def test_cli_cannot_receive_session_grant(self):
        self.assertEqual(self.dialog('allow_session', offer=False)[0], 'deny')
        _, call = self.dialog('deny', offer=False)
        self.assertFalse(json.loads(call.kwargs['input'])['offer_session'])

    def test_unexpected_output_and_process_failure_deny(self):
        for value in ('', 'allow_session\nallow', 'True', 'ALLOW'):
            self.assertEqual(self.dialog(value)[0], 'deny')
        self.assertEqual(self.dialog('allow_session', code=1)[0], 'deny')

    def test_payload_is_data_not_executable_script(self):
        _, call = self.dialog('deny')
        self.assertEqual(json.loads(call.kwargs['input'])['text'],
                         'Secret K\n$(not code) "quotes"')
        self.assertNotIn('$(not code)', ' '.join(call.args[0]))
        self.assertIn('-NoProfile', call.args[0])
        self.assertIn('-STA', call.args[0])

    def test_process_timeout_and_missing_powershell(self):
        with mock.patch.object(keygrant.subprocess, 'run', side_effect=subprocess.TimeoutExpired('ps', 1)):
            self.assertEqual(keygrant._approval_dialog_win('text', 1, True), 'timeout')
        with mock.patch.object(keygrant.subprocess, 'run', side_effect=FileNotFoundError):
            self.assertEqual(keygrant._approval_dialog_win('text', 1, True), 'deny')

    def test_dispatch_passes_session_offer_and_explanation(self):
        with mock.patch.object(keygrant, 'IS_WIN', True), mock.patch.object(
                keygrant, '_approval_dialog_win', return_value='deny') as dialog:
            keygrant._approval_dialog(['K'], 'cmd', 1000, offer_session=True)
            text, timeout, offer = dialog.call_args.args
            self.assertTrue(offer)
            self.assertEqual(timeout, 1000)
            self.assertIn(keygrant.SESSION_BUTTON, text)
            self.assertIn('ANY command', text)
