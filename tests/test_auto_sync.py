"""Best-effort pull that `list` / `exec` run before reading the vault."""

import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import keygrant_cloud as kc  # noqa: E402


class AutoSync(unittest.TestCase):
    def run_with(self, state, pull=None):
        pull = pull or mock.Mock(return_value=(0, 0, 0))
        with mock.patch.object(kc, "load_state", return_value=state), \
             mock.patch.object(kc, "pull", pull):
            kc.auto_sync()
        return pull

    def test_noop_without_account(self):
        self.run_with({}).assert_not_called()

    def test_noop_when_locked(self):
        self.run_with({"account_id": "a"}).assert_not_called()

    def test_throttled_after_recent_sync(self):
        self.run_with({"vault_key": {"k": 1}, "last_sync": time.time() - 5}).assert_not_called()

    def test_pulls_with_short_timeout_when_due(self):
        state = {"vault_key": {"k": 1}, "last_sync": time.time() - 3600}
        self.run_with(state).assert_called_once_with(state, timeout=3)

    def test_network_errors_are_silent(self):
        boom = mock.Mock(side_effect=kc.CloudError("cannot reach api"))
        self.run_with({"vault_key": {"k": 1}}, pull=boom)  # must not raise
        boom.assert_called_once()


if __name__ == "__main__":
    unittest.main()
