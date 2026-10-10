"""Client audit trail: what gets queued per tier, and how the outbox uploads."""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import keygrant as kg  # noqa: E402
import keygrant_cloud as kc  # noqa: E402


class AuditBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        p = mock.patch.object(kg, "VAULT_DIR", self.dir)
        p.start()
        self.addCleanup(p.stop)
        self.outbox = os.path.join(self.dir, "audit-outbox.jsonl")

    def cloud(self, **state):
        with open(os.path.join(self.dir, "cloud.json"), "w") as f:
            json.dump(state, f)

    def queued(self):
        if not os.path.exists(self.outbox):
            return []
        with open(self.outbox) as f:
            return [json.loads(line) for line in f]


class Recording(AuditBase):
    def test_metadata_tier_hashes_the_command_and_never_stores_it(self):
        self.cloud(account_id="a")
        with mock.patch.dict(os.environ, {"KEYGRANT_REQUESTER": "mcp:42"}):
            kg.record_event("exec", ["STRIPE", "OPENAI"], "curl -H $STRIPE api")
        events = self.queued()
        self.assertEqual([e["name"] for e in events], ["STRIPE", "OPENAI"])
        self.assertTrue(events[0]["command_hash"].startswith("sha256:"))
        self.assertEqual(events[0]["requester"], "mcp:42")
        self.assertNotIn("command_preview", events[0])

    def test_full_tier_adds_the_command_text(self):
        self.cloud(account_id="a", audit="full")
        kg.record_event("denied", ["K"], "curl evil")
        self.assertEqual(self.queued()[0]["command_preview"], "curl evil")

    def test_off_tier_and_no_account_queue_nothing(self):
        self.cloud(account_id="a", audit="off")
        kg.record_event("exec", ["K"], "x")
        os.remove(os.path.join(self.dir, "cloud.json"))
        kg.record_event("exec", ["K"], "x")
        self.assertEqual(self.queued(), [])


class Flush(AuditBase):
    def setUp(self):
        super().setUp()
        self.cloud(account_id="a")
        for i in range(150):
            kg.record_event("exec", [f"K{i}"], "x")
        self.posted = []

    def test_uploads_in_batches_and_clears_the_outbox(self):
        with mock.patch.object(kc, "api", lambda s, m, p, body=None, **k: self.posted.append(body)):
            self.assertEqual(kc.flush_audit({}), 150)
        self.assertEqual([len(b["events"]) for b in self.posted], [100, 50])
        self.assertFalse(os.path.exists(self.outbox))
        self.assertFalse(os.path.exists(self.outbox + ".sending"))

    def test_partial_failure_keeps_only_unsent_events_and_new_ones(self):
        def flaky(_s, _m, _p, body=None, **_k):
            if self.posted:
                raise kc.CloudError("offline")
            self.posted.append(body)
        with mock.patch.object(kc, "api", flaky):
            with self.assertRaises(kc.CloudError):
                kc.flush_audit({})
        kg.record_event("exec", ["NEW"], "x")  # commands keep appending meanwhile
        with open(self.outbox + ".sending") as f:
            self.assertEqual(len(f.readlines()), 50)
        self.posted = []
        with mock.patch.object(kc, "api", lambda s, m, p, body=None, **k: self.posted.append(body)):
            kc.flush_audit({})  # resend the 50 left over
            kc.flush_audit({})  # then the new one
        self.assertEqual([len(b["events"]) for b in self.posted], [50, 1])


class RemoteApprovalRegression(unittest.TestCase):
    def test_escalation_reaches_the_cloud_module(self):
        # 0.1.4 referenced a removed helper here, so escalation always failed
        with mock.patch.object(kc, "remote_approval", return_value=True) as remote:
            self.assertIs(kg._remote_approval(["K"], "echo hi"), True)
        self.assertEqual(remote.call_args.args[2], kg.current_requester())


if __name__ == "__main__":
    unittest.main()
