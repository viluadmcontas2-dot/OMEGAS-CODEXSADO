import json
import time
import unittest

from reverse_lab.workunits import claim_next_workunit, release_workunit


class WorkunitTests(unittest.TestCase):
    def test_claim_next_workunit_takes_ready_item_with_lease(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "workunits.json"
            state.write_text(
                json.dumps(
                    {
                        "workunits": [
                            {"id": "WU-001", "status": "ready", "depends_on": []},
                            {"id": "WU-002", "status": "ready", "depends_on": ["WU-001"]},
                        ]
                    }
                ),
                encoding="utf-8",
            )

            claim = claim_next_workunit(state, owner="runner-a", lease_seconds=60)

            data = json.loads(state.read_text(encoding="utf-8"))
            self.assertEqual(claim["id"], "WU-001")
            self.assertEqual(data["workunits"][0]["status"], "running")
            self.assertEqual(data["workunits"][0]["owner"], "runner-a")
            self.assertGreater(data["workunits"][0]["lease_expires_at"], int(time.time()))
            self.assertEqual(data["workunits"][1]["status"], "ready")

    def test_claim_next_workunit_recovers_expired_lease(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "workunits.json"
            state.write_text(
                json.dumps(
                    {
                        "workunits": [
                            {
                                "id": "WU-001",
                                "status": "running",
                                "owner": "lost-runner",
                                "lease_expires_at": 1,
                                "depends_on": [],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            claim = claim_next_workunit(state, owner="runner-b", lease_seconds=60)

            self.assertEqual(claim["id"], "WU-001")
            self.assertEqual(claim["owner"], "runner-b")

    def test_release_workunit_records_blocked_reason(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "workunits.json"
            state.write_text(
                json.dumps(
                    {
                        "workunits": [
                            {
                                "id": "WU-001",
                                "status": "running",
                                "owner": "runner-a",
                                "lease_expires_at": int(time.time()) + 60,
                                "depends_on": [],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            release_workunit(state, "WU-001", status="blocked", result={"reason": "missing_corpus"})

            data = json.loads(state.read_text(encoding="utf-8"))
            self.assertEqual(data["workunits"][0]["status"], "blocked")
            self.assertEqual(data["workunits"][0]["result"]["reason"], "missing_corpus")
            self.assertNotIn("owner", data["workunits"][0])


if __name__ == "__main__":
    unittest.main()
