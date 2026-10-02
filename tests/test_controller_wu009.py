import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from reverse_lab.controller import execute_workunit, main
from reverse_lab.workunits import claim_next_workunit


class Wu009LoopRegressionTests(unittest.TestCase):
    def test_unchanged_corpus_saturates_instead_of_retrying(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / "corpus"
            corpus.mkdir()
            status, result = execute_workunit(
                {"id": "WU-009", "attempts": 101821},
                corpus, Path(tmp) / "artifacts",
            )
            self.assertEqual(status, "saturated")
            self.assertFalse(result["retryable"])
            self.assertEqual(result["reason"], "closed_corpus_no_new_evidence")
            artifact = json.loads(Path(result["artifact"]).read_text(encoding="utf-8"))
            self.assertEqual(artifact["status"], "saturated")
            self.assertTrue(all(value == "UNKNOWN" for value in artifact["autocalibration"].values()))
            self.assertFalse(artifact["automaticWrite"])

    def test_controller_exits_without_retrying_or_dispatching(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state.json"
            state.write_text(json.dumps({"workunits": [
                {"id": "WU-004", "status": "done", "depends_on": []},
                {"id": "WU-007", "status": "done", "depends_on": []},
                {"id": "WU-008", "status": "done", "depends_on": []},
                {"id": "WU-011", "status": "done", "depends_on": []},
                {"id": "WU-009", "status": "ready", "attempts": 101820,
                 "depends_on": ["WU-004", "WU-007", "WU-008", "WU-011"]},
                {"id": "WU-010", "status": "ready",
                 "depends_on": ["WU-009"]},
            ]}), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result_code = main([
                    "--state-path", str(state),
                    "--corpus-root", str(root / "corpus"),
                    "--artifacts-root", str(root / "artifacts"),
                    "--max-units", "10",
                ])
            summary = json.loads(output.getvalue())
            saved = json.loads(state.read_text(encoding="utf-8"))
            self.assertEqual(result_code, 0)
            self.assertEqual([item["id"] for item in summary["executed"]], ["WU-009"])
            self.assertEqual(saved["workunits"][4]["attempts"], 101821)
            self.assertEqual(saved["workunits"][4]["status"], "saturated")
            self.assertEqual(saved["workunits"][5]["status"], "ready")
            self.assertFalse(summary["continuation"]["dispatched"])
            self.assertIsNone(claim_next_workunit(state, "runner", 60))


if __name__ == "__main__":
    unittest.main()
