import hashlib
import unittest
import zipfile
from pathlib import Path

from reverse_lab.corpus import build_manifest, inventory_zip


class CorpusTests(unittest.TestCase):
    def test_build_manifest_records_size_and_sha256(self):
        with self.subTest("manifest"):
            import tempfile

            with tempfile.TemporaryDirectory() as tmp:
                sample = Path(tmp) / "sample.bin"
                sample.write_bytes(b"omegas")

                manifest = build_manifest([sample])

                self.assertEqual(manifest["files"][0]["path"], str(sample))
                self.assertEqual(manifest["files"][0]["size"], 6)
                self.assertEqual(manifest["files"][0]["sha256"], hashlib.sha256(b"omegas").hexdigest())

    def test_inventory_zip_rejects_path_traversal(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "bad.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("../escape.bin", b"bad")

            result = inventory_zip(archive, max_expanded_bytes=1024)

            self.assertFalse(result["safe"])
            self.assertEqual(result["members"][0]["blocked_reason"], "path_traversal")

    def test_inventory_zip_limits_expanded_size(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "large.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("large.bin", b"x" * 32)

            result = inventory_zip(archive, max_expanded_bytes=16)

            self.assertFalse(result["safe"])
            self.assertEqual(result["blocked_reason"], "expanded_size_limit")


if __name__ == "__main__":
    unittest.main()
