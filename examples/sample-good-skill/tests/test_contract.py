import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from check_contract import check_required_keys


class TestCheckContract(unittest.TestCase):
    def test_valid_payload(self):
        self.assertEqual(check_required_keys({"code": 200, "data": "ok"}, ["code", "data"]), [])

    def test_missing_or_empty_field(self):
        self.assertEqual(check_required_keys({"code": 200, "data": ""}, ["code", "data"]), ["data"])


if __name__ == "__main__":
    unittest.main()
