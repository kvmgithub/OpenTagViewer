"""
Tests for the Android app's python bridge (app/src/main/python/main.py)
against findmy >= 0.10.0 (issue #30: rotation/alignment tracking).

Requires the `FindMy` pip package; skipped otherwise (the other tests in
this folder must stay runnable without it).

Run from the `python/` folder:
    python -m unittest test.test_app_main
"""
import importlib.util
import json
import os
import plistlib
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

try:
    import findmy  # noqa: F401
    HAS_FINDMY = True
except ImportError:
    HAS_FINDMY = False

APP_PYTHON_DIR = Path(__file__).resolve().parents[2] / "app" / "src" / "main" / "python"

TMP = tempfile.mkdtemp(prefix="otv_test_home_")


def _make_plist(identifier: str, paired_at: datetime) -> str:
    """Synthetic OwnedBeacons plist with the fields main.py/findmy need."""
    return plistlib.dumps({
        "privateKey": {"key": {"data": b"\x01" * 85}},
        "publicKey": {"key": {"data": b"\x02" * 57}},
        "sharedSecret": {"key": {"data": b"\x03" * 32}},
        "secondarySharedSecret": {"key": {"data": b"\x04" * 32}},
        "pairingDate": paired_at.replace(tzinfo=None),
        "model": "Smart Card",
        "identifier": identifier,
        "stableIdentifier": ["a:/TEST~#0123456789ABCDEF"],
    }, fmt=plistlib.FMT_XML).decode("utf-8")


class FakePair:
    def __init__(self, first, second):
        self.first = first
        self.second = second


class FakeJavaList:
    """Mimics the java List<Pair<String,String>> chaquopy passes in."""

    def __init__(self, items):
        self._items = items

    def size(self):
        return len(self._items)

    def get(self, i):
        return self._items[i]


def _report(ts: datetime):
    return SimpleNamespace(
        timestamp=ts,
        confidence=1,
        latitude=50.0,
        longitude=7.0,
        horizontal_accuracy=10,
        status=0,
    )


class FakeAccount:
    def __init__(self, reports):
        self._reports = reports

    def fetch_location_history(self, accessory):
        # real findmy updates alignment as reports come in
        for i, r in enumerate(self._reports):
            accessory.update_alignment(r.timestamp, i + 1)
        return list(self._reports)


@unittest.skipUnless(HAS_FINDMY, "FindMy pip package not installed")
class TestAppMain(unittest.TestCase):
    BEACON_ID = "00000000-0000-0000-0000-000000000001"

    @classmethod
    def setUpClass(cls):
        os.environ["HOME"] = TMP  # chaquopy sets HOME to the app files dir
        # load by path under a unique name: a plain `import main` would clash
        # with the desktop tools' `main` package next to this test folder
        spec = importlib.util.spec_from_file_location(
            "otv_app_main", APP_PYTHON_DIR / "main.py")
        cls.main = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.main)

    def setUp(self):
        self.paired_at = datetime.now(tz=timezone.utc) - timedelta(days=3)
        self.plist = _make_plist(self.BEACON_ID, self.paired_at)
        state = self.main.STATE_DIR / f"{self.BEACON_ID}.json"
        if state.exists():
            state.unlink()

    def _java_list(self):
        return FakeJavaList([FakePair(self.BEACON_ID, self.plist)])

    def test_get_last_reports_filters_and_maps(self):
        now = datetime.now(tz=timezone.utc)
        acc = FakeAccount([
            _report(now - timedelta(hours=2)),
            _report(now - timedelta(hours=48)),  # outside 24h window
        ])
        res = self.main.getLastReports(acc, self._java_list(), 24)

        self.assertIsNotNone(res)
        items = res[self.BEACON_ID]
        self.assertEqual(len(items), 1)
        item = items[0]
        # Java (PythonAppleService) hard-requires every one of these keys:
        for key in ("publishedAt", "description", "timestamp", "confidence",
                    "latitude", "longitude", "horizontalAccuracy", "status"):
            self.assertIn(key, item)
        self.assertEqual(item["timestamp"], item["publishedAt"])
        self.assertIsInstance(item["description"], str)

    def test_alignment_state_persisted_and_reused(self):
        now = datetime.now(tz=timezone.utc)
        self.main.getLastReports(
            FakeAccount([_report(now - timedelta(hours=1))]),
            self._java_list(), 24)

        state_file = self.main.STATE_DIR / f"{self.BEACON_ID}.json"
        self.assertTrue(state_file.exists(), "accessory state must be persisted (issue #30)")
        saved = json.loads(state_file.read_text())
        self.assertEqual(saved["alignment_index"], 1)

        # next load must come from the saved state, not the plist
        accessory = self.main._loadAccessory(self.BEACON_ID, self.plist)
        self.assertEqual(accessory.to_json()["alignment_index"], 1)

    def test_corrupt_state_falls_back_to_plist(self):
        self.main.STATE_DIR.mkdir(parents=True, exist_ok=True)
        (self.main.STATE_DIR / f"{self.BEACON_ID}.json").write_text("not json{")
        accessory = self.main._loadAccessory(self.BEACON_ID, self.plist)
        self.assertEqual(accessory.identifier, self.BEACON_ID)

    def test_get_reports_range(self):
        now = datetime.now(tz=timezone.utc)
        inside = now - timedelta(hours=5)
        acc = FakeAccount([_report(inside), _report(now - timedelta(days=6))])
        start_ms = int((now - timedelta(hours=10)).timestamp() * 1000)
        end_ms = int(now.timestamp() * 1000)

        res = self.main.getReports(acc, self._java_list(), start_ms, end_ms)
        items = res[self.BEACON_ID]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["timestamp"], int(inside.timestamp() * 1000))

    def test_get_account_rejects_legacy_state(self):
        # pre-0.8 `account.export()` blobs have no "type" key -> must return
        # None so the app sends the user through a clean re-login
        legacy = json.dumps({"ids": {}, "account": {}, "login_state": 3})
        self.assertIsNone(self.main.getAccount(legacy, "http://ani.example"))


if __name__ == "__main__":
    unittest.main()
