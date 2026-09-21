"""
Tests for BackupManager.crack_password / cancel_crack_password — the
numeric-passcode brute-force recovery feature.

`backup.open_local_backup` is patched directly rather than exercising a real
encrypted backup on disk: what's under test here is the brute-force loop,
progress reporting, and cancellation, not iphone-backup-decrypt itself.
"""

import sys
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, "python")

import backup as backup_mod  # noqa: E402
from backup import BackupManager  # noqa: E402


def _wait_for(predicate, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


class TestCrackPasswordValidation(unittest.TestCase):

    def setUp(self):
        self.manager = BackupManager()

    def test_rejects_unsupported_digit_count(self):
        result = self.manager.crack_password("udid-1", 5)
        self.assertEqual(result["status"], "error")
        self.assertNotIn("job_id", result)

    def test_backup_not_found(self):
        with patch.object(self.manager, "_resolve_backup_dir_info", return_value=(None, None)):
            result = self.manager.crack_password("missing-udid", 4)
        self.assertEqual(result, {"status": "error", "error": "Backup not found"})

    def test_rejects_when_not_encrypted(self):
        with patch.object(
            self.manager, "_resolve_backup_dir_info",
            return_value=({"encrypted": False}, "/tmp/some-backup"),
        ):
            result = self.manager.crack_password("udid-1", 4)
        self.assertEqual(result["status"], "error")
        self.assertIn("not encrypted", result["error"])

    def test_rejects_when_decrypt_lib_missing(self):
        with (
            patch.object(
                self.manager, "_resolve_backup_dir_info",
                return_value=({"encrypted": True}, "/tmp/some-backup"),
            ),
            patch.object(backup_mod, "HAS_DECRYPT", False),
        ):
            result = self.manager.crack_password("udid-1", 4)
        self.assertEqual(result["status"], "error")
        self.assertIn("Decryption library", result["error"])

    def test_rejects_pattern_wrong_length(self):
        result = self.manager.crack_password("udid-1", 6, pattern="123")
        self.assertEqual(result["status"], "error")
        self.assertIn("6 characters", result["error"])

    def test_rejects_pattern_with_invalid_characters(self):
        result = self.manager.crack_password("udid-1", 6, pattern="12345X")
        self.assertEqual(result["status"], "error")
        self.assertIn("6 characters", result["error"])

    def test_rejects_pattern_with_no_wildcards(self):
        result = self.manager.crack_password("udid-1", 6, pattern="123456")
        self.assertEqual(result["status"], "error")
        self.assertIn("no unknown digits", result["error"])

    def test_pattern_total_reflects_wildcard_count(self):
        with (
            patch.object(
                self.manager, "_resolve_backup_dir_info",
                return_value=({"encrypted": True}, "/tmp/some-backup"),
            ),
            patch.object(backup_mod, "HAS_DECRYPT", True),
            patch.object(backup_mod.BackupManager, "_try_password", staticmethod(lambda d, p: False)),
        ):
            result = self.manager.crack_password("udid-1", 6, pattern="1*3**6")
        self.assertEqual(result["status"], "started")
        self.assertEqual(result["total"], 1000)  # 3 wildcards -> 10**3
        self.manager.cancel_crack_password(result["job_id"])


class TestPatternCandidates(unittest.TestCase):

    def test_holds_fixed_digits_and_covers_all_wildcards(self):
        candidates = list(BackupManager._pattern_candidates("1*3**6"))
        self.assertEqual(len(candidates), 1000)  # 3 wildcards
        self.assertEqual(len(set(candidates)), 1000)  # all unique
        for c in candidates:
            self.assertEqual(len(c), 6)
            self.assertEqual(c[0], "1")
            self.assertEqual(c[2], "3")
            self.assertEqual(c[5], "6")

    def test_no_wildcards_yields_single_candidate(self):
        candidates = list(BackupManager._pattern_candidates("123456"))
        self.assertEqual(candidates, ["123456"])


class TestCrackPasswordJob(unittest.TestCase):

    def setUp(self):
        self.manager = BackupManager()
        self.events: list = []
        self.events_lock = threading.Lock()

    def _notify(self, event):
        with self.events_lock:
            self.events.append(event)

    def _events_by_phase(self, phase):
        with self.events_lock:
            return [e for e in self.events if e["phase"] == phase]

    def test_finds_correct_password_and_reports_total(self):
        """A 4-digit search should try candidates until it hits the real one."""
        with (
            patch.object(
                self.manager, "_resolve_backup_dir_info",
                return_value=({"encrypted": True}, "/tmp/some-backup"),
            ),
            patch.object(backup_mod, "HAS_DECRYPT", True),
            patch.object(
                backup_mod.BackupManager, "_try_password",
                staticmethod(lambda backup_dir, password: password == "4242"),
            ),
        ):
            result = self.manager.crack_password("udid-1", 4, notify=self._notify)
            self.assertEqual(result["status"], "started")
            self.assertEqual(result["total"], 10_000)
            job_id = result["job_id"]

            self.assertTrue(_wait_for(lambda: self._events_by_phase("done")))

        done_events = self._events_by_phase("done")
        self.assertEqual(len(done_events), 1)
        done = done_events[0]
        self.assertEqual(done["job_id"], job_id)
        self.assertTrue(done["found"])
        self.assertEqual(done["password"], "4242")
        # The job should have cleaned itself up.
        self.assertNotIn(job_id, self.manager._crack_jobs)

    def test_pattern_search_only_tries_matching_candidates_and_finds_match(self):
        """A pattern search should hold known digits fixed and still find a match."""
        with (
            patch.object(
                self.manager, "_resolve_backup_dir_info",
                return_value=({"encrypted": True}, "/tmp/some-backup"),
            ),
            patch.object(backup_mod, "HAS_DECRYPT", True),
            patch.object(
                backup_mod.BackupManager, "_try_password",
                # Would only match if the search space were the full 10**6 —
                # proves the pattern's fixed digits are actually being held.
                staticmethod(lambda backup_dir, password: password == "193942"),
            ),
        ):
            result = self.manager.crack_password("udid-1", 6, pattern="1*39*2", notify=self._notify)
            self.assertEqual(result["status"], "started")
            self.assertEqual(result["total"], 100)  # 2 wildcards -> 10**2
            self.assertTrue(_wait_for(lambda: self._events_by_phase("done")))

        done = self._events_by_phase("done")[0]
        self.assertTrue(done["found"])
        self.assertEqual(done["password"], "193942")
        self.assertLessEqual(done["tried"], 100)

    def test_reports_not_found_when_no_match(self):
        """A search where no candidate matches should finish with found=False."""
        with (
            patch.object(
                self.manager, "_resolve_backup_dir_info",
                return_value=({"encrypted": True}, "/tmp/some-backup"),
            ),
            patch.object(backup_mod, "HAS_DECRYPT", True),
            patch.object(
                backup_mod.BackupManager, "_try_password",
                staticmethod(lambda backup_dir, password: False),
            ),
        ):
            self.manager.crack_password("udid-1", 4, notify=self._notify)
            self.assertTrue(_wait_for(lambda: self._events_by_phase("done"), timeout=10.0))

        done = self._events_by_phase("done")[0]
        self.assertFalse(done["found"])
        self.assertNotIn("cancelled", done)
        self.assertEqual(done["tried"], 10_000)

    def test_cancel_stops_job_before_exhausting_search_space(self):
        """cancel_crack_password should short-circuit a 6-digit search."""
        release = threading.Event()

        def _slow_try(backup_dir, password):
            # Give the test time to call cancel before the pool drains.
            release.wait(timeout=2.0)
            return False

        with (
            patch.object(
                self.manager, "_resolve_backup_dir_info",
                return_value=({"encrypted": True}, "/tmp/some-backup"),
            ),
            patch.object(backup_mod, "HAS_DECRYPT", True),
            patch.object(
                backup_mod.BackupManager, "_try_password",
                staticmethod(_slow_try),
            ),
        ):
            result = self.manager.crack_password("udid-1", 6, notify=self._notify)
            job_id = result["job_id"]
            self.assertEqual(result["total"], 1_000_000)

            self.assertTrue(_wait_for(lambda: job_id in self.manager._crack_jobs))
            cancel_result = self.manager.cancel_crack_password(job_id)
            self.assertEqual(cancel_result["status"], "cancelling")

            release.set()
            self.assertTrue(_wait_for(lambda: self._events_by_phase("done"), timeout=10.0))

        done = self._events_by_phase("done")[0]
        self.assertFalse(done["found"])
        self.assertTrue(done["cancelled"])
        self.assertLess(done["tried"], 1_000_000)

    def test_cancel_unknown_job_returns_not_found(self):
        result = self.manager.cancel_crack_password("does-not-exist")
        self.assertEqual(result, {"status": "not_found"})


class TestCrackPasswordRpcRouting(unittest.TestCase):
    """Verify main.py's SidecarServer wires crack_password / cancel_crack_password."""

    def _make_server(self):
        with (
            patch("backup.BackupManager"),
            patch("messages.MessageExtractor"),
            patch("contacts.ContactResolver"),
            patch("photos.PhotoExtractor"),
            patch("voicemail.VoicemailExtractor"),
            patch("calls.CallExtractor"),
            patch("notes.NoteExtractor"),
        ):
            import importlib
            import main as main_mod
            importlib.reload(main_mod)
            return main_mod.SidecarServer()

    def test_methods_registered(self):
        server = self._make_server()
        self.assertIn("crack_password", server.methods)
        self.assertIn("cancel_crack_password", server.methods)

    def test_crack_password_delegates(self):
        from unittest.mock import MagicMock
        server = self._make_server()
        server.backup_manager = MagicMock()
        server.backup_manager.crack_password.return_value = {
            "status": "started", "job_id": "abc", "total": 10_000,
        }

        result = server.handle_request({
            "id": 1,
            "method": "crack_password",
            "params": {"udid": "udid-1", "digits": 4, "backup_dir": "/tmp/x"},
        })

        server.backup_manager.crack_password.assert_called_once()
        call_kwargs = server.backup_manager.crack_password.call_args
        self.assertEqual(call_kwargs.args, ("udid-1", 4))
        self.assertEqual(call_kwargs.kwargs["backup_dir"], "/tmp/x")
        self.assertTrue(callable(call_kwargs.kwargs["notify"]))
        self.assertEqual(result["result"]["job_id"], "abc")

    def test_cancel_crack_password_delegates(self):
        from unittest.mock import MagicMock
        server = self._make_server()
        server.backup_manager = MagicMock()
        server.backup_manager.cancel_crack_password.return_value = {"status": "cancelling"}

        result = server.handle_request({
            "id": 2,
            "method": "cancel_crack_password",
            "params": {"job_id": "abc"},
        })

        server.backup_manager.cancel_crack_password.assert_called_once_with("abc")
        self.assertEqual(result["result"]["status"], "cancelling")


if __name__ == "__main__":
    unittest.main()
