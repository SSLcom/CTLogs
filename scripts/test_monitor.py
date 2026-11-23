#!/usr/bin/env python3
"""Unit tests of monitor.py against a log served from memory. Usage: python3 -m unittest discover -s scripts -p 'test_*.py'"""
import base64
import hashlib
import http.client
import io
import json
import pathlib
import tempfile
import unittest
import urllib.error
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import ctlog
import monitor
from test_ctlog import LEAVES, mth, signed_note, tree

MON, SUB, ORIGIN = "https://mon.example/2027h1/", "https://log.example/2027h1/", "log.example/2027h1"
NOW = 1_800_000_000  # seconds; a checkpoint signed "now" carries NOW * 1000
KEY = ec.generate_private_key(ec.SECP256R1())
LOG = {"friendly_name": "Example 2027h1", "status": "active",
       "key": base64.b64encode(KEY.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode(),
       "submission_endpoint": {"url": SUB}, "monitoring_endpoint": {"url": MON}}
FORKED = list(LEAVES[:1000])
FORKED[7] = hashlib.sha256(b"another certificate").digest()


def note(leaves, age=0, root=None):
    if root is None:
        root = ctlog.roots(ctlog.Tiles(len(leaves), tree(leaves)), 0, len(leaves))[1]
    return signed_note(KEY, ORIGIN, len(leaves), root, (NOW - age) * 1000)


class Web:
    """The log's public surface: its checkpoints in the order given, and only the tiles a log holding `leaves` still has."""

    def __init__(self, leaves, *notes):
        self.notes = list(notes) or [note(leaves)]
        self.files, read = {}, tree(leaves)
        for level in range(4):
            have = len(leaves) >> 8 * level
            for index in range(-(-have // ctlog.TILE)):
                width = min(ctlog.TILE, have - ctlog.TILE * index)
                self.files[ctlog.tile_path(level, index, width)] = read(level, index, width)

    def fetch(self, url, attempts=3):
        if url == SUB + "ct/v1/get-roots":
            return json.dumps({"certificates": ["MIIB"]}).encode()
        path = url.removeprefix(MON)
        if path == "checkpoint":
            return (self.notes.pop(0) if len(self.notes) > 1 else self.notes[0]).encode()
        if path not in self.files:
            raise urllib.error.HTTPError(url, 404, "Not Found", None, io.BytesIO())
        return self.files[path]


def run(web, last=None, log=LOG):
    with mock.patch.object(monitor, "fetch", web.fetch), mock.patch.object(monitor.time, "sleep"):
        return monitor.check_tree(log, last, NOW)


def checks(result):
    return [check for check, _ in result[0]]


class Tree(unittest.TestCase):
    def test_a_first_look_passes_and_remembers_the_checkpoint(self):
        web = Web(LEAVES[:1000])
        problems, facts, keep, evidence = run(web)
        self.assertEqual((problems, keep, evidence), ([], web.notes[0], []))
        self.assertIn("2 tile(s) hash to its root", facts)

    def test_an_empty_tree_needs_no_tile(self):
        problems, facts, keep, _ = run(Web([]))
        self.assertEqual(problems, [])
        self.assertIn("empty tree, so no tile yet", facts)

    def test_a_tree_that_grew_extends_the_last_checkpoint(self):
        for old in (0, 1, 300, 1000):
            with self.subTest(old=old):
                web = Web(LEAVES[:1000])
                problems, facts, keep, _ = run(web, note(LEAVES[:old]))
                self.assertEqual((problems, keep), ([], web.notes[0]))
                self.assertTrue(any(f.startswith(f"extends the {old} entries") for f in facts))

    def test_rewritten_history_fails_and_keeps_the_last_good_checkpoint(self):
        last = note(LEAVES[:300])
        web = Web(FORKED)
        problems, _, keep, evidence = run(web, last)
        self.assertEqual(checks((problems,)), ["consistency"])
        self.assertIn("history changed", problems[0][1])
        self.assertEqual((keep, evidence), (last, [last, web.notes[0]]))

    def test_the_same_size_with_another_root_fails(self):
        last = note(LEAVES[:1000])
        self.assertEqual(checks(run(Web(FORKED), last)), ["consistency"])

    def test_a_tree_that_shrank_fails_and_keeps_the_last_good_checkpoint(self):
        last = note(LEAVES[:1000])
        problems, _, keep, evidence = run(Web(LEAVES[:300]), last)
        self.assertEqual(checks((problems,)), ["consistency"])
        self.assertIn("shrank from 1000 to 300", problems[0][1])
        self.assertEqual((keep, len(evidence)), (last, 2))

    def test_tiles_that_do_not_hash_to_the_signed_root_fail(self):
        last = note(LEAVES[:300])
        problems, _, keep, _ = run(Web(LEAVES[:1000], note(LEAVES[:1000], root=b"\x22" * 32)), last)
        self.assertEqual((checks((problems,)), keep), (["tiles"], last))

    def test_a_missing_full_tile_fails(self):
        web = Web(LEAVES[:1000])
        del web.files["tile/0/001"]
        problems = run(web, note(LEAVES[:300]))[0]
        self.assertEqual(checks((problems,)), ["tiles"])
        self.assertIn("cannot read tile/0/001", problems[0][1])

    def test_an_old_checkpoint_fails_an_active_log_only(self):
        web = Web(LEAVES[:300], note(LEAVES[:300], age=monitor.MAX_AGE + 60))
        problems, _, keep, _ = run(web)
        self.assertEqual(checks((problems,)), ["age"])
        self.assertEqual(keep, web.notes[0])
        self.assertEqual(run(web, log={**LOG, "status": "readonly"})[0], [])

    def test_a_checkpoint_under_another_key_fails(self):
        other = ec.generate_private_key(ec.SECP256R1())
        forged = signed_note(other, ORIGIN, 300, mth(0, 300), NOW * 1000)
        last = note(LEAVES[:100])
        problems, _, keep, evidence = run(Web(LEAVES[:300], forged), last)
        self.assertEqual((checks((problems,)), keep, evidence), (["checkpoint"], last, [forged]))

    def test_a_remembered_note_that_no_longer_verifies_is_dropped_not_trusted(self):
        web = Web(LEAVES[:300])
        problems, _, keep, _ = run(web, "not a checkpoint\n")
        self.assertEqual((problems, keep), ([], web.notes[0]))

    def test_a_partial_tile_that_filled_since_the_checkpoint_is_read_from_the_full_one(self):
        # The checkpoint in hand says 200; the log now holds 256, so tile/0/000.p/200 is gone and tile/0/000 exists.
        web = Web(LEAVES[:256], note(LEAVES[:200]))
        self.assertEqual(run(web, note(LEAVES[:100]))[0], [])

    def test_a_deleted_partial_tile_is_retried_with_a_fresh_checkpoint(self):
        # 200 was read, then the log moved to 230 and deleted .p/200: the second checkpoint is the one that verifies.
        web = Web(LEAVES[:230], note(LEAVES[:200]), note(LEAVES[:230]))
        problems, facts, keep, _ = run(web, note(LEAVES[:100]))
        self.assertEqual((problems, keep), ([], web.notes[0]))
        self.assertIn("size 230", facts)

    def test_a_log_that_always_outruns_its_checkpoint_fails(self):
        web = Web(LEAVES[:230], note(LEAVES[:200]))
        self.assertEqual(checks(run(web)), ["tiles"])

    def test_a_checkpoint_dated_in_the_future_fails_but_a_small_clock_difference_passes(self):
        ahead = Web(LEAVES[:300], note(LEAVES[:300], age=-(monitor.MAX_AHEAD + 60)))
        problems = run(ahead)[0]
        self.assertEqual(checks((problems,)), ["age"])
        self.assertIn("in the future", problems[0][1])
        self.assertEqual(run(ahead, log={**LOG, "status": "readonly"})[0], problems)
        self.assertEqual(run(Web(LEAVES[:300], note(LEAVES[:300], age=-30)))[0], [])


class Endpoints(unittest.TestCase):
    def test_a_cut_short_answer_is_retried_then_reported_like_any_unreadable_one(self):
        cut = http.client.IncompleteRead(b"half")
        with mock.patch.object(monitor.urllib.request, "urlopen", side_effect=cut) as urlopen, mock.patch.object(monitor.time, "sleep"):
            with self.assertRaisesRegex(OSError, "IncompleteRead"):
                monitor.fetch(MON + "checkpoint")
        self.assertEqual(urlopen.call_count, 3)

    def test_a_missing_object_is_an_answer_and_is_not_retried(self):
        gone = urllib.error.HTTPError(MON, 404, "Not Found", None, io.BytesIO())
        with mock.patch.object(monitor.urllib.request, "urlopen", side_effect=gone) as urlopen:
            with self.assertRaises(urllib.error.HTTPError):
                monitor.fetch(MON + "tile/0/000.p/5")
        self.assertEqual(urlopen.call_count, 1)

    def test_no_fetch_starts_once_the_time_budget_is_spent(self):
        with mock.patch.object(monitor, "deadline", monitor.time.monotonic() - 1), \
                mock.patch.object(monitor.urllib.request, "urlopen") as urlopen:
            with self.assertRaisesRegex(OSError, "time budget"):
                monitor.fetch(MON + "checkpoint")
        urlopen.assert_not_called()

    def test_get_roots(self):
        with mock.patch.object(monitor, "fetch", Web([]).fetch):
            self.assertEqual(monitor.check_roots(LOG), ([], ["get-roots serves 1 roots"]))
        for body in (b'{"certificates": []}', b"<html>bad gateway</html>", b'{"other": 1}'):
            with self.subTest(body=body), mock.patch.object(monitor, "fetch", lambda url, body=body: body):
                self.assertEqual(checks(monitor.check_roots(LOG)), ["get-roots"])
        with mock.patch.object(monitor, "fetch", side_effect=OSError("connection refused")):
            self.assertEqual(checks(monitor.check_roots(LOG)), ["get-roots"])

    def test_chrome_report(self):
        day = {SUB: {"add-chain": 98.5, "checkpoint": 100.0, "tile": 99.0}}
        self.assertEqual(monitor.check_chrome(LOG, ({}, {})), ([], ["not in Chrome's availability report"]))
        self.assertEqual(monitor.check_chrome(LOG, ({SUB: 99.9}, {SUB: {"add-chain": 100.0}}))[0], [])
        self.assertEqual(checks(monitor.check_chrome(LOG, ({SUB: 99.4}, day))), ["chrome-90d", "chrome-24h-add-chain"])

    def test_chrome_files_are_read_as_published(self):
        files = {"min_uptime.csv": "LOG_URL,UPTIME\n%s,99.8146\n" % SUB,
                 "endpoint_uptime_24h.csv": "LOG_URL,ENDPOINT,UPTIME\n%s,add-chain,98.8858\n%s,tile,100.0000\n" % (SUB, SUB)}
        with mock.patch.object(monitor, "fetch", lambda url: files[url.removeprefix(monitor.CHROME)].encode()):
            floor, day = monitor.chrome()
        self.assertEqual((floor, dict(day)), ({SUB: 99.8146}, {SUB: {"add-chain": 98.8858, "tile": 100.0}}))


    def test_a_bad_row_in_chromes_files_is_skipped_and_a_file_with_none_usable_is_unread(self):
        files = {"min_uptime.csv": "LOG_URL,UPTIME\n%s,99.8146\nhttps://short.example/\nhttps://bad.example/,n/a\n" % SUB,
                 "endpoint_uptime_24h.csv": "LOG_URL,ENDPOINT,UPTIME\n%s,tile,100.0000\n%s,add-chain\n" % (SUB, SUB)}
        with mock.patch.object(monitor, "fetch", lambda url: files[url.removeprefix(monitor.CHROME)].encode()):
            floor, day = monitor.chrome()
        self.assertEqual((floor, dict(day)), ({SUB: 99.8146}, {SUB: {"tile": 100.0}}))
        for body in ("<html>moved</html>\n", "LOG_URL,UPTIME\n", "URL,PERCENT\nhttps://x.example/,99\n"):
            with self.subTest(body=body), mock.patch.object(monitor, "fetch", lambda url, body=body: body.encode()):
                with self.assertRaises(ValueError):
                    monitor.chrome()


class Run(unittest.TestCase):
    """main() end to end, against a json/ folder in a temporary directory and nothing on the network."""

    def run_main(self, logs, web=None, report=({}, {})):
        with tempfile.TemporaryDirectory() as root:
            folder = pathlib.Path(root, "json")
            folder.mkdir()
            (folder / "example-operator.json").write_text("{}")
            for name, log in logs.items():
                (folder / name).write_text(json.dumps(log))
            chrome = mock.Mock(side_effect=report) if isinstance(report, Exception) else mock.Mock(return_value=report)
            with mock.patch.object(monitor, "ROOT", pathlib.Path(root)), mock.patch.object(monitor, "chrome", chrome), \
                    mock.patch.object(monitor, "fetch", (web or Web([])).fetch), mock.patch.object(monitor.time, "sleep"), \
                    mock.patch.object(monitor.time, "time", return_value=NOW), mock.patch.object(monitor, "slack", return_value=True) as slack, \
                    mock.patch.object(monitor.sys, "argv", ["monitor.py"]), mock.patch("builtins.print"):
                with self.assertRaises(SystemExit) as done:
                    monitor.main()
            return done.exception.code, [c.args[0] for c in slack.call_args_list]

    def test_a_healthy_log_passes_and_tells_slack_nothing(self):
        self.assertEqual(self.run_main({"example2027h1.json": {**LOG, "log_spec": "static-ct-api"}}, Web(LEAVES[:300])), (0, []))

    def test_no_log_to_check_fails_and_reaches_slack(self):
        for logs in ({}, {"retired.json": {**LOG, "log_spec": "static-ct-api", "status": "retired"}}):
            with self.subTest(logs=list(logs)):
                code, said = self.run_main(logs)
                self.assertEqual(code, 1)
                self.assertIn("nothing was checked", said[0])

    def test_an_unreadable_chrome_report_does_not_stop_the_log_checks(self):
        for error in (TypeError("float() argument"), ValueError("no row"), OSError("timed out"), monitor.csv.Error("field larger than field limit")):
            with self.subTest(error=error):
                web = Web(LEAVES[:300], note(LEAVES[:300], age=monitor.MAX_AGE + 60))
                code, said = self.run_main({"example2027h1.json": {**LOG, "log_spec": "static-ct-api"}}, web, report=error)
                self.assertEqual(code, 1)
                self.assertIn("has stopped publishing", said[0])


class Slack(unittest.TestCase):
    def tell(self, failing, told, now, delivered=True):
        with mock.patch.object(monitor, "slack", return_value=delivered) as slack:
            return monitor.tell(failing, told, now, 7), [c.args[0] for c in slack.call_args_list]

    def test_slack_hears_a_change_then_daily_then_the_recovery(self):
        failing = {"a.json:age": "A: checkpoint was signed 20 min ago"}
        told, said = self.tell(failing, {}, NOW)
        self.assertEqual((told, len(said)), ({"failing": ["a.json:age"], "at": NOW}, 1))
        self.assertIn("1 check(s) failing\n• A: checkpoint was signed 20 min ago", said[0])
        self.assertEqual(self.tell(failing, told, NOW + 3600), (told, []))
        again, said = self.tell(failing, told, NOW + monitor.REMIND)
        self.assertEqual(again["at"], NOW + monitor.REMIND)
        self.assertIn("(still)", said[0])
        more, said = self.tell({**failing, "b.json:tiles": "B: tiles"}, told, NOW + 3600)
        self.assertEqual((more["failing"], len(said)), (["a.json:age", "b.json:tiles"], 1))
        cleared, said = self.tell({}, told, NOW + 7200)
        self.assertEqual(cleared, {})
        self.assertIn("every check passes again (7 logs)", said[0])
        self.assertEqual(self.tell({}, {}, NOW), ({}, []))

    def test_an_undelivered_message_is_tried_again_next_run(self):
        failing = {"a.json:age": "A: old"}
        self.assertEqual(self.tell(failing, {}, NOW, delivered=False)[0], {})
        told = {"failing": ["a.json:age"], "at": NOW}
        self.assertEqual(self.tell({}, told, NOW + 3600, delivered=False)[0], told)

    def test_the_webhook_is_never_printed(self):
        hook = "https://hooks.slack.example/services/SECRET"
        for hook, error in ((hook, OSError(f"cannot reach {hook}")), ("not a url/SECRET", None)):
            with self.subTest(hook=hook), mock.patch.dict(monitor.os.environ, {"SLACK_WEBHOOK_URL": hook}), \
                    mock.patch.object(monitor.urllib.request, "urlopen", side_effect=error or monitor.urllib.request.urlopen), \
                    mock.patch.object(monitor.time, "sleep"), mock.patch("builtins.print") as out:
                self.assertFalse(monitor.slack("first line\nsecond"))
            self.assertNotIn("SECRET", " ".join(str(a) for c in out.call_args_list for a in c.args))


if __name__ == "__main__":
    unittest.main()
