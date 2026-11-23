#!/usr/bin/env python3
"""Checks every log in json/ from outside, as a monitor would, and tells Slack when a check starts or stops failing.
Usage: scripts/monitor.py [--state FILE] [--slack-test]
  --state FILE   remembers each log's last checkpoint and what Slack was told; without it no run is compared with the one before
  --slack-test   also posts one test message, to prove $SLACK_WEBHOOK_URL still delivers

Per active log: the checkpoint is signed by the published key and recent, the tiles hash to its root, the tree still
starts with the checkpoint the last run saw, get-roots answers, and Chrome's published availability is above the line.
A readonly log keeps the signature, tile and consistency checks. Exits 1 when any check fails."""
import argparse
import collections
import csv
import http.client
import io
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

import ctlog

ROOT = pathlib.Path(__file__).resolve().parent.parent
# TesseraCT re-signs every 30s even with nothing new, so ten minutes is a log that stopped publishing, not a quiet one.
MAX_AGE = 10 * 60
# A few minutes of clock difference is ordinary; more is a signer whose clock is wrong, which a zero age would hide.
MAX_AHEAD = 5 * 60
# While the same checks keep failing, Slack hears once a day, not once a run.
REMIND = 24 * 3600
# The job is killed at 15 minutes and a killed run tells nobody: fetches stop here, so each unread log is reported instead.
BUDGET = 10 * 60
deadline = None
# Chrome's compliance monitor: per-log minimum over 90 days, and per-endpoint over its last 24 hours, republished daily.
CHROME = "https://www.gstatic.com/ct/compliance/"
# Chrome's policy needs 99% over 90 days; the line sits above it so there is time to act.
CHROME_MIN_90D = 99.5
CHROME_MIN_24H = 99.0
# Chrome's files are not ours to keep up: only a day of runs without them is worth a message.
CHROME_UNREAD_RUNS = 24
LIMIT = 16 << 20


class Moved(Exception):
    """The log grew past the checkpoint in hand and deleted a partial tile it named."""


def fetch(url, attempts=3):
    for i in range(attempts):
        left = 30 if deadline is None else deadline - time.monotonic()
        if left <= 0:
            raise OSError("the monitor's time budget ran out before this was read")
        try:
            with urllib.request.urlopen(url, timeout=min(30, left)) as r:
                return r.read(LIMIT)
        except urllib.error.HTTPError as e:
            # An answer, not a blip: the caller decides what a missing object means.
            if e.code in (403, 404):
                raise
            err = e
        except OSError as e:
            err = e
        except http.client.HTTPException as e:
            # A body cut short is not an OSError; callers treat every unreadable answer alike.
            err = OSError(f"{type(e).__name__}: {e}")
        if i + 1 < attempts:
            time.sleep(3 * (i + 1))
    raise err


def reader(mon):
    def read(level, index, width):
        path = ctlog.tile_path(level, index, width)
        try:
            return fetch(mon + path)
        except urllib.error.HTTPError as e:
            if width == ctlog.TILE or e.code not in (403, 404):
                raise ctlog.TileError(f"cannot read {path}: {e}") from None
        except OSError as e:
            raise ctlog.TileError(f"cannot read {path}: {e}") from None
        # TesseraCT deletes a tile's partials only once it is full, so the full tile is there and starts with the same hashes.
        try:
            return fetch(mon + ctlog.tile_path(level, index, ctlog.TILE))
        except OSError:
            raise Moved(path) from None
    return read


def iso(ms):
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def span(seconds):
    return f"{seconds:.0f}s" if seconds < 120 else f"{seconds / 60:.0f} min" if seconds < 7200 else f"{seconds / 3600:.1f} h"


def check_tree(log, last_note, now):
    """One log's checkpoint and tiles: ([(check, problem)], [facts], the checkpoint to remember, evidence to print)."""
    origin, mon, active = ctlog.origin_of(log), log["monitoring_endpoint"]["url"], log["status"] == "active"
    prev = None
    if last_note:
        try:
            prev = ctlog.verify_checkpoint(last_note, origin, log["key"])
        except ctlog.CheckpointError as e:
            # Signed state is self-proving: a remembered note that no longer verifies is dropped, never trusted.
            print(f"note  {log['friendly_name']}: the remembered checkpoint {e}; comparing with nothing this run")
            last_note = None
    for _ in range(3):
        try:
            note = fetch(mon + "checkpoint").decode()
        except (OSError, UnicodeDecodeError) as e:
            return [("checkpoint", f"cannot fetch the checkpoint: {e}")], [], last_note, []
        try:
            cp = ctlog.verify_checkpoint(note, origin, log["key"])
        except ctlog.CheckpointError as e:
            return [("checkpoint", f"checkpoint {e}")], [], last_note, [note]
        problems, facts, keep, evidence = [], [f"size {cp.size}"], last_note, []
        age = now - cp.timestamp / 1000
        if age < -MAX_AHEAD:
            problems.append(("age", f"checkpoint is dated {iso(cp.timestamp)}, {span(-age)} in the future: the signer's clock is wrong"))
        elif active and age > MAX_AGE:
            problems.append(("age", f"checkpoint was signed {span(age)} ago, at {iso(cp.timestamp)}: the log has stopped publishing (limit {span(MAX_AGE)})"))
        else:
            facts.append(f"signed {span(max(age, 0))} ago by the published key")
        shrank = prev is not None and cp.size < prev.size
        if shrank:
            problems.append(("consistency", f"tree shrank from {prev.size} to {cp.size} entries since {iso(prev.timestamp)}"))
            evidence = [last_note, note]
        tiles = ctlog.Tiles(cp.size, reader(mon))
        try:
            old_root, new_root = ctlog.roots(tiles, 0 if shrank or prev is None else prev.size, cp.size)
        except Moved:
            # CloudFront may repeat the same checkpoint for 30s, so an immediate retry would read the same missing tile.
            time.sleep(15)
            continue
        except ctlog.TileError as e:
            return problems + [("tiles", str(e))], facts, keep, evidence
        if new_root != cp.root:
            problems.append(("tiles", f"the tiles do not hash to the signed root at size {cp.size}"))
            evidence = evidence or [note]
        elif prev is not None and not shrank and old_root != prev.root:
            problems.append(("consistency", f"the tree of {cp.size} no longer starts with the {prev.size} entries signed at {iso(prev.timestamp)}: history changed"))
            evidence = [last_note, note]
        elif not shrank:
            # Only a checkpoint that passed is remembered, so a failure is compared with the last good one until it is resolved.
            keep = note
            facts.append(f"{len(tiles.rows)} tile(s) hash to its root" if cp.size else "empty tree, so no tile yet")
            if prev is not None:
                facts.append(f"extends the {prev.size} entries signed at {iso(prev.timestamp)}")
        return problems, facts, keep, evidence
    return [("tiles", "three checkpoints in a row named a partial tile that could not be read")], [], last_note, []


def check_roots(log):
    url = log["submission_endpoint"]["url"] + "ct/v1/get-roots"
    try:
        n = len(json.loads(fetch(url))["certificates"])
    except (OSError, ValueError, KeyError, TypeError) as e:
        return [("get-roots", f"get-roots does not answer with its roots: {e}")], []
    return ([], [f"get-roots serves {n} roots"]) if n else ([("get-roots", "get-roots serves no root")], [])


def chrome():
    """({submission URL: 90-day minimum}, {submission URL: {endpoint: last 24 hours}}), in percent, as Chrome publishes them."""
    def rows(name):
        return csv.DictReader(io.StringIO(fetch(CHROME + name).decode()))

    def pct(row):
        # One bad row is skipped, never fatal: DictReader fills a short row with None, and float(None) is a TypeError.
        try:
            return float(row["UPTIME"])
        except (KeyError, TypeError, ValueError):
            return None

    floor = {r["LOG_URL"]: v for r in rows("min_uptime.csv") if r.get("LOG_URL") and (v := pct(r)) is not None}
    if not floor:
        # A file with no usable row counts as unread, or every log would read as "not in Chrome's report" for good.
        raise ValueError("min_uptime.csv has no row that can be read")
    day = collections.defaultdict(dict)
    for r in rows("endpoint_uptime_24h.csv"):
        if r.get("LOG_URL") and r.get("ENDPOINT") and (v := pct(r)) is not None:
            day[r["LOG_URL"]][r["ENDPOINT"]] = v
    return floor, day


def check_chrome(log, report):
    url = log["submission_endpoint"]["url"]
    floor, day = report
    if url not in floor:
        return [], ["not in Chrome's availability report"]
    problems = []
    if floor[url] < CHROME_MIN_90D:
        problems.append(("chrome-90d", f"Chrome measures {floor[url]:.2f}% availability over 90 days; its policy needs 99% (line at {CHROME_MIN_90D}%)"))
    for endpoint, pct in sorted(day.get(url, {}).items()):
        if pct < CHROME_MIN_24H:
            problems.append((f"chrome-24h-{endpoint}", f"Chrome measured {pct:.2f}% on {endpoint} over its last 24 hours (line at {CHROME_MIN_24H}%)"))
    return problems, [f"Chrome measures {floor[url]:.2f}% over 90 days"]


def slack(text):
    """True when Slack took the message; the webhook is a secret, so it is never printed."""
    hook = os.environ.get("SLACK_WEBHOOK_URL")
    if not hook:
        print(f"::warning::SLACK_WEBHOOK_URL is unset, so nobody was told: {text.splitlines()[0]}")
        return False
    for i in range(3):
        try:
            req = urllib.request.Request(hook, json.dumps({"text": text}).encode(), {"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=20):
                print("Posted to Slack.")
                return True
        except Exception as e:  # noqa: BLE001
            # Only the type: urllib's messages can quote the URL, and the URL is the secret.
            err = type(e).__name__
            time.sleep(3 * (i + 1))
    print(f"::warning::Slack did not take the message ({err}), so nobody was told: {text.splitlines()[0]}")
    return False


def tell(failing, told, now, checked, link=""):
    """What Slack has been told after this run: it hears when the failing checks change, daily while they last, and when they clear."""
    names = sorted(failing)
    if failing and (names != told.get("failing") or now - told.get("at", 0) >= REMIND):
        again = " (still)" if names == told.get("failing") else ""
        lines = "\n".join(f"• {failing[n]}" for n in names)
        if slack(f":rotating_light: CT log monitor: {len(failing)} check(s) failing{again}\n{lines}{link}"):
            return {"failing": names, "at": now}
    elif not failing and told.get("failing"):
        if slack(f":white_check_mark: CT log monitor: every check passes again ({checked} logs).{link}"):
            return {}
    # An undelivered message leaves this as it was, so the next run tries again.
    return told


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--state", type=pathlib.Path)
    ap.add_argument("--slack-test", action="store_true")
    args = ap.parse_args()
    global deadline
    deadline = time.monotonic() + BUDGET
    now = time.time()
    state = {}
    if args.state and args.state.is_file():
        try:
            state = json.loads(args.state.read_text())
        except ValueError:
            print(f"note  {args.state} is not JSON; starting with nothing remembered")
    notes = state.get("checkpoints", {})

    logs = {p.name: json.loads(p.read_text()) for p in sorted((ROOT / "json").glob("*.json")) if not p.name.endswith("-operator.json")}
    logs = {name: log for name, log in logs.items() if log.get("log_spec") == "static-ct-api" and log.get("status") in ("active", "readonly")}
    try:
        report, unread = chrome(), 0
    except (OSError, ValueError, KeyError, TypeError, csv.Error) as e:
        # csv.Error too: a field past the reader's size limit is neither a ValueError nor an OSError.
        report, unread = None, state.get("chrome_unread", 0) + 1
        print(f"note  cannot read Chrome's availability report ({e}); {unread} run(s) in a row")

    failing = {}
    if not logs:
        # Nothing to check is a broken monitor, not a clean run: json/ moved, or no log is active or readonly any more.
        failing["monitor:no-logs"] = "no active or readonly static-ct-api log found in json/, so nothing was checked"
        print(f"FAIL  {failing['monitor:no-logs']}")
    for name, log in logs.items():
        title, evidence = log["friendly_name"], []
        try:
            problems, facts, keep, evidence = check_tree(log, notes.get(name), now)
            if keep:
                notes[name] = keep
            else:
                notes.pop(name, None)
            if log["status"] == "active":
                for more_problems, more_facts in (check_roots(log), check_chrome(log, report) if report else ([], [])):
                    problems += more_problems
                    facts += more_facts
        except Exception as e:  # noqa: BLE001
            # A bug here must reach Slack like any failing check, or a broken monitor reads as a healthy log.
            problems = [("monitor", f"the check itself failed ({type(e).__name__}: {e}), so this log went unchecked")]
        for check, problem in problems:
            failing[f"{name}:{check}"] = f"{title}: {problem}"
            print(f"FAIL  {title}: {problem}")
        if not problems:
            print(f"ok    {title}: {'; '.join(facts)}")
        for note in evidence:
            # The notes are signed, so two that disagree are the proof an incident report needs.
            print(f"----- {title}: signed checkpoint, for the record -----\n{note}-----")
    if unread >= CHROME_UNREAD_RUNS:
        failing["chrome:unread"] = f"Chrome's availability report has been unreadable for {unread} runs: {CHROME}min_uptime.csv"
        print(f"FAIL  {failing['chrome:unread']}")

    link = f"\n<{os.environ['RUN_URL']}|Open the run>" if os.environ.get("RUN_URL") else ""
    told = tell(failing, state.get("told", {}), now, len(logs), link)
    if args.slack_test:
        slack(f":white_check_mark: CT log monitor: test message. {len(logs)} logs checked, {len(failing)} check(s) failing.{link}")

    if args.state:
        args.state.parent.mkdir(parents=True, exist_ok=True)
        args.state.write_text(json.dumps({"checkpoints": notes, "told": told, "chrome_unread": unread}, indent=1) + "\n")
    print(f"\n{len(logs)} log(s) checked, {len(failing)} check(s) failing")
    sys.exit(1 if failing else 0)


if __name__ == "__main__":
    main()
