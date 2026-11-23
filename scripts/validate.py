#!/usr/bin/env python3
"""Checks every file in json/ against Chrome's CT schemas and against itself.
Usage: scripts/validate.py [--live] [--base REF]
  --live      also checks each active static-ct log's live checkpoint: its origin, and its signature by the published key
  --base REF  also refuses a change, against REF, to a published log's key, log_id, endpoints or temporal_interval"""
import argparse
import base64
import hashlib
import json
import pathlib
import subprocess
import sys
import urllib.request
from datetime import datetime

import jsonschema

import ctlog

ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
ap.add_argument("--live", action="store_true")
ap.add_argument("--base", metavar="REF")
args = ap.parse_args()

ROOT = pathlib.Path(__file__).resolve().parent.parent
JSON_DIR = ROOT / "json"
# Where log programs fetch each log's file: main of this repository, as json/sslcom-operator.json hands it out.
PUBLISHED = "https://raw.githubusercontent.com/SSLcom/CTLogs/main/json/"
failures = []


def fail(msg):
    failures.append(msg)
    print(f"FAIL  {msg}")


def fetch(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return r.read()


schemas = {}


def schema(url):
    if url not in schemas:
        schemas[url] = json.loads(fetch(url))
    return schemas[url]


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


operators = {p: json.loads(p.read_text()) for p in sorted(JSON_DIR.glob("*-operator.json"))}
logs = {p: json.loads(p.read_text()) for p in sorted(JSON_DIR.glob("*.json")) if p not in operators}
if not operators:
    fail("no json/*-operator.json file")

listed = set()
for path, op in operators.items():
    try:
        jsonschema.validate(op, schema(op["$schema"]), format_checker=jsonschema.FormatChecker())
    except (jsonschema.ValidationError, KeyError) as e:
        fail(f"{path.name}: {getattr(e, 'message', e)}")
        continue
    for url in op["logs"]:
        name = url.rsplit("/", 1)[-1]
        # The whole URL, not its file name: one pointing at another repo or branch would hand log programs that file.
        if url != PUBLISHED + name:
            fail(f"{path.name} lists {url}; every log URL must be {PUBLISHED}<file>")
        # A URL naming no file here would hand log programs a 404.
        if not (JSON_DIR / name).is_file():
            fail(f"{path.name} lists {url}, but json/{name} does not exist")
        listed.add(name)

families = {}
for path, log in logs.items():
    try:
        jsonschema.validate(log, schema(log["$schema"]), format_checker=jsonschema.FormatChecker())
    except (jsonschema.ValidationError, KeyError) as e:
        fail(f"{path.name}: {getattr(e, 'message', e)}")
        continue
    if path.name not in listed:
        fail(f"{path.name} is in no operator file, so no log program will ever read it")
    # The log ID is the SHA-256 of the key; a mismatch means one of them was pasted wrong.
    if hashlib.sha256(base64.b64decode(log["key"])).digest() != base64.b64decode(log["log_id"]):
        fail(f"{path.name}: log_id is not the SHA-256 of key")
    for ep in ("submission_endpoint", "monitoring_endpoint"):
        if log["log_spec"] == "static-ct-api" and not log[ep]["url"].endswith("/"):
            fail(f"{path.name}: {ep} must end with '/'")
    families.setdefault(log["friendly_name"].split()[0], []).append((path.name, log))

# Chrome requires a family's expiry ranges to be contiguous, each 3 to 12 months.
for family, members in families.items():
    members.sort(key=lambda m: ts(m[1]["temporal_interval"]["start_inclusive"]))
    for (prev_name, prev), (name, cur) in zip(members, members[1:]):
        if prev["temporal_interval"]["end_exclusive"] != cur["temporal_interval"]["start_inclusive"]:
            fail(f"{family}: gap or overlap between {prev_name} and {name}")
    for name, log in members:
        ti = log["temporal_interval"]
        days = (ts(ti["end_exclusive"]) - ts(ti["start_inclusive"])).days
        if not 89 <= days <= 366:
            fail(f"{name}: expiry range is {days} days, outside Chrome's 3-12 months")

# A published log's identity never changes: log programs and monitors pin it, and a new key or
# range is a new log. Deleting the file breaks the URL the operator list handed out.
IDENTITY = ("key", "log_id", "submission_endpoint", "monitoring_endpoint", "temporal_interval", "mmd_seconds", "log_spec")


def git(*argv):
    return subprocess.run(["git", "-C", str(ROOT), *argv], check=True, capture_output=True, text=True).stdout


if args.base:
    try:
        git("rev-parse", "--verify", "--quiet", f"{args.base}^{{commit}}")
        published = git("ls-tree", "--name-only", args.base, "json/").split()
    except subprocess.CalledProcessError:
        # A gate: an unreadable base must fail, never read as "nothing published".
        fail(f"--base {args.base} is not a commit in this checkout; fetch it")
        published = []
    for name in published:
        path = ROOT / name
        if not name.endswith(".json") or path.name.endswith("-operator.json"):
            continue
        old = json.loads(git("show", f"{args.base}:{name}"))
        new = logs.get(path)
        if new is None:
            fail(f"{path.name} is published at {args.base} and deleted here; retire a log by its status")
            continue
        for field in IDENTITY:
            if old.get(field) != new.get(field):
                fail(f"{path.name}: {field} differs from {args.base} ({old.get(field)!r} -> {new.get(field)!r}); a published log's identity never changes")


if args.live:
    for path, log in logs.items():
        if log.get("status") != "active" or log.get("log_spec") != "static-ct-api":
            continue
        origin = ctlog.origin_of(log)
        try:
            note = fetch(log["monitoring_endpoint"]["url"] + "checkpoint").decode()
        except Exception as e:
            fail(f"{path.name}: cannot fetch checkpoint: {e}")
            continue
        try:
            cp = ctlog.verify_checkpoint(note, origin, log["key"])
        except ctlog.CheckpointError as e:
            fail(f"{path.name}: live checkpoint {e}")
            continue
        print(f"ok    {path.name}: live checkpoint {origin} size {cp.size}, signed by the published key")

checked = len(operators) + len(logs)
print(f"\n{checked} file(s) checked, {len(failures)} failure(s)")
sys.exit(1 if failures else 0)
