#!/usr/bin/env python3
"""Checks every file in json/ against Chrome's CT schemas and against itself.
Usage: scripts/validate.py [--live]   (--live also checks each active static-ct log's checkpoint origin)"""
import base64
import hashlib
import json
import pathlib
import sys
import urllib.request
from datetime import datetime

import jsonschema

ROOT = pathlib.Path(__file__).resolve().parent.parent
JSON_DIR = ROOT / "json"
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

if "--live" in sys.argv:
    for path, log in logs.items():
        if log.get("status") != "active" or log.get("log_spec") != "static-ct-api":
            continue
        sub = log["submission_endpoint"]["url"]
        try:
            origin = fetch(log["monitoring_endpoint"]["url"] + "checkpoint").decode().split("\n", 1)[0]
        except Exception as e:
            fail(f"{path.name}: cannot fetch checkpoint: {e}")
            continue
        # static-ct-api: the checkpoint origin is the submission prefix without scheme or trailing slash.
        want = sub.split("://", 1)[1].rstrip("/")
        if origin != want:
            fail(f"{path.name}: live checkpoint origin is {origin!r}, metadata implies {want!r}")
        else:
            print(f"ok    {path.name}: live checkpoint origin {origin}")

checked = len(operators) + len(logs)
print(f"\n{checked} file(s) checked, {len(failures)} failure(s)")
sys.exit(1 if failures else 0)
