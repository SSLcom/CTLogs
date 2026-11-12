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
import struct
import subprocess
import sys
import urllib.request
from datetime import datetime

import jsonschema
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
ap.add_argument("--live", action="store_true")
ap.add_argument("--base", metavar="REF")
args = ap.parse_args()

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

# A published log's identity never changes: log programs and monitors pin it, and a new key or
# range is a new log. Deleting the file breaks the URL the operator list handed out.
IDENTITY = ("key", "log_id", "submission_endpoint", "monitoring_endpoint", "temporal_interval")


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


def check_checkpoint(name, log, note, origin):
    """C2SP static-ct-api: a signed note whose RFC6962NoteSignature, under the log's key, covers the tree head."""
    body, sep, sig_lines = note.partition("\n\n")
    lines = body.split("\n")
    if not sep or not note.endswith("\n") or len(lines) != 3:
        # The RFC 6962 signature covers only size and root, so extension lines would be unsigned.
        return fail(f"{name}: live checkpoint is not origin, size, root hash and signatures")
    size, root = lines[1], lines[2]
    try:
        root = base64.b64decode(root, validate=True)
    except ValueError:
        root = b""
    if not size.isdigit() or (size != "0" and size.startswith("0")) or len(root) != 32:
        return fail(f"{name}: live checkpoint has a malformed tree size or root hash")
    key_der = base64.b64decode(log["key"])
    key = load_der_public_key(key_der)
    # Key ID: SHA-256(key name || "\n" || 0x05 || log ID)[:4], the key name being the origin.
    key_id = hashlib.sha256(origin.encode() + b"\n\x05" + hashlib.sha256(key_der).digest()).digest()[:4]
    for line in sig_lines.rstrip("\n").split("\n"):
        parts = line.split(" ")
        if len(parts) != 3 or parts[0] != "\u2014" or parts[1] != origin:
            continue  # someone else's line, e.g. a witness cosignature
        try:
            raw = base64.b64decode(parts[2], validate=True)
        except ValueError:
            continue
        if raw[:4] != key_id or len(raw) < 16:
            continue
        # timestamp u64, then a DigitallySigned: hash alg, signature alg, u16 length, signature.
        timestamp, hash_alg, sig_alg, n = struct.unpack(">QBBH", raw[4:16])
        sig = raw[16:]
        if hash_alg != 4 or len(sig) != n:
            return fail(f"{name}: live checkpoint signature is not a SHA-256 DigitallySigned")
        # RFC 6962 TreeHeadSignature: v1, tree_hash, timestamp, tree_size, root hash.
        signed = struct.pack(">BBQQ", 0, 1, timestamp, int(size)) + root
        try:
            if isinstance(key, ec.EllipticCurvePublicKey) and sig_alg == 3:
                key.verify(sig, signed, ec.ECDSA(hashes.SHA256()))
            elif isinstance(key, rsa.RSAPublicKey) and sig_alg == 1:
                key.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
            else:
                return fail(f"{name}: live checkpoint signature algorithm {sig_alg} does not match the published key")
        except InvalidSignature:
            return fail(f"{name}: live checkpoint signature does not verify under the published key")
        return print(f"ok    {name}: live checkpoint {origin} size {size}, signed by the published key")
    fail(f"{name}: live checkpoint has no signature by {origin} with the published key's ID")


if args.live:
    for path, log in logs.items():
        if log.get("status") != "active" or log.get("log_spec") != "static-ct-api":
            continue
        sub = log["submission_endpoint"]["url"]
        try:
            note = fetch(log["monitoring_endpoint"]["url"] + "checkpoint").decode()
        except Exception as e:
            fail(f"{path.name}: cannot fetch checkpoint: {e}")
            continue
        # static-ct-api: the checkpoint origin is the submission prefix without scheme or trailing slash.
        want = sub.split("://", 1)[1].rstrip("/")
        origin = note.split("\n", 1)[0]
        if origin != want:
            fail(f"{path.name}: live checkpoint origin is {origin!r}, metadata implies {want!r}")
            continue
        check_checkpoint(path.name, log, note, want)

checked = len(operators) + len(logs)
print(f"\n{checked} file(s) checked, {len(failures)} failure(s)")
sys.exit(1 if failures else 0)
