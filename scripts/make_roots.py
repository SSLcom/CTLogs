#!/usr/bin/env python3
"""Rebuilds crt/<family>/, pem/ and tsv/ from what the family's active shards actually serve.
Usage: scripts/make_roots.py <family>   (e.g. mercury; reads json/<family>*.json)
       scripts/make_roots.py --all      (every family with a json/<family><shard>.json file)"""
import base64
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

ROOT = pathlib.Path(__file__).resolve().parent.parent
SHORT = {"countryName": "C", "stateOrProvinceName": "ST", "localityName": "L",
         "organizationName": "O", "organizationalUnitName": "OU", "commonName": "CN"}

# Families come from the shard files, so CI checks a new family's roots without a workflow edit.
if sys.argv[1:] == ["--all"]:
    families = sorted({m[1] for p in (ROOT / "json").glob("*.json") if (m := re.match(r"([a-z]+)\d", p.name))})
    if not families:
        sys.exit("no json/<family><shard>.json file")
    # Every family runs even after one fails, so one half-finished publish hides no other family's drift.
    sys.exit(max(subprocess.run([sys.executable, __file__, f]).returncode for f in families))

if len(sys.argv) != 2:
    sys.exit("usage: scripts/make_roots.py <family> | --all")
family = sys.argv[1]

shards = [json.loads(p.read_text()) for p in sorted((ROOT / "json").glob(f"{family}*.json"))]
active = [s for s in shards if s.get("status") == "active"]
if not active:
    sys.exit(f"no active json/{family}*.json shard")

sets = {}
for s in active:
    url = s["submission_endpoint"]["url"] + "ct/v1/get-roots"
    with urllib.request.urlopen(url, timeout=30) as r:
        ders = [base64.b64decode(c) for c in json.load(r)["certificates"]]
    sets[url] = {hashlib.sha256(d).hexdigest().upper(): d for d in ders}

# One list per family: shards that disagree mean a half-finished publish, so publish nothing.
first = next(iter(sets.values()))
for url, roots in sets.items():
    if roots.keys() != first.keys():
        sys.exit(f"shards serve different root sets; {url} differs — rerun once they agree")


def name(cert):
    return ", ".join(f"{SHORT.get(a.oid._name, a.oid.dotted_string)}={a.value}" for a in cert.subject)


crt_dir = ROOT / "crt" / family
crt_dir.mkdir(parents=True, exist_ok=True)
for old in crt_dir.glob("*.crt"):
    old.unlink()
pems, rows = [], ["SHA-256(Certificate)\tCA Name"]
for fp in sorted(first):
    cert = x509.load_der_x509_certificate(first[fp])
    pem = cert.public_bytes(Encoding.PEM).decode()
    (crt_dir / f"{fp}.crt").write_text(pem)
    pems.append(pem)
    rows.append(f"{fp}\t{name(cert)}")
(ROOT / "pem" / f"{family}-ca-roots.pem").write_text("".join(pems))
(ROOT / "tsv" / f"{family}-ca-roots.tsv").write_text("\n".join(rows) + "\n")
print(f"{family}: {len(first)} root(s) from {len(sets)} active shard(s)")
