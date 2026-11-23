#!/usr/bin/env python3
"""Unit tests of ctlog.py against RFC 6962 computed the slow way. Usage: python3 -m unittest discover -s scripts -p 'test_*.py'"""
import base64
import functools
import hashlib
import struct
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import ctlog

# 66000 reaches a level-2 tile (256 * 256 leaves) with a partial tile on every level.
SIZES = [0, 1, 2, 3, 255, 256, 257, 511, 512, 513, 1000, 65535, 65536, 65537, 66000]
LEAVES = [hashlib.sha256(b"leaf %d" % i).digest() for i in range(max(SIZES))]


def tree(leaves):
    """read(level, index, width) over the tiles of a log holding exactly these leaf hashes; a wrong width is a bug in the caller."""
    levels = [leaves]
    while len(levels[-1]) >= ctlog.TILE:
        below = levels[-1]
        full = []
        for i in range(len(below) // ctlog.TILE):
            row = below[ctlog.TILE * i:ctlog.TILE * (i + 1)]
            while len(row) > 1:
                row = [ctlog.node(row[j], row[j + 1]) for j in range(0, len(row), 2)]
            full.append(row[0])
        levels.append(full)

    def read(level, index, width):
        row = levels[level][ctlog.TILE * index:ctlog.TILE * (index + 1)]
        assert width == len(row), f"tile {level}/{index} asked at width {width}, the tree holds {len(row)}"
        return b"".join(row)
    return read


@functools.lru_cache(maxsize=None)
def mth(lo, hi):
    """RFC 6962 section 2.1 over LEAVES[lo:hi], straight from its definition."""
    if hi - lo == 0:
        return ctlog.EMPTY_ROOT
    if hi - lo == 1:
        return LEAVES[lo]
    k = 1 << (hi - lo - 1).bit_length() - 1
    return ctlog.node(mth(lo, lo + k), mth(lo + k, hi))


def signed_note(key, origin, size, root, timestamp, signed_size=None, extra=""):
    """A static-ct-api checkpoint as a log publishes it; signed_size and extra make the malformed ones."""
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    tbs = struct.pack(">BBQQ", 0, 1, timestamp, size if signed_size is None else signed_size) + root
    sig = key.sign(tbs, ec.ECDSA(hashes.SHA256()))
    key_id = hashlib.sha256(origin.encode() + b"\n\x05" + hashlib.sha256(der).digest()).digest()[:4]
    raw = key_id + struct.pack(">QBBH", timestamp, 4, 3, len(sig)) + sig
    return f"{origin}\n{size}\n{base64.b64encode(root).decode()}\n{extra}\n— {origin} {base64.b64encode(raw).decode()}\n"


class TileArithmetic(unittest.TestCase):
    def test_tile_paths(self):
        self.assertEqual(ctlog.tile_path(0, 0, 256), "tile/0/000")
        self.assertEqual(ctlog.tile_path(0, 5, 17), "tile/0/005.p/17")
        self.assertEqual(ctlog.tile_path(1, 1234067, 256), "tile/1/x001/x234/067")

    def test_spans_cover_the_range_with_aligned_subtrees(self):
        for lo, hi in [(0, 0), (0, 1), (0, 13), (5, 13), (256, 66000), (65535, 65537), (1000, 1000)]:
            at = lo
            for height, start in ctlog.spans(lo, hi):
                self.assertEqual(start, at)
                self.assertEqual(start % (1 << height), 0)
                at += 1 << height
            self.assertEqual(at, max(lo, hi))

    def test_roots_equal_rfc6962_for_every_pair_of_sizes(self):
        for new in SIZES:
            read = tree(LEAVES[:new])
            for old in (s for s in SIZES if s <= new):
                with self.subTest(old=old, new=new):
                    self.assertEqual(ctlog.roots(ctlog.Tiles(new, read), old, new), (mth(0, old), mth(0, new)))

    def test_a_rewritten_leaf_changes_the_old_root(self):
        for old, new, changed in [(1, 2, 0), (300, 1000, 7), (300, 1000, 299), (65536, 66000, 40000), (66000, 66000, 65999)]:
            with self.subTest(old=old, new=new, changed=changed):
                forked = list(LEAVES[:new])
                forked[changed] = hashlib.sha256(b"another certificate").digest()
                got_old, _ = ctlog.roots(ctlog.Tiles(new, tree(forked)), old, new)
                self.assertNotEqual(got_old, mth(0, old))

    def test_a_leaf_appended_after_the_old_size_keeps_the_old_root(self):
        forked = list(LEAVES[:1000])
        forked[999] = hashlib.sha256(b"another certificate").digest()
        got_old, got_new = ctlog.roots(ctlog.Tiles(1000, tree(forked)), 300, 1000)
        self.assertEqual(got_old, mth(0, 300))
        self.assertNotEqual(got_new, mth(0, 1000))

    def test_a_longer_tile_is_read_by_its_first_hashes(self):
        # The log grew between the checkpoint and the tile: the full tile stands in for the partial one.
        full = tree(LEAVES[:256])
        self.assertEqual(ctlog.roots(ctlog.Tiles(200, lambda level, index, width: full(level, index, 256)), 100, 200),
                         (mth(0, 100), mth(0, 200)))

    def test_a_short_or_missing_tile_is_an_error(self):
        short = lambda level, index, width: tree(LEAVES[:200])(level, index, width)[:-32]  # noqa: E731
        with self.assertRaises(ctlog.TileError):
            ctlog.roots(ctlog.Tiles(200, short), 0, 200)
        with self.assertRaises(ctlog.TileError):
            ctlog.Tiles(200, tree(LEAVES[:200])).row(0, 1)


class Checkpoints(unittest.TestCase):
    ORIGIN = "log.example/2027h1"

    @classmethod
    def setUpClass(cls):
        cls.key = ec.generate_private_key(ec.SECP256R1())
        der = cls.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        cls.key_der, cls.key_b64 = der, base64.b64encode(der).decode()

    def note(self, size=7, origin=None, **kw):
        return signed_note(self.key, origin or self.ORIGIN, size, b"\x11" * 32, 1_800_000_000_000, **kw)

    def test_a_signed_checkpoint_verifies(self):
        self.assertEqual(ctlog.verify_checkpoint(self.note(), self.ORIGIN, self.key_b64),
                         ctlog.Checkpoint(7, b"\x11" * 32, 1_800_000_000_000))

    def test_a_cosignature_line_is_skipped(self):
        note = self.note() + "— witness.example AAAAAAAAAAAAAAAAAAAAAAAA\n"
        self.assertEqual(ctlog.verify_checkpoint(note, self.ORIGIN, self.key_b64).size, 7)

    def test_what_is_refused(self):
        other = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        cases = {
            "origin is": (self.note(origin="log.example/2027h2"), self.key_b64),
            "does not verify": (self.note(size=8, signed_size=7), self.key_b64),
            "is not origin, size, root hash and signatures": (self.note(extra="extension\n"), self.key_b64),
            "malformed tree size": (self.note().replace("\n7\n", "\n07\n", 1), self.key_b64),
            "has no signature by": (self.note(), base64.b64encode(other).decode()),
        }
        for want, (note, key) in cases.items():
            with self.subTest(want=want), self.assertRaisesRegex(ctlog.CheckpointError, want):
                ctlog.verify_checkpoint(note, self.ORIGIN, key)


if __name__ == "__main__":
    unittest.main()
