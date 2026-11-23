"""What a static-ct-api log publishes and how to check it: the signed checkpoint and the hash tiles.
validate.py and monitor.py share it, so one place decides what a valid checkpoint is."""
import base64
import collections
import hashlib
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

# timestamp: when the log signed it, in milliseconds since the epoch.
Checkpoint = collections.namedtuple("Checkpoint", "size root timestamp")
EMPTY_ROOT = hashlib.sha256(b"").digest()
TILE = 256  # hashes in a full tile; each level's hashes cover 256 of the level below.


class CheckpointError(ValueError):
    """Why a note is not this log's checkpoint; the message completes "<log>: live checkpoint ..."."""


class TileError(ValueError):
    """A tile the tree's size promises is missing or short."""


def origin_of(log):
    """static-ct-api: the checkpoint origin is the submission prefix without scheme or trailing slash."""
    return log["submission_endpoint"]["url"].split("://", 1)[1].rstrip("/")


def verify_checkpoint(note, origin, key_b64):
    """C2SP static-ct-api: a signed note whose RFC6962NoteSignature, under the log's key, covers the tree head."""
    got = note.split("\n", 1)[0]
    if got != origin:
        raise CheckpointError(f"origin is {got!r}, metadata implies {origin!r}")
    body, sep, sig_lines = note.partition("\n\n")
    lines = body.split("\n")
    if not sep or not note.endswith("\n") or len(lines) != 3:
        # The RFC 6962 signature covers only size and root, so extension lines would be unsigned.
        raise CheckpointError("is not origin, size, root hash and signatures")
    size, root = lines[1], lines[2]
    try:
        root = base64.b64decode(root, validate=True)
    except ValueError:
        root = b""
    if not size.isdigit() or (size != "0" and size.startswith("0")) or len(root) != 32:
        raise CheckpointError("has a malformed tree size or root hash")
    key_der = base64.b64decode(key_b64)
    key = load_der_public_key(key_der)
    # Key ID: SHA-256(key name || "\n" || 0x05 || log ID)[:4], the key name being the origin.
    key_id = hashlib.sha256(origin.encode() + b"\n\x05" + hashlib.sha256(key_der).digest()).digest()[:4]
    for line in sig_lines.rstrip("\n").split("\n"):
        parts = line.split(" ")
        if len(parts) != 3 or parts[0] != "—" or parts[1] != origin:
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
            raise CheckpointError("signature is not a SHA-256 DigitallySigned")
        # RFC 6962 TreeHeadSignature: v1, tree_hash, timestamp, tree_size, root hash.
        signed = struct.pack(">BBQQ", 0, 1, timestamp, int(size)) + root
        try:
            if isinstance(key, ec.EllipticCurvePublicKey) and sig_alg == 3:
                key.verify(sig, signed, ec.ECDSA(hashes.SHA256()))
            elif isinstance(key, rsa.RSAPublicKey) and sig_alg == 1:
                key.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
            else:
                raise CheckpointError(f"signature algorithm {sig_alg} does not match the published key")
        except InvalidSignature:
            raise CheckpointError("signature does not verify under the published key") from None
        return Checkpoint(int(size), root, timestamp)
    raise CheckpointError(f"has no signature by {origin} with the published key's ID")


def node(left, right):
    """RFC 6962 interior node."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def tile_path(level, index, width):
    """C2SP tlog-tiles: tile/<L>/<N>, N in 3-digit elements with an x on all but the last, and .p/<W> while partial."""
    parts = []
    while True:
        index, rest = divmod(index, 1000)
        parts.append(f"{rest:03d}")
        if not index:
            break
    parts.reverse()
    path = "/".join(["x" + p for p in parts[:-1]] + parts[-1:])
    return f"tile/{level}/{path}" + ("" if width == TILE else f".p/{width}")


class Tiles:
    """Hashes of complete subtrees of a tree of `size` leaves, from its tiles; read(level, index, width) returns a tile's bytes."""

    def __init__(self, size, read):
        self.size, self.read, self.rows = size, read, {}

    def row(self, level, index):
        if (level, index) not in self.rows:
            width = min(TILE, (self.size >> 8 * level) - TILE * index)
            if width < 1:
                raise TileError(f"a tree of {self.size} has no tile {level}/{index}")
            data = self.read(level, index, width)
            # Longer is a tile that filled since the checkpoint was read: its first hashes are still this tree's.
            if len(data) % 32 or len(data) < 32 * width:
                raise TileError(f"{tile_path(level, index, width)} holds {len(data)} bytes, not {width} hashes")
            self.rows[level, index] = data
        return self.rows[level, index]

    def subtree(self, height, start):
        """Hash of the 2**height leaves from `start`, which must be a multiple of 2**height."""
        level, extra = divmod(height, 8)
        first = start >> 8 * level
        row = self.row(level, first // TILE)
        at = first % TILE
        row = [row[32 * i:32 * i + 32] for i in range(at, at + (1 << extra))]
        while len(row) > 1:
            row = [node(row[i], row[i + 1]) for i in range(0, len(row), 2)]
        return row[0]


def spans(lo, hi):
    """The complete subtrees covering leaves [lo, hi), left to right as (height, start): the largest that fits, each time."""
    out = []
    while lo < hi:
        height = (hi - lo).bit_length() - 1
        if lo:
            height = min(height, (lo & -lo).bit_length() - 1)
        out.append((height, lo))
        lo += 1 << height
    return out


def _push(stack, height, h):
    # Equal heights side by side are siblings, so they merge exactly as the tree's own nodes do.
    while stack and stack[-1][0] == height:
        h = node(stack.pop()[1], h)
        height += 1
    stack.append((height, h))


def _root(stack):
    if not stack:
        return EMPTY_ROOT
    h = stack[-1][1]
    for _, left in reversed(stack[:-1]):
        h = node(left, h)
    return h


def roots(tiles, old_size, new_size):
    """(root at old_size, root at new_size), both from tiles.

    The second is built on the first's own subtrees, never read afresh, so when both equal signed roots
    the larger tree provably holds the smaller as its first old_size leaves: an RFC 6962 consistency check."""
    stack = []
    for height, start in spans(0, old_size):
        _push(stack, height, tiles.subtree(height, start))
    old = _root(stack)
    for height, start in spans(old_size, new_size):
        _push(stack, height, tiles.subtree(height, start))
    return old, _root(stack)
