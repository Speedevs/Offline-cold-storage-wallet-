#!/usr/bin/env python3
"""
VaultForge — a GUI companion for SeedForge's offline .vlk vault (Windows/desktop).

It reads and writes the EXACT same VLK1 format as the SeedForge-Wallet CLI:
  - Argon2id (time=3, memory=128 MiB, lanes=4) -> 32-byte key
  - XChaCha20-Poly1305, 24-byte random nonce
  - full header authenticated as AAD (tamper-evident, non-downgradable)
so a vault made here opens in the CLI and vice versa. It also splits/combines
Shamir shares in the same seedforge-shamir-v1 format.

Everything is offline. No network calls anywhere in this file.
First run auto-installs two dependencies (pynacl, argon2-cffi) — both ship as
prebuilt Windows wheels, so no compiler is needed.
"""

import os, sys, struct, json, hashlib, subprocess, datetime

# ---------------------------------------------------------------- deps
def _ensure(pkg, importname=None):
    try:
        __import__(importname or pkg)
    except ImportError:
        print(f"installing {pkg} ...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
        __import__(importname or pkg)

_ensure("pynacl", "nacl")
_ensure("argon2-cffi", "argon2")

import nacl.bindings as sodium
from argon2.low_level import hash_secret_raw, Type

# ---------------------------------------------------------------- VLK1 vault
MAGIC = b"VLK1"
VERSION = 1
KDF_ARGON2ID = 1
ARGON_TIME = 3
ARGON_MEM_KIB = 128 * 1024   # 128 MiB
ARGON_LANES = 4
SALT_LEN = 16
NONCE_LEN = 24               # XChaCha20-Poly1305


def _derive_key(password: bytes, salt: bytes, t: int, mem: int, lanes: int) -> bytes:
    return hash_secret_raw(password, salt, time_cost=t, memory_cost=mem,
                           parallelism=lanes, hash_len=32, type=Type.ID, version=19)


def _marshal_header(salt: bytes, nonce: bytes) -> bytes:
    h = bytearray()
    h += MAGIC
    h += bytes([VERSION, KDF_ARGON2ID])
    h += struct.pack(">I", ARGON_TIME)
    h += struct.pack(">I", ARGON_MEM_KIB)
    h += bytes([ARGON_LANES])
    h += bytes([len(salt)]) + salt
    h += bytes([len(nonce)]) + nonce
    return bytes(h)


def _parse_header(blob: bytes):
    if len(blob) < 6 or blob[:4] != MAGIC:
        raise ValueError("not a .vlk vault (bad magic)")
    ver, kdf = blob[4], blob[5]
    if ver != VERSION:
        raise ValueError(f"unsupported vault version {ver}")
    if kdf != KDF_ARGON2ID:
        raise ValueError(f"unsupported KDF id {kdf}")
    t = struct.unpack(">I", blob[6:10])[0]
    mem = struct.unpack(">I", blob[10:14])[0]
    lanes = blob[14]
    p = 15
    sl = blob[p]; p += 1
    salt = blob[p:p + sl]; p += sl
    nl = blob[p]; p += 1
    nonce = blob[p:p + nl]; p += nl
    header = blob[:p]
    ct = blob[p:]
    return dict(ver=ver, t=t, mem=mem, lanes=lanes, salt=salt, nonce=nonce,
               header=header, ct=ct)


def encrypt_vault(mnemonic: str, note: str, words: int, password: bytes) -> bytes:
    if len(password) < 8:
        raise ValueError("vault password must be at least 8 characters")
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    header = _marshal_header(salt, nonce)
    key = _derive_key(password, salt, ARGON_TIME, ARGON_MEM_KIB, ARGON_LANES)
    try:
        payload = json.dumps({
            "type": "seedforge-vault",
            "mnemonic": mnemonic,
            "words": words,
            "note": note,
            "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }, separators=(",", ":")).encode()
        ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(payload, header, nonce, key)
        return header + ct
    finally:
        # best-effort key wipe
        key = b"\x00" * len(key)


def decrypt_vault(blob: bytes, password: bytes) -> dict:
    h = _parse_header(blob)
    key = _derive_key(password, h["salt"], h["t"], h["mem"], h["lanes"])
    try:
        try:
            pt = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                h["ct"], h["header"], h["nonce"], key)
        except Exception:
            raise ValueError("could not open vault: wrong password or corrupted file")
        payload = json.loads(pt)
        if payload.get("type") != "seedforge-vault":
            raise ValueError("not a SeedForge vault payload")
        return payload
    finally:
        key = b"\x00" * len(key)


def inspect_vault(blob: bytes) -> str:
    h = _parse_header(blob)
    return (f"VLK vault v{h['ver']}\n"
            f"  KDF:        Argon2id (time={h['t']}, memory={h['mem']//1024} MiB, lanes={h['lanes']})\n"
            f"  salt:       {len(h['salt'])} bytes\n"
            f"  nonce:      {len(h['nonce'])} bytes (XChaCha20-Poly1305)\n"
            f"  ciphertext: {len(h['ct'])} bytes (incl. 16-byte auth tag)")

# ---------------------------------------------------------------- BIP-39
_EMBEDDED_WORDS_B64 = "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"

def _load_wordlist():
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (os.path.join(here, "english.txt"),
                 os.path.join(here, "wordlist", "english.txt")):
        if os.path.exists(cand):
            with open(cand, encoding="utf-8") as f:
                w = [x.strip() for x in f if x.strip()]
            if len(w) == 2048:
                return w
    # fall back to the wordlist embedded in this file (fully self-contained)
    try:
        import zlib, base64
        w = zlib.decompress(base64.b64decode(_EMBEDDED_WORDS_B64)).decode().split()
        if len(w) == 2048:
            return w
    except Exception:
        pass
    return None

WORDLIST = _load_wordlist()


def mnemonic_to_entropy(m: str) -> bytes:
    if WORDLIST is None:
        raise ValueError("english.txt wordlist not found next to VaultForge")
    words = m.split()
    if len(words) not in (12, 15, 18, 21, 24):
        raise ValueError("mnemonic must be 12/15/18/21/24 words")
    bits = 0
    for w in words:
        try:
            idx = WORDLIST.index(w)
        except ValueError:
            raise ValueError(f"'{w}' is not in the BIP-39 word list")
        bits = (bits << 11) | idx
    total = len(words) * 11
    ent_bits = total * 32 // 33
    cs_bits = total - ent_bits
    ent = bits >> cs_bits
    cs = bits & ((1 << cs_bits) - 1)
    ent_bytes = ent.to_bytes(ent_bits // 8, "big")
    exp = hashlib.sha256(ent_bytes).digest()[0] >> (8 - cs_bits)
    if exp != cs:
        raise ValueError("mnemonic failed BIP-39 checksum")
    return ent_bytes


def entropy_to_mnemonic(ent: bytes) -> str:
    if WORDLIST is None:
        raise ValueError("english.txt wordlist not found next to VaultForge")
    ENT = len(ent) * 8
    cs_bits = ENT // 32
    cs = hashlib.sha256(ent).digest()[0] >> (8 - cs_bits)
    bits = (int.from_bytes(ent, "big") << cs_bits) | cs
    total = ENT + cs_bits
    out = []
    for i in range(total // 11):
        shift = total - 11 * (i + 1)
        out.append(WORDLIST[(bits >> shift) & 0x7FF])
    return " ".join(out)


def validate_mnemonic(m: str) -> bool:
    try:
        mnemonic_to_entropy(m)
        return True
    except Exception:
        return False

# ---------------------------------------------------------------- Shamir (GF256)
_EXP = [0] * 512
_LOG = [0] * 256
def _init_gf():
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        hi = x & 0x80
        x = (x << 1) & 0xFF
        if hi:
            x ^= 0x1B
        x ^= _EXP[i]           # old_x*2 XOR old_x = old_x*3
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]
_init_gf()

def _mul(a, b):
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]

def _div(a, b):
    if b == 0:
        raise ZeroDivisionError
    if a == 0:
        return 0
    return _EXP[_LOG[a] - _LOG[b] + 255]

def _eval(coeffs, x):
    r = 0
    for c in reversed(coeffs):
        r = _mul(r, x) ^ c
    return r

SHARE_MAGIC = "seedforge-shamir-v1"

def _share_crc(k, x, y: bytes) -> int:
    h = hashlib.sha256(f"{k}|{x}|".encode() + y).digest()
    return h[0]

def split_secret(secret: bytes, k: int, n: int):
    if not (2 <= k <= 255):
        raise ValueError("threshold must be 2..255")
    if not (k <= n <= 255):
        raise ValueError("shares must be >= threshold and <= 255")
    shares = {x: bytearray(len(secret)) for x in range(1, n + 1)}
    for bi, s in enumerate(secret):
        coeffs = [s] + list(os.urandom(k - 1))
        while coeffs[k - 1] == 0:
            coeffs[k - 1] = os.urandom(1)[0]
        for x in range(1, n + 1):
            shares[x][bi] = _eval(coeffs, x)
    out = []
    for x in range(1, n + 1):
        y = bytes(shares[x])
        out.append(f"{SHARE_MAGIC}:{k}:{x}:{y.hex()}:{_share_crc(k, x, y):02x}")
    return out

def _combine_points(xs, ys):
    L = len(ys[0])
    secret = bytearray(L)
    for bi in range(L):
        acc = 0
        for i in range(len(xs)):
            num = den = 1
            for j in range(len(xs)):
                if i == j:
                    continue
                num = _mul(num, xs[j])
                den = _mul(den, xs[i] ^ xs[j])
            acc ^= _mul(ys[i][bi], _div(num, den))
        secret[bi] = acc
    return bytes(secret)

def parse_share(s: str):
    parts = s.strip().split(":")
    if len(parts) != 5 or parts[0] != SHARE_MAGIC:
        raise ValueError("not a valid share")
    k = int(parts[1]); x = int(parts[2]); y = bytes.fromhex(parts[3]); crc = int(parts[4], 16)
    if _share_crc(k, x, y) != crc:
        raise ValueError("share failed integrity check (mistyped?)")
    return k, x, y

def combine_shares(strings):
    xs, ys, k = [], [], None
    for s in strings:
        kk, x, y = parse_share(s)
        k = kk if k is None else k
        if kk != k:
            raise ValueError("shares are from different splits")
        xs.append(x); ys.append(y)
    if len(xs) < k:
        raise ValueError(f"need at least {k} shares, got {len(xs)}")
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share index provided")
    return _combine_points(xs, ys)

# ---------------------------------------------------------------- GUI

# ---------------------------------------------------------------- VaultLock (VLTLOCK3 / legacy VLTLOCK2)
_ensure("cryptography")
import secrets as _secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as _PBKDF2
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF
from cryptography.hazmat.primitives import hashes as _hh

_VL3, _VL2 = b"VLTLOCK3", b"VLTLOCK2"
_VSALT, _VIV, _VWRAP, _VITERS = 16, 12, 48, 600_000
_VB32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

def _vkek(secret, salt, algo=None):
    return _PBKDF2(algorithm=algo or _hh.SHA256(), length=32, salt=salt, iterations=_VITERS).derive(secret.encode("utf-8"))
def _vdkey(mk, info):
    return _HKDF(algorithm=_hh.SHA256(), length=32, salt=b"\x00"*32, info=info).derive(mk)
def _vb32(b):
    bits=val=0; out=""
    for byte in b:
        val=(val<<8)|byte; bits+=8
        while bits>=5: out+=_VB32[(val>>(bits-5))&31]; bits-=5
    if bits: out+=_VB32[(val<<(5-bits))&31]
    return out
def vl_make_recovery_code():
    raw=_vb32(_secrets.token_bytes(16)); return "-".join(raw[i:i+4] for i in range(0,len(raw),4))
def _vnorm(s): return "".join(c for c in (s or "").upper() if c in _VB32)

def vl_encrypt(data, password, rk_secret=None):
    mk=_secrets.token_bytes(32)
    salt_pw,iv_pw=_secrets.token_bytes(_VSALT),_secrets.token_bytes(_VIV)
    wrap_pw=_AESGCM(_vkek(password,salt_pw)).encrypt(iv_pw,mk,None)
    flags,rk_block=0,b""
    if rk_secret:
        flags=1; salt_rk,iv_rk=_secrets.token_bytes(_VSALT),_secrets.token_bytes(_VIV)
        wrap_rk=_AESGCM(_vkek(rk_secret,salt_rk)).encrypt(iv_rk,mk,None)
        rk_block=salt_rk+iv_rk+wrap_rk
    k1,k2=_vdkey(mk,b"VL3-L1"),_vdkey(mk,b"VL3-L2")
    ivd1,ivd2=_secrets.token_bytes(_VIV),_secrets.token_bytes(_VIV)
    layer1=_AESGCM(k1).encrypt(ivd1,data,None); layer2=_AESGCM(k2).encrypt(ivd2,layer1,None)
    return _VL3+bytes([3,flags])+salt_pw+iv_pw+wrap_pw+rk_block+ivd1+ivd2+layer2

def vl_decrypt(blob, secret, via_rk=False):
    if blob[:8]==_VL3: return _vdec3(blob,secret,via_rk)
    if blob[:8]==_VL2:
        if via_rk: raise ValueError("Legacy v2 file — password only.")
        return _vdec2(blob,secret)
    raise ValueError("Not a VaultLock file.")
def _vdec3(u,secret,via_rk):
    if u[8]!=3: raise ValueError("Unsupported version.")
    flags=u[9]; o=10
    salt_pw=u[o:o+_VSALT]; o+=_VSALT
    iv_pw=u[o:o+_VIV]; o+=_VIV
    wrap_pw=u[o:o+_VWRAP]; o+=_VWRAP
    salt_rk=iv_rk=wrap_rk=None
    if flags&1:
        salt_rk=u[o:o+_VSALT]; o+=_VSALT
        iv_rk=u[o:o+_VIV]; o+=_VIV
        wrap_rk=u[o:o+_VWRAP]; o+=_VWRAP
    ivd1=u[o:o+_VIV]; o+=_VIV
    ivd2=u[o:o+_VIV]; o+=_VIV
    ct=u[o:]
    if via_rk:
        if not (flags&1): raise ValueError("This file was locked without a recovery key.")
        mk=_AESGCM(_vkek(_vnorm(secret),salt_rk)).decrypt(iv_rk,wrap_rk,None)
    else:
        mk=_AESGCM(_vkek(secret,salt_pw)).decrypt(iv_pw,wrap_pw,None)
    k1,k2=_vdkey(mk,b"VL3-L1"),_vdkey(mk,b"VL3-L2")
    layer1=_AESGCM(k2).decrypt(ivd2,ct,None)
    return _AESGCM(k1).decrypt(ivd1,layer1,None)
def _vdec2(u,password):
    if u[8]!=1: raise ValueError("Unsupported version.")
    o=9
    salt1=u[o:o+_VSALT]; o+=_VSALT
    salt2=u[o:o+_VSALT]; o+=_VSALT
    iv1=u[o:o+_VIV]; o+=_VIV
    iv2=u[o:o+_VIV]; o+=_VIV
    ct=u[o:]
    k1=_PBKDF2(algorithm=_hh.SHA256(),length=32,salt=salt1,iterations=_VITERS).derive(password.encode())
    k2=_PBKDF2(algorithm=_hh.SHA512(),length=32,salt=salt2,iterations=_VITERS).derive(password.encode())
    layer1=_AESGCM(k2).decrypt(iv2,ct,None)
    return _AESGCM(k1).decrypt(iv1,layer1,None)

def vl_detect(u):
    if u[:4]==b"VLK1": return ("vlk1","SeedForge seed vault (VLK1)",False)
    if u[:8]==_VL3:
        rk=bool(u[9]&1); return ("vltlock3","VaultLock v3"+(" — recovery key available" if rk else ""),rk)
    if u[:8]==_VL2: return ("vltlock2","VaultLock v2 (legacy)",False)
    return ("unknown","Unrecognized file (not a supported .vlk)",False)
import hashlib, hmac

# ----------------------------------------------------------------- secp256k1
_P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_G  = (_Gx, _Gy)

def _inv(x, m): return pow(x, m - 2, m)

def _pt_add(p, q):
    if p is None: return q
    if q is None: return p
    (x1, y1), (x2, y2) = p, q
    if x1 == x2 and (y1 + y2) % _P == 0: return None
    if p == q:
        s = (3 * x1 * x1) * _inv(2 * y1, _P) % _P
    else:
        s = (y2 - y1) * _inv((x2 - x1) % _P, _P) % _P
    x3 = (s * s - x1 - x2) % _P
    y3 = (s * (x1 - x3) - y1) % _P
    return (x3, y3)

def _pt_mul(k, p):
    r = None
    while k:
        if k & 1: r = _pt_add(r, p)
        p = _pt_add(p, p)
        k >>= 1
    return r

def pub_from_priv(priv):
    """returns (x, y) public point"""
    return _pt_mul(priv % _N, _G)

def ser_compressed(pt):
    x, y = pt
    return bytes([2 + (y & 1)]) + x.to_bytes(32, 'big')

def ser_uncompressed_xy(pt):
    x, y = pt
    return x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

# ----------------------------------------------------------------- keccak-256
def _keccak(rate, dsbyte, data, outlen):
    R = [[0] * 5 for _ in range(5)]
    RC = [0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,
          0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,
          0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
          0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,
          0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,
          0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
    rot = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
    M = (1 << 64) - 1
    def rol(v, n): return ((v << n) | (v >> (64 - n))) & M
    def keccak_f():
        for rnd in range(24):
            C = [R[x][0] ^ R[x][1] ^ R[x][2] ^ R[x][3] ^ R[x][4] for x in range(5)]
            D = [C[(x - 1) % 5] ^ rol(C[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5): R[x][y] ^= D[x]
            B = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5): B[y][(2 * x + 3 * y) % 5] = rol(R[x][y], rot[x][y])
            for x in range(5):
                for y in range(5): R[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])
            R[0][0] ^= RC[rnd]
    rate_bytes = rate // 8
    data = bytearray(data)
    data.append(dsbyte)
    while len(data) % rate_bytes: data.append(0)
    data[len(data) - 1] |= 0x80
    for off in range(0, len(data), rate_bytes):
        for i in range(rate_bytes):
            R[(i // 8) % 5][(i // 8) // 5] ^= data[off + i] << (8 * (i % 8))
        # absorb by lanes
        keccak_f()
    out = bytearray()
    while len(out) < outlen:
        for i in range(rate_bytes):
            if len(out) >= outlen: break
            out.append((R[(i // 8) % 5][(i // 8) // 5] >> (8 * (i % 8))) & 0xFF)
        if len(out) < outlen: keccak_f()
    return bytes(out[:outlen])

def keccak256(data):
    return _keccak(1088, 0x01, data, 32)

# ----------------------------------------------------------------- RIPEMD-160
def ripemd160(msg):
    def rol(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    rl=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
        3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
        4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    rr=[5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
        15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
        12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
    sl=[11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
        11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
        9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
    sr=[8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
        9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
        8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]
    kl=[0,0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xA953FD4E]
    kr=[0x50A28BE6,0x5C4DD124,0x6D703EF3,0x7A6D76E9,0]
    def f(j,x,y,z):
        if j<16: return x^y^z
        if j<32: return (x&y)|(~x&z)
        if j<48: return (x|~y)^z
        if j<64: return (x&z)|(y&~z)
        return x^(y|~z)
    h0,h1,h2,h3,h4=0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0
    msg=bytearray(msg); ml=len(msg)*8
    msg.append(0x80)
    while len(msg)%64!=56: msg.append(0)
    msg+= (ml & 0xFFFFFFFFFFFFFFFF).to_bytes(8,'little')
    for off in range(0,len(msg),64):
        X=[int.from_bytes(msg[off+4*i:off+4*i+4],'little') for i in range(16)]
        al,bl,cl,dl,el=h0,h1,h2,h3,h4
        ar,br,cr,dr,er=h0,h1,h2,h3,h4
        for j in range(80):
            t=(rol((al+f(j,bl,cl,dl)+X[rl[j]]+kl[j//16])&0xFFFFFFFF, sl[j])+el)&0xFFFFFFFF
            al,el,dl,cl,bl=el,dl,rol(cl,10),bl,t
            t=(rol((ar+f(79-j,br,cr,dr)+X[rr[j]]+kr[j//16])&0xFFFFFFFF, sr[j])+er)&0xFFFFFFFF
            ar,er,dr,cr,br=er,dr,rol(cr,10),br,t
        t=(h1+cl+dr)&0xFFFFFFFF
        h1=(h2+dl+er)&0xFFFFFFFF
        h2=(h3+el+ar)&0xFFFFFFFF
        h3=(h4+al+br)&0xFFFFFFFF
        h4=(h0+bl+cr)&0xFFFFFFFF
        h0=t
    return b''.join(h.to_bytes(4,'little') for h in (h0,h1,h2,h3,h4))

def hash160(b): return ripemd160(hashlib.sha256(b).digest())

# ----------------------------------------------------------------- base58check
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58check(payload):
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(payload + chk, 'big')
    out = ""
    while n > 0:
        n, r = divmod(n, 58); out = _B58[r] + out
    pad = 0
    for b in payload + chk:
        if b == 0: pad += 1
        else: break
    return "1" * pad + out

# ----------------------------------------------------------------- bech32 (v0)
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def _bech32_polymod(values):
    gen = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25; chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk
def _hrp_expand(hrp): return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
def _bech32_create_checksum(hrp, data):
    values = _hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0,0,0,0,0,0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
def _convertbits(data, frm, to, pad=True):
    acc = 0; bits = 0; ret = []; maxv = (1 << to) - 1
    for b in data:
        acc = (acc << frm) | b; bits += frm
        while bits >= to:
            bits -= to; ret.append((acc >> bits) & maxv)
    if pad and bits: ret.append((acc << (to - bits)) & maxv)
    return ret
def segwit_addr(witver, witprog, hrp="bc"):
    data = [witver] + _convertbits(list(witprog), 8, 5)
    return hrp + "1" + "".join(_CHARSET[d] for d in data + _bech32_create_checksum(hrp, data))

# ----------------------------------------------------------------- BIP-39 seed
def mnemonic_to_seed(mnemonic, passphrase=""):
    import unicodedata
    m = unicodedata.normalize("NFKD", mnemonic)
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase)
    return hashlib.pbkdf2_hmac("sha512", m.encode(), salt.encode(), 2048, 64)

# ----------------------------------------------------------------- BIP-32
def _master(seed):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return int.from_bytes(I[:32], 'big'), I[32:]        # (key, chaincode)
def _ckd(k, c, i):
    if i & 0x80000000:
        data = b'\x00' + k.to_bytes(32, 'big') + i.to_bytes(4, 'big')
    else:
        data = ser_compressed(pub_from_priv(k)) + i.to_bytes(4, 'big')
    I = hmac.new(c, data, hashlib.sha512).digest()
    ki = (int.from_bytes(I[:32], 'big') + k) % _N
    return ki, I[32:]
def derive_path(seed, path):
    k, c = _master(seed)
    for part in path.split("/")[1:]:
        hard = part.endswith("'") or part.endswith("h")
        idx = int(part.rstrip("'h")) + (0x80000000 if hard else 0)
        k, c = _ckd(k, c, idx)
    return k

# ----------------------------------------------------------------- addresses
def _eip55(addr_hex):
    h = keccak256(addr_hex.encode()).hex()
    return "0x" + "".join(c.upper() if int(h[i], 16) >= 8 else c for i, c in enumerate(addr_hex))
def eth_address(priv):
    pub = pub_from_priv(priv)
    raw = keccak256(ser_uncompressed_xy(pub))[-20:]
    return _eip55(raw.hex())
def btc_legacy(priv):
    return b58check(b'\x00' + hash160(ser_compressed(pub_from_priv(priv))))
def btc_segwit(priv):
    return segwit_addr(0, hash160(ser_compressed(pub_from_priv(priv))))

_PATHS = {"eth": "m/44'/60'/0'/0/{i}", "btc": "m/44'/0'/0'/0/{i}", "btc-segwit": "m/84'/0'/0'/0/{i}"}
def derive_address(seed, coin, index):
    path = _PATHS[coin].format(i=index)
    priv = derive_path(seed, path)
    if coin == "eth": return path, eth_address(priv)
    if coin == "btc": return path, btc_legacy(priv)
    if coin == "btc-segwit": return path, btc_segwit(priv)
    raise ValueError("unknown coin")

# ================================================================= GUI
def launch_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    BG="#0b1020"; PANEL="#0f1626"; FG="#e6edf3"; SUB="#8892a6"
    CY="#22d3ee"; GR="#34d399"; MG="#ff2e88"; ENT="#0b1220"; EDGE="#1d2a44"
    MONO=("Consolas",11) if sys.platform.startswith("win") else ("Menlo",11) if sys.platform=="darwin" else ("DejaVu Sans Mono",10)
    UI=("Segoe UI",10) if sys.platform.startswith("win") else ("Helvetica",11)

    root=tk.Tk(); root.title("VaultForge — SeedForge + VaultLock (.vlk)")
    root.configure(bg=BG); root.geometry("760x640"); root.minsize(680,560)

    style=ttk.Style()
    try: style.theme_use("clam")
    except Exception: pass
    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure("TNotebook.Tab", background=PANEL, foreground=SUB, padding=(14,8), font=UI)
    style.map("TNotebook.Tab", background=[("selected","#10192b")], foreground=[("selected",CY)])
    style.configure("TFrame", background=BG)

    def lbl(p,t,fg=SUB,f=UI): return tk.Label(p,text=t,bg=BG,fg=fg,font=f,anchor="w",justify="left")
    def entry(p,show=None,w=44):
        e=tk.Entry(p,bg=ENT,fg=FG,insertbackground=CY,relief="flat",font=MONO,width=w,show=show or "")
        e.configure(highlightthickness=1,highlightbackground=EDGE,highlightcolor=CY); return e
    def txt(p,h=4,w=64):
        t=tk.Text(p,bg=ENT,fg=FG,insertbackground=CY,relief="flat",font=MONO,height=h,width=w,wrap="word")
        t.configure(highlightthickness=1,highlightbackground=EDGE,highlightcolor=CY); return t
    def btn(p,t,cmd,accent=CY):
        return tk.Button(p,text=t,command=cmd,bg=accent,fg="#04121a",activebackground="#0ea5b7",
                         activeforeground="#04121a",relief="flat",font=(UI[0],10,"bold"),padx=12,pady=7,cursor="hand2")
    def gbtn(p,t,cmd):
        return tk.Button(p,text=t,command=cmd,bg=PANEL,fg=CY,activebackground="#10192b",activeforeground=CY,
                         relief="flat",font=(UI[0],9),padx=8,pady=4,cursor="hand2",highlightthickness=1,highlightbackground=EDGE)
    def status(p): return tk.Label(p,text="",bg=BG,fg=GR,font=(UI[0],9),anchor="w",justify="left",wraplength=680)
    def set_st(s,msg,ok=True): s.configure(text=msg,fg=GR if ok else "#ff5f7a")
    def copy(s):
        root.clipboard_clear(); root.clipboard_append(s)

    nb=ttk.Notebook(root); nb.pack(fill="both",expand=True,padx=10,pady=10)
    def tab(name):
        f=tk.Frame(nb,bg=BG); nb.add(f,text=name); f.configure(padx=16,pady=14); return f

    # ---------------- Generate ----------------
    g=tab("Generate")
    lbl(g,"Create a brand-new BIP-39 seed from your OS's secure RNG.",FG,(UI[0],11,"bold")).pack(anchor="w")
    lbl(g,"Do this OFFLINE. Write the words on paper; anyone with them controls the funds.").pack(anchor="w",pady=(2,10))
    wf=tk.Frame(g,bg=BG); wf.pack(anchor="w")
    gwords=tk.IntVar(value=12)
    for v in (12,24):
        tk.Radiobutton(wf,text=f"{v} words",variable=gwords,value=v,bg=BG,fg=FG,selectcolor=PANEL,
                       activebackground=BG,activeforeground=CY,font=UI,highlightthickness=0).pack(side="left",padx=(0,14))
    g_out=txt(g,h=3); g_ent=lbl(g,"",CY,MONO); g_st=status(g)
    def do_gen():
        try:
            nbytes=16 if gwords.get()==12 else 32
            ent=os.urandom(nbytes); m=entropy_to_mnemonic(ent)
            g_out.delete("1.0","end"); g_out.insert("1.0",m)
            g_ent.configure(text="entropy: "+ent.hex())
            set_st(g_st,f"generated {gwords.get()} words · verify offline, back up on paper")
        except Exception as e: set_st(g_st,str(e),False)
    bf=tk.Frame(g,bg=BG); bf.pack(anchor="w",pady=10)
    btn(bf,"Generate new seed",do_gen).pack(side="left")
    gbtn(bf,"Copy",lambda:copy(g_out.get("1.0","end").strip())).pack(side="left",padx=8)
    g_out.pack(anchor="w",fill="x"); g_ent.pack(anchor="w",pady=(6,0)); g_st.pack(anchor="w",pady=(8,0))

    # ---------------- Derive ----------------
    d=tab("Derive")
    lbl(d,"Derive receiving addresses from a seed (BIP-44 / BIP-84).",FG,(UI[0],11,"bold")).pack(anchor="w")
    lbl(d,"Seed phrase").pack(anchor="w",pady=(8,2)); d_m=txt(d,h=3); d_m.pack(anchor="w",fill="x")
    row=tk.Frame(d,bg=BG); row.pack(anchor="w",fill="x",pady=6)
    lbl(row,"Passphrase (optional)").grid(row=0,column=0,sticky="w"); d_pass=entry(row,w=20); d_pass.grid(row=1,column=0,padx=(0,12),sticky="w")
    lbl(row,"Coin").grid(row=0,column=1,sticky="w"); d_coin=tk.StringVar(value="eth")
    om=tk.OptionMenu(row,d_coin,"eth","btc","btc-segwit"); om.configure(bg=ENT,fg=FG,activebackground=PANEL,activeforeground=CY,relief="flat",font=MONO,highlightthickness=1,highlightbackground=EDGE); om["menu"].configure(bg=PANEL,fg=FG)
    om.grid(row=1,column=1,padx=(0,12),sticky="w")
    lbl(row,"Start").grid(row=0,column=2,sticky="w"); d_idx=entry(row,w=6); d_idx.insert(0,"0"); d_idx.grid(row=1,column=2,padx=(0,12))
    lbl(row,"Count").grid(row=0,column=3,sticky="w"); d_cnt=entry(row,w=6); d_cnt.insert(0,"5"); d_cnt.grid(row=1,column=3)
    d_out=txt(d,h=9); d_st=status(d)
    def do_derive():
        try:
            m=" ".join(d_m.get("1.0","end").split())
            if not validate_mnemonic(m): raise ValueError("phrase fails BIP-39 checksum — check the words")
            seed=mnemonic_to_seed(m, d_pass.get())
            coin=d_coin.get(); start=int(d_idx.get()); cnt=max(1,min(20,int(d_cnt.get())))
            lines=[]
            for i in range(start,start+cnt):
                p,a=derive_address(seed,coin,i); lines.append(f"{p:<22} {coin:>10}  {a}")
            d_out.delete("1.0","end"); d_out.insert("1.0","\n".join(lines))
            set_st(d_st,f"derived {cnt} {coin} address(es)")
        except Exception as e: set_st(d_st,str(e),False)
    bf=tk.Frame(d,bg=BG); bf.pack(anchor="w",pady=8)
    btn(bf,"Derive",do_derive).pack(side="left")
    gbtn(bf,"Copy",lambda:copy(d_out.get("1.0","end").strip())).pack(side="left",padx=8)
    d_out.pack(anchor="w",fill="x"); d_st.pack(anchor="w",pady=(8,0))

    # ---------------- Create vault ----------------
    c=tab("Create vault")
    lbl(c,"Encrypt a seed phrase into a SeedForge .vlk (VLK1).",FG,(UI[0],11,"bold")).pack(anchor="w")
    lbl(c,"Argon2id + XChaCha20-Poly1305. Opens in the SeedForge CLI and the Android app.").pack(anchor="w",pady=(2,8))
    lbl(c,"Seed phrase").pack(anchor="w"); c_seed=txt(c,h=3); c_seed.pack(anchor="w",fill="x")
    lbl(c,"Note (optional, stored in clear-ish — not secret)").pack(anchor="w",pady=(6,2)); c_note=entry(c); c_note.pack(anchor="w")
    pr=tk.Frame(c,bg=BG); pr.pack(anchor="w",pady=6)
    lbl(pr,"Password").grid(row=0,column=0,sticky="w"); c_pw=entry(pr,show="*",w=22); c_pw.grid(row=1,column=0,padx=(0,12))
    lbl(pr,"Confirm").grid(row=0,column=1,sticky="w"); c_pw2=entry(pr,show="*",w=22); c_pw2.grid(row=1,column=1)
    c_st=status(c)
    def do_create():
        try:
            m=" ".join(c_seed.get("1.0","end").split())
            if not validate_mnemonic(m): raise ValueError("phrase fails BIP-39 checksum")
            if c_pw.get()!=c_pw2.get(): raise ValueError("passwords do not match")
            if len(c_pw.get())<8: raise ValueError("password must be at least 8 characters")
            path=filedialog.asksaveasfilename(defaultextension=".vlk",initialfile="cold.vlk",filetypes=[("VLK vault","*.vlk")])
            if not path: return
            blob=encrypt_vault(m, c_note.get(), len(m.split()), c_pw.get().encode())
            open(path,"wb").write(blob)
            set_st(c_st,f"created {os.path.basename(path)}")
        except Exception as e: set_st(c_st,str(e),False)
    btn(c,"Create .vlk (VLK1)",do_create).pack(anchor="w",pady=8); c_st.pack(anchor="w")

    # ---------------- Open ----------------
    o=tab("Open")
    lbl(o,"Open any .vlk — the format is detected automatically.",FG,(UI[0],11,"bold")).pack(anchor="w")
    lbl(o,"SeedForge vaults show the seed phrase; VaultLock vaults decrypt back to the original file.").pack(anchor="w",pady=(2,8))
    o_state={"bytes":None,"name":None,"kind":None}
    o_file=lbl(o,"No file chosen.",FG,MONO)
    o_det=lbl(o,"",CY,UI)
    o_rk_var=tk.IntVar(value=0)
    o_rk=tk.Checkbutton(o,text="Use recovery key instead of password",variable=o_rk_var,bg=BG,fg=SUB,selectcolor=PANEL,activebackground=BG,activeforeground=CY,font=UI,highlightthickness=0)
    o_pwl=lbl(o,"Password"); o_pw=entry(o,show="*",w=40)
    o_out=txt(o,h=3); o_st=status(o)
    def choose_open():
        p=filedialog.askopenfilename(filetypes=[("VLK vault","*.vlk"),("All files","*.*")])
        if not p: return
        try:
            b=open(p,"rb").read(); kind,label,rk=vl_detect(b)
            o_state.update(bytes=b,name=os.path.basename(p),kind=kind)
            o_file.configure(text=os.path.basename(p)); set_st(o_det,"Detected: "+label, kind!="unknown"); o_det.configure(fg=CY if kind!="unknown" else "#ff5f7a")
            if kind=="vltlock3" and rk: o_rk.pack(anchor="w",pady=(6,0))
            else: o_rk.pack_forget(); o_rk_var.set(0)
            o_out.delete("1.0","end")
        except Exception as e: set_st(o_st,str(e),False)
    def do_open():
        try:
            if not o_state["bytes"]: raise ValueError("choose a .vlk file first")
            secret=o_pw.get(); kind=o_state["kind"]
            if kind=="vlk1":
                info=decrypt_vault(o_state["bytes"], secret.encode())
                o_out.delete("1.0","end"); o_out.insert("1.0",info["mnemonic"])
                set_st(o_st,f"opened seed vault · {info.get('words','?')} words · note: {info.get('note') or '(none)'}")
            elif kind in ("vltlock3","vltlock2"):
                data=vl_decrypt(o_state["bytes"], secret, bool(o_rk_var.get()))
                default=o_state["name"][:-4] if o_state["name"].lower().endswith(".vlk") else o_state["name"]+".out"
                path=filedialog.asksaveasfilename(initialfile=default,title="Save decrypted file as")
                if not path: return
                open(path,"wb").write(data)
                o_out.delete("1.0","end")
                set_st(o_st,f"unlocked → saved {os.path.basename(path)} ({len(data)} bytes)")
            else: raise ValueError("unrecognized file — not a supported .vlk")
        except Exception as e:
            o_out.delete("1.0","end"); set_st(o_st,str(e),False)
    bf=tk.Frame(o,bg=BG); bf.pack(anchor="w",pady=(8,4))
    gbtn(bf,"Choose .vlk…",choose_open).pack(side="left")
    o_file.pack(anchor="w",pady=(6,0)); o_det.pack(anchor="w",pady=(4,0))
    o_pwl.pack(anchor="w",pady=(8,2)); o_pw.pack(anchor="w")
    bf2=tk.Frame(o,bg=BG); bf2.pack(anchor="w",pady=8)
    btn(bf2,"Open",do_open).pack(side="left")
    gbtn(bf2,"Copy seed",lambda:copy(o_out.get("1.0","end").strip())).pack(side="left",padx=8)
    o_out.pack(anchor="w",fill="x"); o_st.pack(anchor="w",pady=(8,0))

    # ---------------- Lock file ----------------
    L=tab("Lock file")
    lbl(L,"Lock any file into a VaultLock .vlk (VLTLOCK3).",FG,(UI[0],11,"bold")).pack(anchor="w")
    lbl(L,"PBKDF2-600k + dual AES-256-GCM. Opens in VaultLock and the Android app.").pack(anchor="w",pady=(2,8))
    L_state={"path":None}
    L_file=lbl(L,"No file chosen.",FG,MONO)
    def choose_lock():
        p=filedialog.askopenfilename(title="Choose a file to lock")
        if p: L_state["path"]=p; L_file.configure(text=os.path.basename(p))
    pr=tk.Frame(L,bg=BG); pr.pack(anchor="w",pady=6)
    lbl(pr,"Password").grid(row=0,column=0,sticky="w"); L_pw=entry(pr,show="*",w=22); L_pw.grid(row=1,column=0,padx=(0,12))
    lbl(pr,"Confirm").grid(row=0,column=1,sticky="w"); L_pw2=entry(pr,show="*",w=22); L_pw2.grid(row=1,column=1)
    L_rk_var=tk.IntVar(value=0)
    L_rk=tk.Checkbutton(L,text="Also generate a recovery key (backup unlock code, shown once)",variable=L_rk_var,bg=BG,fg=SUB,selectcolor=PANEL,activebackground=BG,activeforeground=CY,font=UI,highlightthickness=0)
    L_code=tk.Label(L,text="",bg=BG,fg=MG,font=MONO,wraplength=680,justify="left")
    L_st=status(L)
    def do_lock():
        try:
            if not L_state["path"]: raise ValueError("choose a file to lock first")
            if L_pw.get()!=L_pw2.get(): raise ValueError("passwords do not match")
            if len(L_pw.get())<8: raise ValueError("password must be at least 8 characters")
            data=open(L_state["path"],"rb").read()
            code=None
            if L_rk_var.get():
                code=vl_make_recovery_code(); blob=vl_encrypt(data, L_pw.get(), _vnorm(code))
            else:
                blob=vl_encrypt(data, L_pw.get())
            default=os.path.basename(L_state["path"])+".vlk"
            path=filedialog.asksaveasfilename(defaultextension=".vlk",initialfile=default,filetypes=[("VLK vault","*.vlk")])
            if not path: return
            open(path,"wb").write(blob)
            L_code.configure(text=("Recovery key (save this — shown once): "+code) if code else "")
            set_st(L_st,f"locked → {os.path.basename(path)}")
        except Exception as e: set_st(L_st,str(e),False)
    bf=tk.Frame(L,bg=BG); bf.pack(anchor="w",pady=(4,4))
    gbtn(bf,"Choose file…",choose_lock).pack(side="left"); L_file.pack(anchor="w",pady=(6,0))
    L_rk.pack(anchor="w",pady=(6,0))
    btn(L,"Lock file → .vlk (VLTLOCK3)",do_lock).pack(anchor="w",pady=8)
    L_code.pack(anchor="w"); L_st.pack(anchor="w",pady=(6,0))

    # ---------------- Shamir ----------------
    s=tab("Shamir")
    lbl(s,"Split a seed into shares · any k of n rebuild it.",FG,(UI[0],11,"bold")).pack(anchor="w")
    lbl(s,"Seed phrase to split").pack(anchor="w",pady=(8,2)); s_seed=txt(s,h=3); s_seed.pack(anchor="w",fill="x")
    kr=tk.Frame(s,bg=BG); kr.pack(anchor="w",pady=6)
    lbl(kr,"threshold k").grid(row=0,column=0,sticky="w"); s_k=entry(kr,w=6); s_k.insert(0,"2"); s_k.grid(row=1,column=0,padx=(0,12))
    lbl(kr,"shares n").grid(row=0,column=1,sticky="w"); s_n=entry(kr,w=6); s_n.insert(0,"3"); s_n.grid(row=1,column=1)
    s_out=txt(s,h=4); s_st=status(s)
    def do_split():
        try:
            m=" ".join(s_seed.get("1.0","end").split())
            if not validate_mnemonic(m): raise ValueError("phrase fails BIP-39 checksum")
            shares=split_secret(mnemonic_to_entropy(m), int(s_k.get()), int(s_n.get()))
            s_out.delete("1.0","end"); s_out.insert("1.0","\n".join(shares))
            set_st(s_st,f"{s_n.get()} shares — any {s_k.get()} rebuild the seed")
        except Exception as e: set_st(s_st,str(e),False)
    bf=tk.Frame(s,bg=BG); bf.pack(anchor="w",pady=6)
    btn(bf,"Split",do_split).pack(side="left"); gbtn(bf,"Copy",lambda:copy(s_out.get("1.0","end").strip())).pack(side="left",padx=8)
    s_out.pack(anchor="w",fill="x"); s_st.pack(anchor="w",pady=(6,0))
    tk.Frame(s,bg=EDGE,height=1).pack(fill="x",pady=12)
    lbl(s,"Combine: paste k shares (one per line)").pack(anchor="w",pady=(0,2)); cm_in=txt(s,h=4); cm_in.pack(anchor="w",fill="x")
    cm_out=txt(s,h=3); cm_st=status(s)
    def do_combine():
        try:
            lines=[x.strip() for x in cm_in.get("1.0","end").splitlines() if x.strip()]
            ent=combine_shares(lines); cm_out.delete("1.0","end"); cm_out.insert("1.0",entropy_to_mnemonic(ent))
            set_st(cm_st,"reconstructed")
        except Exception as e: cm_out.delete("1.0","end"); set_st(cm_st,str(e),False)
    bf=tk.Frame(s,bg=BG); bf.pack(anchor="w",pady=6)
    btn(bf,"Combine",do_combine).pack(side="left"); gbtn(bf,"Copy",lambda:copy(cm_out.get("1.0","end").strip())).pack(side="left",padx=8)
    cm_out.pack(anchor="w",fill="x"); cm_st.pack(anchor="w",pady=(6,0))

    foot=tk.Label(root,text="VaultForge · offline · no network · self-contained",bg=BG,fg=SUB,font=(UI[0],8))
    foot.pack(pady=(0,6))
    root.mainloop()

if __name__ == "__main__":
    launch_gui()
