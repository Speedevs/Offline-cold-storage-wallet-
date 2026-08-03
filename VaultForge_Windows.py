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
def launch_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    BG="#0b0f17"; PANEL="#111725"; FG="#e6edf3"; SUB="#8892a6"
    CYAN="#22d3ee"; GREEN="#34d399"; MAG="#ff2e88"; ENTRYBG="#0d1424"

    root = tk.Tk()
    root.title("VaultForge — SeedForge .vlk vault (offline)")
    root.configure(bg=BG)
    root.geometry("760x620")

    style = ttk.Style()
    try: style.theme_use("clam")
    except Exception: pass
    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure("TNotebook.Tab", background=PANEL, foreground=SUB, padding=(16,8))
    style.map("TNotebook.Tab", background=[("selected", BG)], foreground=[("selected", CYAN)])
    style.configure("TFrame", background=BG)
    style.configure("TLabel", background=BG, foreground=FG)
    style.configure("Sub.TLabel", background=BG, foreground=SUB)
    style.configure("TButton", background=PANEL, foreground=FG, borderwidth=0, padding=8)
    style.map("TButton", background=[("active", "#1b2436")])

    def entry(parent, show=None, width=60):
        e = tk.Entry(parent, show=show, width=width, bg=ENTRYBG, fg=FG,
                     insertbackground=CYAN, relief="flat", highlightthickness=1,
                     highlightbackground="#22304a", highlightcolor=CYAN)
        return e

    def textbox(parent, h=4, width=70):
        t = tk.Text(parent, height=h, width=width, bg=ENTRYBG, fg=FG,
                    insertbackground=CYAN, relief="flat", highlightthickness=1,
                    highlightbackground="#22304a", highlightcolor=CYAN, wrap="word")
        return t

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=14, pady=14)

    # ---- Create tab ----
    f1 = ttk.Frame(nb); nb.add(f1, text="Create vault")
    ttk.Label(f1, text="Seed phrase (BIP-39 words):").pack(anchor="w", pady=(14,4), padx=14)
    c_seed = textbox(f1, h=4); c_seed.pack(fill="x", padx=14)
    ttk.Label(f1, text="Note (optional, stored in the vault, not secret):", style="Sub.TLabel").pack(anchor="w", pady=(12,4), padx=14)
    c_note = entry(f1); c_note.pack(fill="x", padx=14)
    row = ttk.Frame(f1); row.pack(fill="x", padx=14, pady=(12,0))
    ttk.Label(row, text="Password:").grid(row=0, column=0, sticky="w")
    c_pw = entry(row, show="•", width=32); c_pw.grid(row=0, column=1, padx=(8,16))
    ttk.Label(row, text="Confirm:").grid(row=0, column=2, sticky="w")
    c_pw2 = entry(row, show="•", width=32); c_pw2.grid(row=0, column=3, padx=(8,0))
    def do_create():
        m = " ".join(c_seed.get("1.0","end").split())
        if not m:
            return messagebox.showerror("VaultForge", "Enter a seed phrase.")
        if WORDLIST is not None and not validate_mnemonic(m):
            return messagebox.showerror("VaultForge", "That phrase fails the BIP-39 checksum.\nDouble-check the words.")
        pw = c_pw.get().encode(); pw2 = c_pw2.get().encode()
        if pw != pw2:
            return messagebox.showerror("VaultForge", "Passwords do not match.")
        if len(pw) < 8:
            return messagebox.showerror("VaultForge", "Password must be at least 8 characters.")
        path = filedialog.asksaveasfilename(defaultextension=".vlk",
               filetypes=[("VLK vault","*.vlk")], initialfile="cold.vlk")
        if not path: return
        try:
            blob = encrypt_vault(m, c_note.get(), len(m.split()), pw)
            with open(path,"wb") as f: f.write(blob)
            messagebox.showinfo("VaultForge", f"Wrote {len(blob)} bytes to\n{path}\n\nArgon2id + XChaCha20-Poly1305.")
            c_seed.delete("1.0","end"); c_pw.delete(0,"end"); c_pw2.delete(0,"end")
        except Exception as e:
            messagebox.showerror("VaultForge", str(e))
    tk.Button(f1, text="Create .vlk", command=do_create, bg=CYAN, fg="#04121a",
              relief="flat", padx=16, pady=8, activebackground=GREEN).pack(pady=18)

    # ---- Open tab ----
    f2 = ttk.Frame(nb); nb.add(f2, text="Open vault")
    o_path = tk.StringVar()
    prow = ttk.Frame(f2); prow.pack(fill="x", padx=14, pady=(16,4))
    ttk.Label(prow, text="Vault file:").pack(side="left")
    ttk.Label(prow, textvariable=o_path, style="Sub.TLabel").pack(side="left", padx=8)
    def pick_open():
        p = filedialog.askopenfilename(filetypes=[("VLK vault","*.vlk"),("All files","*.*")])
        if p: o_path.set(p)
    ttk.Button(f2, text="Choose .vlk…", command=pick_open).pack(anchor="w", padx=14)
    orow = ttk.Frame(f2); orow.pack(fill="x", padx=14, pady=(12,0))
    ttk.Label(orow, text="Password:").pack(side="left")
    o_pw = entry(orow, show="•", width=36); o_pw.pack(side="left", padx=8)
    o_out = textbox(f2, h=5); o_out.pack(fill="x", padx=14, pady=(14,0)); o_out.configure(state="disabled")
    def do_open():
        if not o_path.get(): return messagebox.showerror("VaultForge","Choose a .vlk file first.")
        try:
            blob = open(o_path.get(),"rb").read()
            payload = decrypt_vault(blob, o_pw.get().encode())
            o_out.configure(state="normal"); o_out.delete("1.0","end")
            o_out.insert("1.0", payload["mnemonic"])
            o_out.configure(state="disabled")
            note = payload.get("note") or "(none)"
            messagebox.showinfo("VaultForge", f"Opened. {payload['words']} words.\nNote: {note}\nCreated: {payload.get('created','?')}")
        except Exception as e:
            messagebox.showerror("VaultForge", str(e))
    def copy_seed():
        s = o_out.get("1.0","end").strip()
        if s:
            root.clipboard_clear(); root.clipboard_append(s)
            messagebox.showinfo("VaultForge","Seed copied to clipboard. Clear it after pasting.")
    brow = ttk.Frame(f2); brow.pack(pady=16)
    tk.Button(brow, text="Open", command=do_open, bg=CYAN, fg="#04121a", relief="flat",
              padx=16, pady=8, activebackground=GREEN).grid(row=0,column=0,padx=6)
    ttk.Button(brow, text="Copy seed", command=copy_seed).grid(row=0,column=1,padx=6)

    # ---- Inspect tab ----
    f3 = ttk.Frame(nb); nb.add(f3, text="Inspect")
    i_out = textbox(f3, h=8); 
    def do_inspect():
        p = filedialog.askopenfilename(filetypes=[("VLK vault","*.vlk"),("All files","*.*")])
        if not p: return
        try:
            info = inspect_vault(open(p,"rb").read())
        except Exception as e:
            info = f"Not a SeedForge vault:\n{e}"
        i_out.configure(state="normal"); i_out.delete("1.0","end"); i_out.insert("1.0", info); i_out.configure(state="disabled")
    ttk.Button(f3, text="Choose .vlk to inspect (no password)…", command=do_inspect).pack(anchor="w", padx=14, pady=(16,10))
    i_out.pack(fill="x", padx=14); i_out.configure(state="disabled")

    # ---- Shamir tab ----
    f4 = ttk.Frame(nb); nb.add(f4, text="Shamir split / combine")
    ttk.Label(f4, text="Split: seed phrase → N shares (any k rebuild it)").pack(anchor="w", padx=14, pady=(14,4))
    s_seed = textbox(f4, h=3); s_seed.pack(fill="x", padx=14)
    knrow = ttk.Frame(f4); knrow.pack(fill="x", padx=14, pady=(8,0))
    ttk.Label(knrow, text="threshold k:").grid(row=0,column=0); s_k = entry(knrow, width=6); s_k.insert(0,"2"); s_k.grid(row=0,column=1,padx=(6,16))
    ttk.Label(knrow, text="shares n:").grid(row=0,column=2); s_n = entry(knrow, width=6); s_n.insert(0,"3"); s_n.grid(row=0,column=3,padx=(6,0))
    s_out = textbox(f4, h=5); 
    def do_split():
        m = " ".join(s_seed.get("1.0","end").split())
        if WORDLIST is None: return messagebox.showerror("VaultForge","english.txt not found — Shamir needs the wordlist.")
        if not validate_mnemonic(m): return messagebox.showerror("VaultForge","Phrase fails BIP-39 checksum.")
        try:
            k=int(s_k.get()); n=int(s_n.get())
            shares = split_secret(mnemonic_to_entropy(m), k, n)
            s_out.configure(state="normal"); s_out.delete("1.0","end"); s_out.insert("1.0","\n".join(shares)); s_out.configure(state="disabled")
        except Exception as e:
            messagebox.showerror("VaultForge", str(e))
    tk.Button(f4, text="Split", command=do_split, bg=CYAN, fg="#04121a", relief="flat", padx=14, pady=6, activebackground=GREEN).pack(anchor="w", padx=14, pady=8)
    s_out.pack(fill="x", padx=14); s_out.configure(state="disabled")
    ttk.Separator(f4, orient="horizontal").pack(fill="x", padx=14, pady=10)
    ttk.Label(f4, text="Combine: paste k shares (one per line) → seed phrase").pack(anchor="w", padx=14, pady=(0,4))
    cm_in = textbox(f4, h=4); cm_in.pack(fill="x", padx=14)
    cm_out = textbox(f4, h=3)
    def do_combine():
        lines = [l.strip() for l in cm_in.get("1.0","end").splitlines() if l.strip()]
        try:
            ent = combine_shares(lines); m = entropy_to_mnemonic(ent)
            cm_out.configure(state="normal"); cm_out.delete("1.0","end"); cm_out.insert("1.0", m); cm_out.configure(state="disabled")
        except Exception as e:
            messagebox.showerror("VaultForge", str(e))
    tk.Button(f4, text="Combine", command=do_combine, bg=CYAN, fg="#04121a", relief="flat", padx=14, pady=6, activebackground=GREEN).pack(anchor="w", padx=14, pady=8)
    cm_out.pack(fill="x", padx=14); cm_out.configure(state="disabled")

    # footer
    foot = tk.Frame(root, bg=BG); foot.pack(fill="x", padx=14, pady=(0,10))
    tk.Label(foot, text="VaultForge · reads & writes SeedForge VLK1 · offline · no network",
             bg=BG, fg=SUB, font=("Segoe UI", 8)).pack(side="left")
    if WORDLIST is None:
        tk.Label(foot, text="  ⚠ english.txt missing: Shamir & checksum disabled",
                 bg=BG, fg=MAG, font=("Segoe UI", 8)).pack(side="left")

    root.mainloop()


# ---------------------------------------------------------------- entry
if __name__ == "__main__":
    # tiny CLI so it's scriptable too: enc / dec / inspect
    if len(sys.argv) >= 2 and sys.argv[1] in ("enc","dec","inspect"):
        import getpass
        cmd = sys.argv[1]
        if cmd == "inspect":
            print(inspect_vault(open(sys.argv[2],"rb").read())); sys.exit(0)
        if cmd == "enc":
            mn = input("seed phrase: ").strip()
            pw = getpass.getpass("password: ").encode()
            out = sys.argv[2] if len(sys.argv) > 2 else "cold.vlk"
            open(out,"wb").write(encrypt_vault(mn, "", len(mn.split()), pw))
            print("wrote", out); sys.exit(0)
        if cmd == "dec":
            pw = getpass.getpass("password: ").encode()
            print(decrypt_vault(open(sys.argv[2],"rb").read(), pw)["mnemonic"]); sys.exit(0)
    launch_gui()
