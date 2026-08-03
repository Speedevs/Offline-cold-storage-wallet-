# SeedForge

**An offline BIP-39 seed phrase generator.** Two independent, auditable
implementations that share nothing but the algorithm:

| Target | Language | Deliverable |
|---|---|---|
| Windows / macOS / Linux | Go (stdlib only) | native console binaries |
| Android | Java (no frameworks) | signed `SeedForge.apk` |

There is **no HTML, no JavaScript, no web layer, and no network code anywhere.**

---

## Why this is secure

Security here is not a slogan — it is a set of properties you can check yourself:

1. **It cannot reach the network — by construction, not by policy.**
   - *Desktop:* the Go source imports no `net` package. Run
     `go list -deps ./src/desktop | grep net` and you get nothing. A binary that
     never links a socket API cannot phone home.
   - *Android:* the manifest requests **zero permissions** — in particular no
     `INTERNET`. The Android sandbox then physically forbids the process from
     opening a socket. Verify with `aapt dump permissions SeedForge.apk`
     (output: none).

2. **Real randomness.** Entropy comes only from the OS CSPRNG
   (`crypto/rand` → `getrandom(2)`/`BCryptGenRandom`; `SecureRandom` on Android).
   You can optionally fold in your own dice rolls / coin flips — see below.

3. **Nothing is stored.** No files written, no logs, no clipboard, no telemetry.
   The phrase exists only on screen for as long as you leave it there. On
   Android, `FLAG_SECURE` blocks screenshots, screen recording, and the
   recent-apps thumbnail.

4. **The wordlist can't be swapped.** The official 2048-word BIP-39 English list
   is embedded and its SHA-256
   (`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`) is
   checked at startup. A tampered build refuses to run.

5. **Provably correct.** Both implementations are validated against the official
   BIP-39 / Trezor test vectors (`SeedForge... -selftest` on desktop). Wrong math
   would fail the self-test.

6. **Zero third-party dependencies.** The desktop build pulls in *nothing* beyond
   the Go standard library, so there is no supply chain to trust and the build is
   reproducible offline.

**What it does NOT protect against — read this.** No generator can save you from
a compromised operating system. Keyloggers, screen recorders, RAM scrapers,
malicious drivers, and shoulder-surfers / cameras are all outside its control.
For anything holding real value:

- Run it on a clean machine, ideally one that is **offline** (Wi-Fi/Ethernet
  physically off) or wiped afterward — a spare laptop in airplane mode, or a
  live-USB Linux session.
- **Write the words on paper (or stamp them into metal).** Never type them into
  any website, wallet "import" box, chat, email, cloud note, or photo.
- Keep two copies in separate secure places. Anyone with the words owns the
  funds; there is no reset.

---

## Run it

### Windows
Double-click **`SeedForge-windows-amd64.exe`** (use the `-arm64` build on ARM
Windows). A console window opens with a menu. Windows SmartScreen may warn
because the binary isn't purchased-code-signed — choose *More info → Run anyway*,
or build it yourself (below).

### macOS
```bash
chmod +x SeedForge-macos-arm64        # or -amd64 on Intel
./SeedForge-macos-arm64
```
Gatekeeper may block an unsigned binary: *System Settings → Privacy & Security →
Open Anyway*, or run `xattr -d com.apple.quarantine ./SeedForge-macos-arm64`.

### Linux
```bash
chmod +x SeedForge-linux-amd64
./SeedForge-linux-amd64
```

### Android
Copy **`SeedForge.apk`** to the phone and open it. Allow "install from unknown
sources" for your file manager when prompted. Best practice: **put the phone in
airplane mode first** and leave it there. The app itself has no network
permission regardless.

---

## Command-line usage (desktop)

Running with no arguments launches the interactive menu. Flags are available for
power users:

```
SeedForge -words 24              # print a 24-word phrase and exit
SeedForge -words 12 -entropy     # also show the raw entropy hex
SeedForge -words 24 -seed        # also derive the 64-byte BIP-39 seed
SeedForge -extra "5 3 6 1 dice"  # fold your own entropy into the OS randomness
SeedForge -passphrase "..." -seed  # 25th-word passphrase affects the seed
SeedForge -verify "word1 word2 ... word12"   # validate an existing phrase
SeedForge -selftest              # run BIP-39 test vectors and exit
```

Word counts and their entropy: `12→128-bit, 15→160, 18→192, 21→224, 24→256`.

### Extra entropy (optional, for the paranoid)
If you don't fully trust the machine's RNG, add your own randomness. The tool
computes `entropy = SHA-512(os_random ‖ your_input)`. Because SHA-512 is a strong
mixing function, the result is unpredictable if **either** source is — so a
backdoored OS RNG can't determine your phrase, and weak human input can't weaken
a good OS RNG. Roll a few dice, flip coins, or mash the keyboard.

---

## Build from source

If you don't want to trust the prebuilt binaries, build them yourself — this is
the strongest guarantee.

### Desktop (needs only Go)
```bash
cd src/desktop
go run . -selftest      # confirm the vectors pass
bash build.sh           # cross-compiles Windows/macOS/Linux into ./out
```

### Android (needs a JDK + Android SDK build-tools, no Gradle/Android Studio)
```bash
# one-time SDK setup:
sdkmanager "platform-tools" "platforms;android-34" "build-tools;34.0.0"

cd src/android
ANDROID_HOME=/path/to/android-sdk JAVA_HOME=/path/to/jdk bash build.sh
# -> build/SeedForge.apk  (signed, verified with apksigner)
```
The bundled APK is signed with a project key (alias `seedforge`) purely so it can
install; it is **not** a trusted identity. For your own copy, rebuild and let the
script generate a fresh keystore, or supply your own.

---

---

## SeedForge Wallet — HD derivation + backup (desktop)

A **second, separate binary** (`SeedForge-Wallet-*`) turns a mnemonic into
actual wallet addresses and provides two backup mechanisms. It is kept separate
on purpose: the generator above stays dependency-free, while this tool uses the
vetted `btcec` secp256k1 library and `x/crypto` (Argon2id, XChaCha20-Poly1305)
where rolling your own would be reckless. It has **no network code either** —
secrets only ever print to your local terminal, and only when you ask.

Everything below is verified against official test vectors — run
`SeedForge-Wallet... selftest` to see BIP-32, BIP-44/84, ETH, BTC, Shamir, and
the vault all checked in one shot.

### Derive addresses (BIP-44 / BIP-84)
```bash
SeedForge-Wallet derive -mnemonic "word1 ... word24" -coin eth -count 5
SeedForge-Wallet derive -mnemonic "..." -coin btc-segwit          # bc1... (BIP-84)
SeedForge-Wallet derive -mnemonic "..." -coin btc                 # 1...  legacy (BIP-44)
# add -show-secret to also print private keys / WIF (only on a screen nobody sees)
```

### Backup option A — encrypted `.vlk` vault
A password-protected file, safe for cloud/USB, useless without the password
(Argon2id + XChaCha20-Poly1305). Full spec in `VAULT_FORMAT.md`.
```bash
SeedForge-Wallet vault-create -mnemonic "..." -note "cold storage" -out backup.vlk
SeedForge-Wallet vault-inspect -in backup.vlk     # shows KDF params, no password needed
SeedForge-Wallet vault-open    -in backup.vlk      # prompts for password, prints phrase
```

### Backup option B — Shamir N-of-M split
Split the seed into `N` shares where any `K` reconstruct it and `K-1` reveal
nothing. Give shares to different people/locations; no single one is a point of
compromise or failure.
```bash
SeedForge-Wallet split -mnemonic "..." -threshold 3 -shares 5   # prints 5 shares
# later, with any 3 of them:
SeedForge-Wallet combine -share "seedforge-shamir-v1:3:1:..." -share "...:3:4:..." -share "...:3:5:..."
```
Each share carries a checksum, so a mistyped share is rejected rather than
silently reconstructing the wrong secret. (This is a plain documented split, not
SLIP-39 — it round-trips only with this tool.)

### Offline multisig (Bitcoin k-of-n)
A multisig wallet is defined by **public** keys, so it can be built entirely
offline: each cosigner generates a seed on their own airgapped device and shares
only an account **xpub** — no private key ever meets. Spending later requires k
of the n keys to sign (a PSBT flow, done in your wallet of choice).

```bash
# 1) On EACH signer's offline machine — export the account xpub (never the seed):
SeedForge-Wallet xpub -mnemonic "signer's words..."
#    prints: master fingerprint, path m/48'/0'/0'/2', the xpub, and a
#    ready-to-paste descriptor key [fingerprint/48h/0h/0h/2h]xpub...

# 2) On the coordinator machine — combine the xpubs into 2-of-3 addresses:
SeedForge-Wallet multisig -threshold 2 -script wsh \
  -xpub "xpubAAA..." -xpub "xpubBBB..." -xpub "xpubCCC..." -count 5
```
`-script` chooses the address type: `wsh` native segwit (`bc1q…`, recommended),
`sh` legacy (`3…`), or `sh-wsh` wrapped segwit (`3…`). Keys are BIP-67 sorted so
every cosigner derives identical addresses regardless of order. The command also
prints a checksummed **output descriptor** — import it into Sparrow, Bitcoin
Core (`importdescriptors`), or Electrum and confirm the addresses match
byte-for-byte. Every multisig address, xpub, and descriptor checksum in this
tool is verified in `selftest` against the embit (Specter) and bip_utils
reference libraries.

> Ethereum "multisig" is a smart contract (e.g. Safe), not offline key
> derivation, so it is intentionally out of scope for this key tool.

Build it yourself: `cd src/wallet && go run . selftest` then
`go build -o SeedForge-Wallet .` (needs Go + network once to fetch the pinned
deps in `go.sum`).

---

## Layout
```
SeedForge/
├── bin/                 prebuilt binaries: generator + SeedForge.apk + Wallet
├── src/desktop/         BIP-39 generator — Go (main.go, bip39.go) + build.sh
├── src/android/         Android app — Java, manifest, res, assets + build.sh
├── src/wallet/          HD derivation, multisig & backup — Go + go.sum
├── wordlist/            official BIP-39 English list + its SHA-256
├── LICENSE              MIT
├── .gitignore           blocks seeds/keys/vaults from ever being committed
├── SECURITY.md          full threat model & verification steps
├── VAULT_FORMAT.md      the .vlk container spec
└── SHA256SUMS.txt       checksums for every shipped artifact
```

## Publishing to GitHub

The included `.gitignore` blocks the dangerous stuff — `*.vlk`, anything named
like a seed/mnemonic/share, `*.wif`/`*.key`, and Android `*.keystore`/`*.jks` —
so a stray secret can't be committed. **Double-check `git status` before your
first push and never commit a real seed, share, vault, or signing key.**

```bash
cd SeedForge
git init -b main
git add .
git status                      # confirm NO seeds/keys/.vlk are staged
git commit -m "SeedForge: offline BIP-39 generator + HD wallet, multisig & backup"

# Option A — GitHub CLI (creates the repo and pushes in one step):
gh repo create speedevs/seedforge --public --source=. --remote=origin --push

# Option B — manual (create the empty repo on github.com first):
git remote add origin https://github.com/speedevs/seedforge.git
git push -u origin main
```
Prebuilt binaries are git-ignored on purpose (they bloat history); publish them
as a **Release** instead:
```bash
gh release create v1.0.0 dist/SeedForge-* bin/SeedForge.apk -t "SeedForge v1.0.0"
```

Built by @speedevs. BIP-39 by M. Palatinus, P. Rusnak, A. Voisine, S. Bowe.
secp256k1 via btcec; Argon2id/XChaCha20-Poly1305 via golang.org/x/crypto.
