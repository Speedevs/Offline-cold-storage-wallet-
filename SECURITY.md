# SeedForge — Security Model

This document states precisely what SeedForge guarantees, what it does not, and
how to verify each claim yourself. Do not take any of it on faith — the whole
point is that you can check it.

## Threat model

**In scope (what SeedForge defends against):**
- Exfiltration of the seed over the network by the tool itself.
- Weak or predictable randomness.
- A tampered/mismatched wordlist producing a phrase you can't restore elsewhere.
- Incidental capture: screenshots / screen recording (Android), disk artifacts,
  logs, clipboard history.
- Supply-chain risk from third-party libraries.

**Out of scope (what NO offline generator can defend against):**
- A compromised operating system or hardware: kernel/root malware, keyloggers,
  screen scrapers, RAM dumpers, malicious GPU/USB drivers, evil-maid attacks.
- Physical observation: cameras, shoulder-surfing, reflections.
- The user copying the phrase into an untrusted app or website afterward.
- Coercion, phishing, or social engineering.

The mitigation for the out-of-scope items is operational, not software: generate
on a clean, offline device and keep the words on paper/metal, offline.

## Guarantees and how to verify them

### 1. No network access
- **Desktop:** the source imports no networking package.
  ```bash
  cd src/desktop && go list -deps . | grep -E '^net$|net/http'   # prints nothing
  ```
  A Go binary cannot make a socket call it never linked.
- **Android:** the app requests no permissions.
  ```bash
  aapt dump permissions bin/SeedForge.apk     # no uses-permission lines
  ```
  Without `android.permission.INTERNET`, the Android runtime blocks all sockets.

### 2. Cryptographically secure randomness
- Desktop entropy: `crypto/rand.Read` → OS CSPRNG (`getrandom(2)` on Linux,
  `getentropy` on macOS, `BCryptGenRandom` on Windows). No `math/rand` is used
  for key material.
- Android entropy: `java.security.SecureRandom` (kernel-backed).
- Optional user entropy is mixed as `leftmost_N_bytes( SHA-512(os_random ‖ user) )`.
  SHA-512 acts as a random oracle: the output is unpredictable if *either* input
  is unknown, so the mix can only help, never hurt.

### 3. Correct BIP-39 implementation
Both implementations pass the official Trezor/BIP-39 vectors:
```bash
./bin/SeedForge-linux-amd64 -selftest
```
This checks 128-, 160-, 192- and 256-bit mnemonic vectors **and** a
PBKDF2-HMAC-SHA512 seed-derivation vector
(`"abandon … about"` + passphrase `TREZOR` →
`c55257c3…e7463b04`). A transcription bug would fail here and the program exits
non-zero before generating anything.

### 4. Wordlist integrity
The embedded English list is checked at startup against
`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`
(the canonical `bip-0039/english.txt`). Mismatch → the program/app aborts.
Confirm the shipped copy:
```bash
sha256sum wordlist/english.txt
```

### 5. No persistence / no leakage
- Nothing is written to disk, no logs, no analytics, no clipboard writes.
- Android sets `FLAG_SECURE`: screenshots and screen recording of the app are
  blocked and the window is excluded from the recent-apps preview.
- Sensitive byte buffers (entropy, derived seed) are zeroed after use. In managed
  runtimes (Go GC, ART) this is best-effort mitigation, not a hard guarantee —
  the runtime may have copied a buffer before it was wiped. Treat RAM on a
  compromised host as readable regardless.

### 6. Reproducibility / no supply chain
The desktop module has **no third-party dependencies** (standard library only),
so `go build` is deterministic and needs no network. The Android build uses only
the Android SDK build-tools and a JDK — no Gradle plugins, no Maven artifacts.

## On the APK signature

`bin/SeedForge.apk` is signed (APK Signature Schemes v1+v2+v3) with a key
generated for this project (alias `seedforge`, CN=SeedForge). This lets Android
install it and guarantees the APK hasn't been altered since signing — but the
key is **not** a vetted publisher identity and its password ships in the build
script. If you require a trusted provenance, rebuild from source with your own
keystore:
```bash
cd src/android
# delete build/seedforge.keystore first, or point the script at your own -ks
ANDROID_HOME=… JAVA_HOME=… bash build.sh
```
Then record and compare the certificate fingerprint:
```bash
apksigner verify --print-certs build/SeedForge.apk
```

## Recommended operating procedure (high value)
1. Boot a clean OS (spare device, or a live-USB Linux session with no drives
   mounted). Put it in airplane mode / unplug the network.
2. Run SeedForge; choose 24 words; optionally add dice entropy.
3. Write the words on paper **in order**, twice. Verify with option `[3]`.
4. Power off (RAM clears). Store the copies in separate secure locations.
5. Never digitize the words. Fund a small amount first and test recovery before
   trusting it with more.

## Responsible use
This tool generates cryptographic key material for wallets you control. Losing
the phrase means losing the funds; exposing it means someone else can take them.
There is no customer support and no recovery. Own that responsibility.
