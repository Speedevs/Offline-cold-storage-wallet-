// bip39.go — BIP-39 mnemonic generation, validation, and seed derivation.
//
// Zero external dependencies: only the Go standard library is used. This keeps
// the attack surface minimal and the build fully reproducible with no supply
// chain to trust. The 2048-word English wordlist is embedded and its SHA-256 is
// verified at startup, so a tampered binary cannot silently swap the wordlist.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

//go:embed english.txt
var wordlistRaw string

// wordlistSHA256 is the canonical SHA-256 of the official BIP-39 English
// wordlist (from bitcoin/bips bip-0039/english.txt). It is checked at init.
const wordlistSHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

var (
	wordlist  []string
	wordIndex map[string]int
)

func init() {
	sum := sha256.Sum256([]byte(wordlistRaw))
	if hex.EncodeToString(sum[:]) != wordlistSHA256 {
		panic("FATAL: embedded wordlist integrity check FAILED — refusing to run")
	}
	lines := strings.Split(strings.TrimSpace(wordlistRaw), "\n")
	if len(lines) != 2048 {
		panic(fmt.Sprintf("FATAL: wordlist must contain 2048 words, found %d", len(lines)))
	}
	wordlist = make([]string, 2048)
	wordIndex = make(map[string]int, 2048)
	for i, w := range lines {
		w = strings.TrimSpace(w)
		wordlist[i] = w
		wordIndex[w] = i
	}
}

// entropyBitsForWords maps a mnemonic length to its entropy size in bits.
func entropyBitsForWords(words int) (int, bool) {
	switch words {
	case 12:
		return 128, true
	case 15:
		return 160, true
	case 18:
		return 192, true
	case 21:
		return 224, true
	case 24:
		return 256, true
	}
	return 0, false
}

// SystemEntropy returns n cryptographically secure random bytes drawn from the
// operating system CSPRNG (crypto/rand — getrandom(2)/BCryptGenRandom).
func SystemEntropy(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("secure RNG unavailable: %w", err)
	}
	return b, nil
}

// MixEntropy folds optional user-supplied entropy into the system entropy.
//
// When the user provides extra bytes (dice rolls, coin flips, keyboard mashing),
// the result is the leftmost bytes of SHA-512(system || user). Because SHA-512
// behaves as a strong pseudo-random function, the output is unpredictable as
// long as *either* input is unknown to an attacker. So even a fully backdoored
// system RNG cannot determine the seed if the user contributes real entropy,
// and a low-quality user input cannot weaken a good system RNG. When no extra
// entropy is supplied, the raw CSPRNG bytes are returned unchanged.
func MixEntropy(system, user []byte) []byte {
	if len(user) == 0 {
		return system
	}
	h := sha512.New()
	h.Write(system)
	h.Write(user)
	digest := h.Sum(nil)
	out := make([]byte, len(system))
	copy(out, digest[:len(system)])
	Zero(digest)
	return out
}

// readBits reads n bits (big-endian, MSB first) starting at bit offset start.
func readBits(data []byte, start, n int) int {
	v := 0
	for i := 0; i < n; i++ {
		pos := start + i
		bit := (data[pos/8] >> (7 - uint(pos%8))) & 1
		v = (v << 1) | int(bit)
	}
	return v
}

// EntropyToMnemonic converts entropy bytes into a BIP-39 mnemonic. The entropy
// length must be one of 16/20/24/28/32 bytes (128–256 bits, multiple of 32).
func EntropyToMnemonic(entropy []byte) (string, error) {
	ent := len(entropy) * 8
	if ent < 128 || ent > 256 || ent%32 != 0 {
		return "", fmt.Errorf("entropy must be 128–256 bits in 32-bit steps, got %d", ent)
	}
	cs := ent / 32 // checksum length in bits (4..8)
	hash := sha256.Sum256(entropy)

	// entropy bits followed by the top `cs` bits of the SHA-256 checksum.
	combined := make([]byte, 0, len(entropy)+1)
	combined = append(combined, entropy...)
	combined = append(combined, hash[0]) // cs <= 8, so one byte holds all checksum bits

	nWords := (ent + cs) / 11
	words := make([]string, nWords)
	for i := 0; i < nWords; i++ {
		words[i] = wordlist[readBits(combined, i*11, 11)]
	}
	return strings.Join(words, " "), nil
}

// GenerateMnemonic produces a fresh mnemonic of the requested word count using
// the system CSPRNG, optionally mixing in user-supplied extra entropy. It also
// returns the entropy that was used so the caller can display/verify it.
func GenerateMnemonic(words int, extraEntropy []byte) (mnemonic string, entropyUsed []byte, err error) {
	bits, ok := entropyBitsForWords(words)
	if !ok {
		return "", nil, fmt.Errorf("word count must be 12, 15, 18, 21 or 24 (got %d)", words)
	}
	sys, err := SystemEntropy(bits / 8)
	if err != nil {
		return "", nil, err
	}
	entropy := MixEntropy(sys, extraEntropy)
	if &entropy[0] != &sys[0] { // mixing occurred; scrub the raw system bytes
		Zero(sys)
	}
	m, err := EntropyToMnemonic(entropy)
	if err != nil {
		Zero(entropy)
		return "", nil, err
	}
	return m, entropy, nil
}

// NormalizeMnemonic lowercases and collapses whitespace in a mnemonic.
func NormalizeMnemonic(mnemonic string) string {
	return strings.Join(strings.Fields(strings.ToLower(mnemonic)), " ")
}

// MnemonicToEntropy validates a mnemonic (word membership + checksum) and
// returns the recovered entropy. An error means the phrase is invalid.
func MnemonicToEntropy(mnemonic string) ([]byte, error) {
	words := strings.Fields(NormalizeMnemonic(mnemonic))
	n := len(words)
	if _, ok := entropyBitsForWords(n); !ok {
		return nil, fmt.Errorf("phrase must have 12, 15, 18, 21 or 24 words (got %d)", n)
	}
	totalBits := n * 11
	ent := totalBits / 33 * 32
	cs := totalBits - ent

	bits := make([]byte, (totalBits+7)/8)
	pos := 0
	for _, w := range words {
		idx, ok := wordIndex[w]
		if !ok {
			return nil, fmt.Errorf("word not in BIP-39 wordlist: %q", w)
		}
		for b := 10; b >= 0; b-- {
			if (idx>>uint(b))&1 == 1 {
				bits[pos/8] |= 1 << (7 - uint(pos%8))
			}
			pos++
		}
	}

	entropy := make([]byte, ent/8)
	copy(entropy, bits[:ent/8])
	hash := sha256.Sum256(entropy)
	for i := 0; i < cs; i++ {
		want := (hash[i/8] >> (7 - uint(i%8))) & 1
		got := readBits(bits, ent+i, 1)
		if int(want) != got {
			Zero(entropy)
			return nil, fmt.Errorf("checksum mismatch — phrase is invalid or mistyped")
		}
	}
	return entropy, nil
}

// ValidateMnemonic reports whether a mnemonic is well-formed with a valid checksum.
func ValidateMnemonic(mnemonic string) bool {
	e, err := MnemonicToEntropy(mnemonic)
	if err != nil {
		return false
	}
	Zero(e)
	return true
}

// pbkdf2SHA512 implements PBKDF2 with HMAC-SHA-512 (RFC 2898), stdlib only.
func pbkdf2SHA512(password, salt []byte, iter, keyLen int) []byte {
	const hLen = sha512.Size // 64
	blocks := (keyLen + hLen - 1) / hLen
	dk := make([]byte, 0, blocks*hLen)
	var idx [4]byte
	for block := 1; block <= blocks; block++ {
		binary.BigEndian.PutUint32(idx[:], uint32(block))
		prf := hmac.New(sha512.New, password)
		prf.Write(salt)
		prf.Write(idx[:])
		u := prf.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			p := hmac.New(sha512.New, password)
			p.Write(u)
			u = p.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// MnemonicToSeed derives the 64-byte BIP-39 seed (PBKDF2-HMAC-SHA-512, 2048
// iterations, salt = "mnemonic"+passphrase). NOTE: inputs are expected to be
// ASCII / NFKD-normalized. The English wordlist is ASCII; if you use a
// non-ASCII passphrase, normalize it to NFKD yourself for cross-wallet parity.
func MnemonicToSeed(mnemonic, passphrase string) []byte {
	pw := []byte(NormalizeMnemonic(mnemonic))
	salt := []byte("mnemonic" + passphrase)
	seed := pbkdf2SHA512(pw, salt, 2048, 64)
	Zero(pw)
	return seed
}

// Zero best-effort wipes a byte slice. In a managed runtime this is a mitigation,
// not a guarantee (the GC may have copied the buffer), but it shrinks the window
// in which key material lingers in memory.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
