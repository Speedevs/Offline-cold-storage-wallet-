package main

// vault.go — the ".vlk" encrypted vault container for backing up a seed to a
// file that is safe to store in cloud storage, on a USB stick, or emailed to
// yourself, because it is useless without the passphrase.
//
// There is no universal standard ".vlk" format, so this defines one explicitly.
// It is self-describing and fully documented in VAULT_FORMAT.md. It round-trips
// only with this tool (and any implementation that follows that spec).
//
// SECURITY DECISIONS:
//   * Password -> key uses Argon2id, a memory-hard KDF that resists GPU/ASIC
//     brute force far better than PBKDF2/bcrypt. Parameters are stored in the
//     header (and authenticated, see below) so the file stays readable if we
//     raise them later. Defaults: 3 passes, 128 MiB, 4 lanes.
//   * Encryption is XChaCha20-Poly1305, an AEAD with a 192-bit random nonce.
//     The extended nonce means a randomly chosen nonce will never collide in
//     practice, so we never have to track a counter, and Poly1305 gives us
//     tamper detection for free.
//   * The entire header (magic, version, KDF params, salt, nonce) is fed to the
//     AEAD as Additional Authenticated Data. An attacker therefore cannot weaken
//     the file by editing, say, the Argon2 memory cost down — any change makes
//     decryption fail rather than silently succeed with a cheaper key.
//   * A wrong password is indistinguishable from a corrupted file: both simply
//     fail the Poly1305 tag. We never reveal which, and never "partially"
//     decrypt.
//   * The plaintext (the mnemonic) is wiped from memory after encryption and
//     after a successful decrypt+display. Best-effort, as always.

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	vlkMagic0, vlkMagic1, vlkMagic2, vlkMagic3 = 'V', 'L', 'K', '1'
	vlkVersion                                 = 1
	kdfArgon2id                                = 1

	saltLen = 16
	nonceLen = chacha20poly1305.NonceSizeX // 24
	keyLen   = chacha20poly1305.KeySize    // 32
)

// default Argon2id cost parameters.
var (
	argonTime    uint32 = 3
	argonMemKiB  uint32 = 128 * 1024 // 128 MiB
	argonThreads uint8  = 4
)

// vaultPayload is the JSON that gets encrypted. Only non-secret metadata plus
// the mnemonic itself; we never store the optional BIP-39 passphrase.
type vaultPayload struct {
	Type     string `json:"type"`
	Mnemonic string `json:"mnemonic"`
	Words    int    `json:"words"`
	Note     string `json:"note,omitempty"`
	Created  string `json:"created"`
}

// vaultHeader is the cleartext, authenticated prefix of a .vlk file.
type vaultHeader struct {
	version  byte
	kdf      byte
	time     uint32
	memKiB   uint32
	threads  uint8
	salt     []byte
	nonce    []byte
}

func (h *vaultHeader) marshal() []byte {
	// magic(4) ver(1) kdf(1) time(4) mem(4) threads(1) saltLen(1) salt nonceLen(1) nonce
	b := make([]byte, 0, 4+1+1+4+4+1+1+len(h.salt)+1+len(h.nonce))
	b = append(b, vlkMagic0, vlkMagic1, vlkMagic2, vlkMagic3)
	b = append(b, h.version, h.kdf)
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], h.time)
	b = append(b, u4[:]...)
	binary.BigEndian.PutUint32(u4[:], h.memKiB)
	b = append(b, u4[:]...)
	b = append(b, h.threads)
	b = append(b, byte(len(h.salt)))
	b = append(b, h.salt...)
	b = append(b, byte(len(h.nonce)))
	b = append(b, h.nonce...)
	return b
}

// parseHeader reads a header from the front of buf and returns it plus the
// remaining ciphertext.
func parseHeader(buf []byte) (*vaultHeader, []byte, error) {
	if len(buf) < 6 || buf[0] != vlkMagic0 || buf[1] != vlkMagic1 || buf[2] != vlkMagic2 || buf[3] != vlkMagic3 {
		return nil, nil, errors.New("not a .vlk vault (bad magic)")
	}
	h := &vaultHeader{version: buf[4], kdf: buf[5]}
	if h.version != vlkVersion {
		return nil, nil, fmt.Errorf("unsupported vault version %d", h.version)
	}
	if h.kdf != kdfArgon2id {
		return nil, nil, fmt.Errorf("unsupported KDF id %d", h.kdf)
	}
	p := 6
	need := func(n int) error {
		if p+n > len(buf) {
			return errors.New("vault truncated")
		}
		return nil
	}
	if err := need(9); err != nil {
		return nil, nil, err
	}
	h.time = binary.BigEndian.Uint32(buf[p : p+4])
	p += 4
	h.memKiB = binary.BigEndian.Uint32(buf[p : p+4])
	p += 4
	h.threads = buf[p]
	p++
	if err := need(1); err != nil {
		return nil, nil, err
	}
	sl := int(buf[p])
	p++
	if err := need(sl); err != nil {
		return nil, nil, err
	}
	h.salt = buf[p : p+sl]
	p += sl
	if err := need(1); err != nil {
		return nil, nil, err
	}
	nl := int(buf[p])
	p++
	if err := need(nl); err != nil {
		return nil, nil, err
	}
	h.nonce = buf[p : p+nl]
	p += nl
	return h, buf[p:], nil
}

func deriveVaultKey(password, salt []byte, t, mem uint32, threads uint8) []byte {
	return argon2.IDKey(password, salt, t, mem, threads, keyLen)
}

// EncryptVault produces .vlk bytes for a mnemonic under a password.
func EncryptVault(mnemonic, note string, words int, password []byte) ([]byte, error) {
	if len(password) < 8 {
		return nil, errors.New("vault password must be at least 8 characters")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	h := &vaultHeader{
		version: vlkVersion, kdf: kdfArgon2id,
		time: argonTime, memKiB: argonMemKiB, threads: argonThreads,
		salt: salt, nonce: nonce,
	}
	aad := h.marshal()

	key := deriveVaultKey(password, salt, h.time, h.memKiB, h.threads)
	defer Zero(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	payload := vaultPayload{
		Type: "seedforge-vault", Mnemonic: mnemonic, Words: words,
		Note: note, Created: time.Now().UTC().Format(time.RFC3339),
	}
	pt, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, pt, aad)
	Zero(pt) // scrub the plaintext JSON (contained the mnemonic)

	return append(aad, ct...), nil
}

// DecryptVault opens a .vlk blob with a password, returning the payload.
func DecryptVault(blob, password []byte) (*vaultPayload, error) {
	h, ct, err := parseHeader(blob)
	if err != nil {
		return nil, err
	}
	aad := h.marshal()
	key := deriveVaultKey(password, h.salt, h.time, h.memKiB, h.threads)
	defer Zero(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, h.nonce, ct, aad)
	if err != nil {
		// Wrong password OR tampered/corrupted file — deliberately not
		// distinguished, to avoid a password oracle.
		return nil, errors.New("could not open vault: wrong password or corrupted file")
	}
	var payload vaultPayload
	if err := json.Unmarshal(pt, &payload); err != nil {
		Zero(pt)
		return nil, errors.New("vault opened but contents are malformed")
	}
	Zero(pt)
	if payload.Type != "seedforge-vault" {
		return nil, errors.New("not a SeedForge vault payload")
	}
	return &payload, nil
}

// InspectVault reports the non-secret header parameters without a password.
func InspectVault(blob []byte) (string, error) {
	h, ct, err := parseHeader(blob)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"VLK vault v%d\n  KDF:        Argon2id (time=%d, memory=%d MiB, lanes=%d)\n  salt:       %d bytes\n  nonce:      %d bytes (XChaCha20-Poly1305)\n  ciphertext: %d bytes (incl. 16-byte auth tag)",
		h.version, h.time, h.memKiB/1024, h.threads, len(h.salt), len(h.nonce), len(ct)), nil
}
