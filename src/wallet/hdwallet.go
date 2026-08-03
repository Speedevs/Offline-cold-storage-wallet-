package main

// hdwallet.go — BIP-32 hierarchical-deterministic derivation and BIP-44/BIP-84
// address generation for Bitcoin and Ethereum.
//
// SECURITY DECISIONS (why this file is written the way it is):
//
//   * secp256k1 is NOT implemented here. Rolling your own elliptic-curve math is
//     one of the most reliable ways to introduce a catastrophic, fund-draining
//     bug (bad reductions, non-constant-time ops, point-at-infinity mishandling).
//     We delegate all curve operations to btcec/v2 (the secp256k1 library used
//     by btcd), which is widely deployed and reviewed. Everything else in this
//     file — BIP-32 tree walking, serialization, address encoding — is plain,
//     well-specified byte manipulation that does not touch secret scalars beyond
//     handing them to the vetted library.
//
//   * All key material lives in []byte we can wipe, not in strings (strings are
//     immutable and may be copied/interned by the runtime, so they can't be
//     scrubbed). Callers Zero() these buffers when done. This is best-effort:
//     the GC may still have moved a copy, so a hostile OS is out of scope.
//
//   * No network, no disk, no logging happens here. Derivation is pure and
//     offline by construction.

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

// hardened marks a BIP-32 hardened child (index >= 2^31).
const hardened uint32 = 0x80000000

// secp256k1 group order n.
var curveN = btcec.S256().Params().N

// mainnet BIP-32 serialization version bytes.
var (
	verMainPriv = [4]byte{0x04, 0x88, 0xAD, 0xE4} // xprv
	verMainPub  = [4]byte{0x04, 0x88, 0xB2, 0x1E} // xpub
)

// xkey is a BIP-32 extended key (private form; we never need public-parent
// derivation for a from-seed wallet, so we keep only the private path).
type xkey struct {
	version   [4]byte
	depth     byte
	parentFP  [4]byte
	childNum  uint32
	chainCode [32]byte
	priv      [32]byte // raw private scalar, big-endian
}

// masterFromSeed implements BIP-32 master key generation:
//   I = HMAC-SHA512(key = "Bitcoin seed", data = seed)
//   IL = master private key, IR = master chain code.
func masterFromSeed(seed []byte) (*xkey, error) {
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed)
	I := mac.Sum(nil)
	il := new(big.Int).SetBytes(I[:32])
	// Reject an out-of-range or zero master key (astronomically unlikely, but
	// the spec mandates the check and skipping it would be a silent weakness).
	if il.Sign() == 0 || il.Cmp(curveN) >= 0 {
		return nil, errors.New("invalid master key derived from seed")
	}
	k := &xkey{version: verMainPriv}
	copy(k.priv[:], I[:32])
	copy(k.chainCode[:], I[32:])
	Zero(I)
	return k, nil
}

// pubCompressed returns the 33-byte compressed public key for a private scalar.
func pubCompressed(priv [32]byte) []byte {
	pk, _ := btcec.PrivKeyFromBytes(priv[:])
	return pk.PubKey().SerializeCompressed()
}

// fingerprint is the first 4 bytes of HASH160(compressed pubkey); used as the
// parent fingerprint when serializing child extended keys.
func (k *xkey) fingerprint() [4]byte {
	h := hash160(pubCompressed(k.priv))
	var fp [4]byte
	copy(fp[:], h[:4])
	return fp
}

// child implements BIP-32 CKDpriv (private parent -> private child).
func (k *xkey) child(i uint32) (*xkey, error) {
	var data []byte
	if i >= hardened {
		// Hardened: 0x00 || ser256(k_par) || ser32(i)
		data = make([]byte, 0, 37)
		data = append(data, 0x00)
		data = append(data, k.priv[:]...)
	} else {
		// Normal: serP(point(k_par)) || ser32(i)
		data = append(data, pubCompressed(k.priv)...)
	}
	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], i)
	data = append(data, idx[:]...)

	mac := hmac.New(sha512.New, k.chainCode[:])
	mac.Write(data)
	I := mac.Sum(nil)
	Zero(data)

	il := new(big.Int).SetBytes(I[:32])
	if il.Cmp(curveN) >= 0 {
		return nil, errors.New("derived IL >= n; caller should try next index")
	}
	kpar := new(big.Int).SetBytes(k.priv[:])
	ki := new(big.Int).Add(il, kpar)
	ki.Mod(ki, curveN)
	if ki.Sign() == 0 {
		return nil, errors.New("derived child key is zero; caller should try next index")
	}

	child := &xkey{version: k.version, depth: k.depth + 1, childNum: i}
	child.parentFP = k.fingerprint()
	ki.FillBytes(child.priv[:]) // left-pads to 32 bytes
	copy(child.chainCode[:], I[32:])

	// scrub intermediates
	Zero(I)
	il.SetInt64(0)
	kpar.SetInt64(0)
	ki.SetInt64(0)
	return child, nil
}

// derivePath walks a full path like "m/44'/60'/0'/0/0".
func derivePath(seed []byte, path string) (*xkey, error) {
	k, err := masterFromSeed(seed)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] != "m" {
		return nil, fmt.Errorf("path must start with 'm': %q", path)
	}
	for _, p := range parts[1:] {
		if p == "" {
			continue
		}
		h := false
		if strings.HasSuffix(p, "'") || strings.HasSuffix(p, "h") || strings.HasSuffix(p, "H") {
			h = true
			p = p[:len(p)-1]
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil || n >= uint64(hardened) {
			return nil, fmt.Errorf("invalid path element %q", p)
		}
		idx := uint32(n)
		if h {
			idx += hardened
		}
		nk, err := k.child(idx)
		if err != nil {
			return nil, err
		}
		k = nk
	}
	return k, nil
}

// ---- serialization ---------------------------------------------------------

func (k *xkey) serialize(pub bool) string {
	buf := make([]byte, 0, 78)
	if pub {
		buf = append(buf, verMainPub[:]...)
	} else {
		buf = append(buf, k.version[:]...)
	}
	buf = append(buf, k.depth)
	buf = append(buf, k.parentFP[:]...)
	var cn [4]byte
	binary.BigEndian.PutUint32(cn[:], k.childNum)
	buf = append(buf, cn[:]...)
	buf = append(buf, k.chainCode[:]...)
	if pub {
		buf = append(buf, pubCompressed(k.priv)...)
	} else {
		buf = append(buf, 0x00)
		buf = append(buf, k.priv[:]...)
	}
	return base58Check(buf)
}

func (k *xkey) xprv() string { return k.serialize(false) }
func (k *xkey) xpub() string { return k.serialize(true) }

// ---- hashing helpers -------------------------------------------------------

func sha256d(b []byte) []byte {
	h1 := sha256.Sum256(b)
	h2 := sha256.Sum256(h1[:])
	return h2[:]
}

func hash160(b []byte) []byte {
	s := sha256.Sum256(b)
	r := ripemd160.New()
	r.Write(s[:])
	return r.Sum(nil)
}

func keccak256(b []byte) []byte {
	h := sha3.NewLegacyKeccak256() // Ethereum uses original Keccak, not NIST SHA3
	h.Write(b)
	return h.Sum(nil)
}

// ---- base58check -----------------------------------------------------------

const b58alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(b []byte) string {
	// count leading zero bytes -> leading '1's
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	num := new(big.Int).SetBytes(b)
	base := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	for num.Sign() > 0 {
		num.DivMod(num, base, mod)
		out = append(out, b58alpha[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, '1')
	}
	// reverse
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func base58Check(payload []byte) string {
	chk := sha256d(payload)[:4]
	return base58Encode(append(append([]byte{}, payload...), chk...))
}

// ---- bech32 (BIP-173, witness v0) -----------------------------------------

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(values []int) int {
	gen := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HrpExpand(hrp string) []int {
	var out []int
	for _, c := range hrp {
		out = append(out, int(c)>>5)
	}
	out = append(out, 0)
	for _, c := range hrp {
		out = append(out, int(c)&31)
	}
	return out
}

func bech32Checksum(hrp string, data []int) []int {
	values := append(bech32HrpExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(values) ^ 1
	out := make([]int, 6)
	for i := 0; i < 6; i++ {
		out[i] = (polymod >> uint(5*(5-i))) & 31
	}
	return out
}

func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]int, error) {
	acc := 0
	bits := uint(0)
	var out []int
	maxv := (1 << toBits) - 1
	for _, b := range data {
		if int(b)>>fromBits != 0 {
			return nil, errors.New("convertBits: input byte out of range")
		}
		acc = (acc << fromBits) | int(b)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, (acc>>bits)&maxv)
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, (acc<<(toBits-bits))&maxv)
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxv) != 0 {
		return nil, errors.New("convertBits: invalid padding")
	}
	return out, nil
}

// bech32EncodeP2WPKH encodes a witness-v0 P2WPKH address (hrp "bc").
func bech32EncodeP2WPKH(program []byte) (string, error) {
	conv, err := convertBits(program, 8, 5, true)
	if err != nil {
		return "", err
	}
	data := append([]int{0x00}, conv...) // witness version 0
	sum := bech32Checksum("bc", data)
	combined := append(append([]int{}, data...), sum...)
	var sb strings.Builder
	sb.WriteString("bc1")
	for _, d := range combined {
		sb.WriteByte(bech32Charset[d])
	}
	return sb.String(), nil
}

// ---- address / key encoders ------------------------------------------------

// ethAddress returns an EIP-55 checksummed Ethereum address for a key.
func ethAddress(priv [32]byte) string {
	pk, _ := btcec.PrivKeyFromBytes(priv[:])
	un := pk.PubKey().SerializeUncompressed() // 65 bytes: 0x04 || X || Y
	h := keccak256(un[1:])                    // hash X||Y
	addr := h[12:]                            // last 20 bytes
	hexAddr := fmt.Sprintf("%x", addr)
	// EIP-55: uppercase each hex letter whose corresponding nibble in
	// keccak256(lowercase_address_ascii) is >= 8.
	hash := keccak256([]byte(hexAddr))
	out := []byte("0x")
	for i := 0; i < len(hexAddr); i++ {
		c := hexAddr[i]
		if c >= 'a' && c <= 'f' {
			if (hash[i/2]>>(uint(4*(1-i%2))))&0x0f >= 8 {
				c -= 32 // to uppercase
			}
		}
		out = append(out, c)
	}
	return string(out)
}

// btcP2PKH returns a legacy (1...) Bitcoin address.
func btcP2PKH(priv [32]byte) string {
	h := hash160(pubCompressed(priv))
	return base58Check(append([]byte{0x00}, h...))
}

// btcBech32 returns a native segwit (bc1...) Bitcoin address.
func btcBech32(priv [32]byte) (string, error) {
	return bech32EncodeP2WPKH(hash160(pubCompressed(priv)))
}

// btcWIF returns the compressed-key WIF for a Bitcoin private key.
func btcWIF(priv [32]byte) string {
	payload := make([]byte, 0, 34)
	payload = append(payload, 0x80)       // mainnet prefix
	payload = append(payload, priv[:]...) // 32-byte scalar
	payload = append(payload, 0x01)       // compressed-pubkey flag
	return base58Check(payload)
}

// ethPrivHex returns the 0x-prefixed 32-byte private key (for import into
// Ethereum wallets). This is SECRET; it is only ever printed locally, never
// returned over any network path.
func ethPrivHex(priv [32]byte) string {
	return fmt.Sprintf("0x%x", priv[:])
}

// Account bundles everything a user needs for one derived index.
type Account struct {
	Path    string
	ETH     string
	BTCLeg  string
	BTCSeg  string
	privKey [32]byte // kept for optional secret display; wipe after use
}

// deriveAccount derives one account at m/purpose'/coin'/account'/change/index.
// coin: "eth" (44'/60'), "btc" (44'/0' legacy), "btc-segwit" (84'/0' bech32).
func deriveAccount(seed []byte, coin string, account, change, index uint32) (*Account, error) {
	var purpose, coinType uint32
	switch coin {
	case "eth":
		purpose, coinType = 44, 60
	case "btc":
		purpose, coinType = 44, 0
	case "btc-segwit":
		purpose, coinType = 84, 0
	default:
		return nil, fmt.Errorf("unknown coin %q (use eth, btc, or btc-segwit)", coin)
	}
	path := fmt.Sprintf("m/%d'/%d'/%d'/%d/%d", purpose, coinType, account, change, index)
	k, err := derivePath(seed, path)
	if err != nil {
		return nil, err
	}
	acc := &Account{Path: path}
	acc.privKey = k.priv
	switch coin {
	case "eth":
		acc.ETH = ethAddress(k.priv)
	case "btc":
		acc.BTCLeg = btcP2PKH(k.priv)
	case "btc-segwit":
		acc.BTCSeg, err = btcBech32(k.priv)
		if err != nil {
			return nil, err
		}
	}
	return acc, nil
}
