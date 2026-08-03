package main

// multisig.go — offline Bitcoin k-of-n multisig.
//
// The whole point of offline multisig: a wallet is defined by PUBLIC keys, so it
// can be assembled without any private key ever being present. Each cosigner
// generates a seed on their own airgapped device, exports only an account xpub,
// and a coordinator combines the xpubs into addresses. Spending later needs k of
// the n private keys to sign (done in a PSBT flow, outside this address tool).
//
// SECURITY DECISIONS:
//   * Only public keys are handled here — there is no path by which a private
//     key influences a multisig address, so this half of the tool is safe to run
//     on a networked machine if you want (though staying offline is still best).
//   * Cosigner keys are sorted lexicographically (BIP-67 / `sortedmulti`) before
//     building the script, so every cosigner independently derives the SAME
//     address regardless of the order they list each other. Order-dependent
//     `multi()` is a common footgun; we avoid it.
//   * We also emit a Bitcoin Core output descriptor with its checksum, so you can
//     import the wallet into Core / Sparrow / Electrum and confirm byte-for-byte
//     that this tool produced the right addresses. Never trust a single
//     implementation for multisig — verify the descriptor elsewhere.
//   * Public child keys are derived with BIP-32 CKDpub (EC point addition via the
//     vetted secp256k1 library), never by any home-grown shortcut.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"

	btcec "github.com/btcsuite/btcd/btcec/v2"
)

// extPub is a parsed BIP-32 extended PUBLIC key (xpub/ypub/zpub).
type extPub struct {
	depth     byte
	parentFP  [4]byte
	childNum  uint32
	chainCode [32]byte
	pub       []byte // 33-byte compressed public key
}

// ---- base58check decode (needed to parse xpubs) ---------------------------

func base58Decode(s string) ([]byte, error) {
	num := big.NewInt(0)
	base := big.NewInt(58)
	for _, r := range s {
		idx := strings.IndexRune(b58alpha, r)
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58 character %q", r)
		}
		num.Mul(num, base)
		num.Add(num, big.NewInt(int64(idx)))
	}
	dec := num.Bytes()
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	return append(make([]byte, zeros), dec...), nil
}

func base58CheckDecode(s string) ([]byte, error) {
	b, err := base58Decode(s)
	if err != nil {
		return nil, err
	}
	if len(b) < 5 {
		return nil, errors.New("base58check string too short")
	}
	payload := b[:len(b)-4]
	chk := b[len(b)-4:]
	if !bytes.Equal(sha256d(payload)[:4], chk) {
		return nil, errors.New("bad base58check checksum")
	}
	return payload, nil
}

// parseXpub parses an extended public key. It accepts any version bytes (xpub,
// ypub, zpub, and their multisig variants) since those only hint script type;
// the underlying key material is identical and the caller chooses the script.
func parseXpub(s string) (*extPub, error) {
	s = strings.TrimSpace(s)
	payload, err := base58CheckDecode(s)
	if err != nil {
		return nil, fmt.Errorf("not a valid extended key: %w", err)
	}
	if len(payload) != 78 {
		return nil, fmt.Errorf("extended key wrong length (%d, want 78)", len(payload))
	}
	key := payload[45:78]
	if key[0] != 0x02 && key[0] != 0x03 {
		return nil, errors.New("this is a private extended key (xprv); provide the xpub")
	}
	x := &extPub{depth: payload[4], childNum: binary.BigEndian.Uint32(payload[9:13])}
	copy(x.parentFP[:], payload[5:9])
	copy(x.chainCode[:], payload[13:45])
	x.pub = append([]byte{}, key...)
	return x, nil
}

// ---- BIP-32 public child derivation (CKDpub) -------------------------------

// childPub derives a non-hardened public child. Hardened public derivation is
// impossible by design (that is what makes xpubs safe to share).
func (x *extPub) child(i uint32) (*extPub, error) {
	if i >= hardened {
		return nil, errors.New("cannot derive a hardened child from an xpub")
	}
	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], i)
	mac := hmac.New(sha512.New, x.chainCode[:])
	mac.Write(x.pub) // serP(K_par)
	mac.Write(idx[:])
	I := mac.Sum(nil)

	il := new(big.Int).SetBytes(I[:32])
	if il.Cmp(curveN) >= 0 {
		return nil, errors.New("derived IL >= n; caller should try next index")
	}

	// K_i = IL*G + K_par  (elliptic-curve point addition)
	curve := btcec.S256()
	ilx, ily := curve.ScalarBaseMult(I[:32])
	ppk, err := btcec.ParsePubKey(x.pub)
	if err != nil {
		return nil, err
	}
	pe := ppk.ToECDSA()
	x3, y3 := curve.Add(ilx, ily, pe.X, pe.Y)
	if x3.Sign() == 0 && y3.Sign() == 0 {
		return nil, errors.New("derived point at infinity; caller should try next index")
	}

	// re-serialize as a compressed pubkey
	var fx, fy btcec.FieldVal
	fx.SetByteSlice(leftPad32(x3.Bytes()))
	fy.SetByteSlice(leftPad32(y3.Bytes()))
	childKey := btcec.NewPublicKey(&fx, &fy)

	child := &extPub{depth: x.depth + 1, childNum: i}
	// parent fingerprint = HASH160(parent pubkey)[:4]
	pfp := hash160(x.pub)
	copy(child.parentFP[:], pfp[:4])
	copy(child.chainCode[:], I[32:])
	child.pub = childKey.SerializeCompressed()
	return child, nil
}

func leftPad32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// deriveChildPub walks a "change/index" tail under an account xpub.
func deriveChildPub(x *extPub, change, index uint32) ([]byte, error) {
	c, err := x.child(change)
	if err != nil {
		return nil, err
	}
	leaf, err := c.child(index)
	if err != nil {
		return nil, err
	}
	return leaf.pub, nil
}

// ---- multisig script + addresses ------------------------------------------

// multisigScript builds a sorted (BIP-67) k-of-n bare multisig script:
//   OP_k <pk_1> ... <pk_n> OP_n OP_CHECKMULTISIG
func multisigScript(k int, pubkeys [][]byte) ([]byte, error) {
	if k < 1 || k > len(pubkeys) {
		return nil, fmt.Errorf("threshold %d invalid for %d keys", k, len(pubkeys))
	}
	if len(pubkeys) > 15 {
		return nil, errors.New("bare multisig supports at most 15 keys")
	}
	sorted := make([][]byte, len(pubkeys))
	copy(sorted, pubkeys)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i], sorted[j]) < 0 })

	script := []byte{0x50 + byte(k)} // OP_k
	for _, pk := range sorted {
		script = append(script, byte(len(pk)))
		script = append(script, pk...)
	}
	script = append(script, 0x50+byte(len(pubkeys))) // OP_n
	script = append(script, 0xae)                    // OP_CHECKMULTISIG
	return script, nil
}

// p2wshAddress: native segwit v0 (bc1q..., 32-byte program = SHA256(script)).
func p2wshAddress(script []byte) (string, error) {
	h := sha256.Sum256(script)
	conv, err := convertBits(h[:], 8, 5, true)
	if err != nil {
		return "", err
	}
	data := append([]int{0x00}, conv...)
	sum := bech32Checksum("bc", data)
	combined := append(append([]int{}, data...), sum...)
	var sb strings.Builder
	sb.WriteString("bc1")
	for _, d := range combined {
		sb.WriteByte(bech32Charset[d])
	}
	return sb.String(), nil
}

// p2shAddress: legacy P2SH (3..., HASH160 of the redeem script).
func p2shAddress(script []byte) string {
	return base58Check(append([]byte{0x05}, hash160(script)...))
}

// p2shP2wshAddress: P2WSH wrapped in P2SH (3..., for legacy-only senders).
func p2shP2wshAddress(witnessScript []byte) string {
	wp := sha256.Sum256(witnessScript)
	redeem := append([]byte{0x00, 0x20}, wp[:]...) // OP_0 <32-byte push>
	return base58Check(append([]byte{0x05}, hash160(redeem)...))
}

// multisigAddress dispatches on script kind: "wsh", "sh", or "sh-wsh".
func multisigAddress(kind string, k int, pubkeys [][]byte) (string, error) {
	script, err := multisigScript(k, pubkeys)
	if err != nil {
		return "", err
	}
	switch kind {
	case "wsh":
		return p2wshAddress(script)
	case "sh":
		return p2shAddress(script), nil
	case "sh-wsh":
		return p2shP2wshAddress(script), nil
	default:
		return "", fmt.Errorf("unknown script type %q (use wsh, sh, or sh-wsh)", kind)
	}
}

// ---- output descriptor + checksum -----------------------------------------

const descInputCharset = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
const descChecksumCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var descGen = []uint64{0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd}

func descPolymod(symbols []int) uint64 {
	var chk uint64 = 1
	for _, v := range symbols {
		top := chk >> 35
		chk = (chk&0x7ffffffff)<<5 ^ uint64(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= descGen[i]
			}
		}
	}
	return chk
}

// descChecksum computes the 8-char Bitcoin Core descriptor checksum for s.
func descChecksum(s string) (string, error) {
	var symbols []int
	var groups []int
	for _, c := range s {
		idx := strings.IndexRune(descInputCharset, c)
		if idx < 0 {
			return "", fmt.Errorf("character %q not allowed in a descriptor", c)
		}
		symbols = append(symbols, idx&31)
		groups = append(groups, idx>>5)
		if len(groups) == 3 {
			symbols = append(symbols, groups[0]*9+groups[1]*3+groups[2])
			groups = groups[:0]
		}
	}
	if len(groups) == 1 {
		symbols = append(symbols, groups[0])
	} else if len(groups) == 2 {
		symbols = append(symbols, groups[0]*3+groups[1])
	}
	symbols = append(symbols, 0, 0, 0, 0, 0, 0, 0, 0)
	chk := descPolymod(symbols) ^ 1
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = descChecksumCharset[(chk>>uint(5*(7-i)))&31]
	}
	return string(out), nil
}

// buildDescriptor assembles wsh/sh/sh-wsh sortedmulti descriptor with checksum.
func buildDescriptor(kind string, k int, xpubs []string, change uint32) (string, error) {
	var keys []string
	for _, x := range xpubs {
		keys = append(keys, fmt.Sprintf("%s/%d/*", strings.TrimSpace(x), change))
	}
	inner := fmt.Sprintf("sortedmulti(%d,%s)", k, strings.Join(keys, ","))
	var body string
	switch kind {
	case "wsh":
		body = "wsh(" + inner + ")"
	case "sh":
		body = "sh(" + inner + ")"
	case "sh-wsh":
		body = "sh(wsh(" + inner + "))"
	default:
		return "", fmt.Errorf("unknown script type %q", kind)
	}
	sum, err := descChecksum(body)
	if err != nil {
		return "", err
	}
	return body + "#" + sum, nil
}
