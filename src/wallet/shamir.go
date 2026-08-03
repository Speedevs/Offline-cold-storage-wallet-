package main

// shamir.go — Shamir's Secret Sharing over GF(2^8), used to split a seed's
// entropy into N shares of which any K reconstruct it (and any K-1 reveal
// nothing). This is the "backup-worthy / impenetrable" mechanism: distribute
// shares to separate locations; losing some is survivable, and a thief needs K.
//
// SECURITY DECISIONS:
//   * The scheme is information-theoretically secure when done right: with fewer
//     than K shares, every secret is equally likely. The two things that can
//     break that are (a) non-random polynomial coefficients and (b) field-math
//     bugs. We use crypto/rand for every coefficient (never math/rand), and the
//     GF(256) arithmetic below is the standard AES field (reduction poly 0x11b)
//     with table-driven multiply, matching well-known references.
//   * We split the raw ENTROPY (16/32 bytes), not the words. Entropy fully
//     determines the mnemonic, so reconstruction is exact and shares stay small.
//   * Share bytes carry a per-share CRC so a mistyped share is rejected loudly
//     rather than silently reconstructing the wrong secret.
//
// NOTE: this is a plain, self-describing split — it is intentionally simpler
// than SLIP-39 and is NOT interoperable with SLIP-39 / Trezor Shamir backups.
// It round-trips only with this tool. That trade keeps it auditable in one file.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// --- GF(2^8) arithmetic (AES field, 0x11b) ---------------------------------

var gfExp [512]byte
var gfLog [256]byte

func init() {
	x := byte(1)
	for i := 0; i < 255; i++ {
		gfExp[i] = x
		gfLog[x] = byte(i)
		// multiply x by the generator 0x03 in GF(2^8)
		hi := x & 0x80
		x <<= 1
		if hi != 0 {
			x ^= 0x1b
		}
		x ^= gfExp[i] // x = x*2 XOR x = x*3
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func gfDiv(a, b byte) byte {
	if b == 0 {
		panic("gf division by zero")
	}
	if a == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])-int(gfLog[b])+255]
}

// evalPoly evaluates a polynomial (coeffs[0] = constant term) at x in GF(256).
func evalPoly(coeffs []byte, x byte) byte {
	// Horner's method
	result := byte(0)
	for i := len(coeffs) - 1; i >= 0; i-- {
		result = gfMul(result, x) ^ coeffs[i]
	}
	return result
}

// splitBytes splits secret into n shares, threshold k. Returns, per share x in
// 1..n, the y-bytes (one per secret byte).
func splitBytes(secret []byte, k, n int) (map[byte][]byte, error) {
	if k < 2 || k > 255 {
		return nil, errors.New("threshold must be 2..255")
	}
	if n < k || n > 255 {
		return nil, errors.New("shares must be >= threshold and <= 255")
	}
	shares := make(map[byte][]byte, n)
	for x := 1; x <= n; x++ {
		shares[byte(x)] = make([]byte, len(secret))
	}
	// For each secret byte build a random degree k-1 polynomial with that byte
	// as the constant term, then evaluate at each x.
	coeffs := make([]byte, k)
	for bi, s := range secret {
		coeffs[0] = s
		if _, err := rand.Read(coeffs[1:]); err != nil {
			return nil, err
		}
		// The top coefficient must be non-zero so the polynomial truly has
		// degree k-1 (otherwise the effective threshold drops).
		for coeffs[k-1] == 0 {
			if _, err := rand.Read(coeffs[k-1 : k]); err != nil {
				return nil, err
			}
		}
		for x := 1; x <= n; x++ {
			shares[byte(x)][bi] = evalPoly(coeffs, byte(x))
		}
	}
	Zero(coeffs)
	return shares, nil
}

// combineBytes reconstructs the secret from >= k shares via Lagrange
// interpolation at x = 0.
func combineBytes(xs []byte, ys [][]byte) ([]byte, error) {
	if len(xs) == 0 || len(xs) != len(ys) {
		return nil, errors.New("mismatched shares")
	}
	// all shares must be the same length
	L := len(ys[0])
	for _, y := range ys {
		if len(y) != L {
			return nil, errors.New("shares have different lengths")
		}
	}
	// reject duplicate x values (would divide by zero and is user error)
	seen := map[byte]bool{}
	for _, x := range xs {
		if seen[x] {
			return nil, errors.New("duplicate share index provided")
		}
		seen[x] = true
	}
	secret := make([]byte, L)
	for bi := 0; bi < L; bi++ {
		var acc byte
		for i := range xs {
			num := byte(1)
			den := byte(1)
			for j := range xs {
				if i == j {
					continue
				}
				num = gfMul(num, xs[j])          // (0 - x_j) = x_j in GF(256)
				den = gfMul(den, xs[i]^xs[j])    // (x_i - x_j) = x_i XOR x_j
			}
			term := gfMul(ys[i][bi], gfDiv(num, den))
			acc ^= term
		}
		secret[bi] = acc
	}
	return secret, nil
}

// --- share text encoding ----------------------------------------------------

// Format:  seedforge-shamir-v1:<k>:<x>:<hex(y-bytes)>:<crc8hex>
// crc = first byte of SHA-256 over "k|x|ybytes", to catch transcription typos.
const shareMagic = "seedforge-shamir-v1"

func shareCRC(k int, x byte, y []byte) byte {
	h := sha256.New()
	fmt.Fprintf(h, "%d|%d|", k, x)
	h.Write(y)
	return h.Sum(nil)[0]
}

func encodeShares(k, n int, shares map[byte][]byte) []string {
	out := make([]string, 0, n)
	for x := 1; x <= n; x++ {
		y := shares[byte(x)]
		crc := shareCRC(k, byte(x), y)
		out = append(out, fmt.Sprintf("%s:%d:%d:%s:%02x", shareMagic, k, x, hex.EncodeToString(y), crc))
	}
	return out
}

type parsedShare struct {
	k int
	x byte
	y []byte
}

func parseShare(s string) (*parsedShare, error) {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ":")
	if len(parts) != 5 || parts[0] != shareMagic {
		return nil, fmt.Errorf("not a valid share (expected %s:...)", shareMagic)
	}
	k, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, errors.New("bad threshold field in share")
	}
	xv, err := strconv.Atoi(parts[2])
	if err != nil || xv < 1 || xv > 255 {
		return nil, errors.New("bad index field in share")
	}
	y, err := hex.DecodeString(parts[3])
	if err != nil {
		return nil, errors.New("bad hex payload in share")
	}
	var crc byte
	if _, err := fmt.Sscanf(parts[4], "%02x", &crc); err != nil {
		return nil, errors.New("bad crc field in share")
	}
	if shareCRC(k, byte(xv), y) != crc {
		return nil, errors.New("share failed integrity check (mistyped?)")
	}
	return &parsedShare{k: k, x: byte(xv), y: y}, nil
}

// combineShareStrings parses share strings and reconstructs the secret,
// enforcing that at least the threshold count is present and consistent.
func combineShareStrings(strs []string) ([]byte, error) {
	if len(strs) == 0 {
		return nil, errors.New("no shares provided")
	}
	var xs []byte
	var ys [][]byte
	k := -1
	for _, s := range strs {
		ps, err := parseShare(s)
		if err != nil {
			return nil, err
		}
		if k == -1 {
			k = ps.k
		} else if k != ps.k {
			return nil, errors.New("shares are from different splits (threshold mismatch)")
		}
		xs = append(xs, ps.x)
		ys = append(ys, ps.y)
	}
	if len(xs) < k {
		return nil, fmt.Errorf("need at least %d shares, got %d", k, len(xs))
	}
	return combineBytes(xs, ys)
}
