package main

// SeedForge Wallet — offline HD key derivation + encrypted/Shamir backup.
//
// This binary NEVER touches the network (no net import anywhere in the module)
// and NEVER writes secrets to disk except the encrypted .vlk vault you ask for.
// Secrets are only printed to your local terminal when you explicitly opt in.

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "gen":
		err = cmdGen(os.Args[2:])
	case "derive":
		err = cmdDerive(os.Args[2:])
	case "xpub":
		err = cmdXpub(os.Args[2:])
	case "multisig":
		err = cmdMultisig(os.Args[2:])
	case "vault-create":
		err = cmdVaultCreate(os.Args[2:])
	case "vault-open":
		err = cmdVaultOpen(os.Args[2:])
	case "vault-inspect":
		err = cmdVaultInspect(os.Args[2:])
	case "split":
		err = cmdSplit(os.Args[2:])
	case "combine":
		err = cmdCombine(os.Args[2:])
	case "selftest":
		err = cmdSelftest()
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`SeedForge Wallet — offline HD derivation & backup

USAGE
  seedforge-wallet <command> [flags]

COMMANDS
  gen            Generate a fresh BIP-39 mnemonic (OS CSPRNG, offline)
  derive         Derive BIP-44/BIP-84 addresses from a mnemonic
  xpub           Export an account xpub + fingerprint (share for multisig)
  multisig       Build offline k-of-n BTC multisig addresses from cosigner xpubs
  vault-create   Encrypt a mnemonic into a password-protected .vlk file
  vault-open     Decrypt and show a mnemonic from a .vlk file
  vault-inspect  Show a .vlk file's (non-secret) KDF/cipher parameters
  split          Split a mnemonic into N-of-M Shamir shares
  combine        Reconstruct a mnemonic from Shamir shares
  selftest       Verify all crypto against known test vectors

Run 'seedforge-wallet <command> -h' for command flags.
Secrets print only to your terminal, never over any network. Stay offline.
`)
}

// ---- helpers ---------------------------------------------------------------

// stdinReader is shared across readSecret calls so that piping multiple lines
// (password + confirmation) doesn't lose buffered input between reads.
var stdinReader *bufio.Reader

// readSecret reads a passphrase without echo from a TTY, or a plain line when
// stdin is piped (so the tool is scriptable/testable). Piped use is less safe.
func readSecret(prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return b, err
	}
	if stdinReader == nil {
		stdinReader = bufio.NewReader(os.Stdin)
	}
	line, err := stdinReader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return nil, err
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

func mustMnemonic(m string) (string, error) {
	m = NormalizeMnemonic(m)
	if m == "" {
		return "", errors.New("empty mnemonic")
	}
	if !ValidateMnemonic(m) {
		return "", errors.New("mnemonic failed BIP-39 checksum/word validation")
	}
	return m, nil
}

func wordCount(m string) int { return len(strings.Fields(m)) }

// ---- commands --------------------------------------------------------------

func cmdGen(args []string) error {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	words := fs.Int("words", 24, "word count: 12,15,18,21,24")
	extra := fs.String("extra", "", "optional extra entropy folded into OS randomness")
	fs.Parse(args)
	m, ent, err := GenerateMnemonic(*words, []byte(*extra))
	if err != nil {
		return err
	}
	fmt.Println(m)
	fmt.Fprintf(os.Stderr, "entropy(%d-bit): %s\n", len(ent)*8, hex.EncodeToString(ent))
	Zero(ent)
	return nil
}

func cmdDerive(args []string) error {
	fs := flag.NewFlagSet("derive", flag.ExitOnError)
	mn := fs.String("mnemonic", "", "BIP-39 mnemonic (required)")
	pass := fs.String("passphrase", "", "optional BIP-39 passphrase (25th word)")
	coin := fs.String("coin", "eth", "eth | btc | btc-segwit")
	account := fs.Uint("account", 0, "account index")
	change := fs.Uint("change", 0, "change (0=external,1=internal)")
	index := fs.Uint("index", 0, "starting address index")
	count := fs.Int("count", 1, "how many consecutive addresses")
	showSecret := fs.Bool("show-secret", false, "ALSO print private keys/WIF (dangerous)")
	fs.Parse(args)

	m, err := mustMnemonic(*mn)
	if err != nil {
		return err
	}
	seed := MnemonicToSeed(m, *pass)
	defer Zero(seed)

	if *showSecret {
		fmt.Fprintln(os.Stderr, "!! printing PRIVATE KEYS — ensure nobody can see this screen and clear it after.")
	}
	for i := 0; i < *count; i++ {
		idx := uint32(*index) + uint32(i)
		acc, err := deriveAccount(seed, *coin, uint32(*account), uint32(*change), idx)
		if err != nil {
			return err
		}
		switch *coin {
		case "eth":
			fmt.Printf("%s  ETH  %s\n", acc.Path, acc.ETH)
			if *showSecret {
				fmt.Printf("            priv %s\n", ethPrivHex(acc.privKey))
			}
		case "btc":
			fmt.Printf("%s  BTC  %s\n", acc.Path, acc.BTCLeg)
			if *showSecret {
				fmt.Printf("            WIF  %s\n", btcWIF(acc.privKey))
			}
		case "btc-segwit":
			fmt.Printf("%s  BTC  %s\n", acc.Path, acc.BTCSeg)
			if *showSecret {
				fmt.Printf("            WIF  %s\n", btcWIF(acc.privKey))
			}
		}
		Zero(acc.privKey[:])
	}
	return nil
}

// default BIP-48 P2WSH account path for exporting a cosigner xpub.
const defaultMultisigPath = "m/48'/0'/0'/2'"

func cmdXpub(args []string) error {
	fs := flag.NewFlagSet("xpub", flag.ExitOnError)
	mn := fs.String("mnemonic", "", "BIP-39 mnemonic (required)")
	pass := fs.String("passphrase", "", "optional BIP-39 passphrase")
	path := fs.String("path", defaultMultisigPath, "account path to export")
	fs.Parse(args)
	m, err := mustMnemonic(*mn)
	if err != nil {
		return err
	}
	seed := MnemonicToSeed(m, *pass)
	defer Zero(seed)

	master, err := masterFromSeed(seed)
	if err != nil {
		return err
	}
	fp := master.fingerprint()
	acct, err := derivePath(seed, *path)
	if err != nil {
		return err
	}
	origin := strings.ReplaceAll(strings.TrimPrefix(*path, "m/"), "'", "h")
	fmt.Printf("master fingerprint: %x\n", fp[:])
	fmt.Printf("path:               %s\n", *path)
	fmt.Printf("xpub:               %s\n", acct.xpub())
	fmt.Printf("descriptor key:     [%x/%s]%s\n", fp[:], origin, acct.xpub())
	Zero(acct.priv[:])
	return nil
}

func cmdMultisig(args []string) error {
	fs := flag.NewFlagSet("multisig", flag.ExitOnError)
	threshold := fs.Int("threshold", 2, "required signatures (k)")
	script := fs.String("script", "wsh", "wsh (native segwit) | sh (legacy) | sh-wsh (wrapped)")
	change := fs.Uint("change", 0, "0 = receive, 1 = change")
	index := fs.Uint("index", 0, "starting address index")
	count := fs.Int("count", 1, "how many consecutive addresses")
	showDesc := fs.Bool("descriptor", true, "print the output descriptor for import/verification")
	var xpubFlags multiFlag
	fs.Var(&xpubFlags, "xpub", "a cosigner account xpub (repeat for each cosigner)")
	fs.Parse(args)

	if len(xpubFlags) < 2 {
		return errors.New("provide at least two -xpub cosigner keys")
	}
	if *threshold < 1 || *threshold > len(xpubFlags) {
		return fmt.Errorf("threshold %d invalid for %d cosigners", *threshold, len(xpubFlags))
	}
	parsed := make([]*extPub, len(xpubFlags))
	for i, x := range xpubFlags {
		p, err := parseXpub(x)
		if err != nil {
			return fmt.Errorf("cosigner %d: %w", i+1, err)
		}
		parsed[i] = p
	}

	if *showDesc {
		desc, err := buildDescriptor(*script, *threshold, xpubFlags, uint32(*change))
		if err != nil {
			return err
		}
		fmt.Printf("descriptor: %s\n\n", desc)
	}

	fmt.Fprintf(os.Stderr, "%d-of-%d %s multisig (BIP-67 sorted). Verify the descriptor in Sparrow/Core.\n\n",
		*threshold, len(xpubFlags), *script)
	for i := 0; i < *count; i++ {
		idx := uint32(*index) + uint32(i)
		pubs := make([][]byte, len(parsed))
		for j, p := range parsed {
			pk, err := deriveChildPub(p, uint32(*change), idx)
			if err != nil {
				return err
			}
			pubs[j] = pk
		}
		addr, err := multisigAddress(*script, *threshold, pubs)
		if err != nil {
			return err
		}
		fmt.Printf("m/.../%d/%d  %s\n", *change, idx, addr)
	}
	return nil
}

func cmdVaultCreate(args []string) error {
	fs := flag.NewFlagSet("vault-create", flag.ExitOnError)
	mn := fs.String("mnemonic", "", "mnemonic to protect (or omit to be prompted)")
	note := fs.String("note", "", "optional non-secret label stored in the vault")
	out := fs.String("out", "", "output .vlk path (required)")
	fs.Parse(args)
	if *out == "" {
		return errors.New("-out is required")
	}
	mnem := *mn
	if mnem == "" {
		b, err := readSecret("Mnemonic to protect: ")
		if err != nil {
			return err
		}
		mnem = string(b)
	}
	m, err := mustMnemonic(mnem)
	if err != nil {
		return err
	}
	pw, err := readSecret("New vault password: ")
	if err != nil {
		return err
	}
	pw2, err := readSecret("Confirm password:   ")
	if err != nil {
		return err
	}
	if !bytes.Equal(pw, pw2) {
		return errors.New("passwords do not match")
	}
	Zero(pw2)
	blob, err := EncryptVault(m, *note, wordCount(m), pw)
	Zero(pw)
	if err != nil {
		return err
	}
	// 0600 so other local users can't read the (encrypted, but still) file.
	if err := os.WriteFile(*out, blob, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %d bytes to %s (Argon2id + XChaCha20-Poly1305)\n", len(blob), *out)
	return nil
}

func cmdVaultOpen(args []string) error {
	fs := flag.NewFlagSet("vault-open", flag.ExitOnError)
	in := fs.String("in", "", "input .vlk path (required)")
	fs.Parse(args)
	if *in == "" {
		return errors.New("-in is required")
	}
	blob, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	pw, err := readSecret("Vault password: ")
	if err != nil {
		return err
	}
	payload, err := DecryptVault(blob, pw)
	Zero(pw)
	if err != nil {
		return err
	}
	fmt.Printf("mnemonic (%d words): %s\n", payload.Words, payload.Mnemonic)
	if payload.Note != "" {
		fmt.Fprintf(os.Stderr, "note: %s\n", payload.Note)
	}
	fmt.Fprintf(os.Stderr, "created: %s\n", payload.Created)
	return nil
}

func cmdVaultInspect(args []string) error {
	fs := flag.NewFlagSet("vault-inspect", flag.ExitOnError)
	in := fs.String("in", "", "input .vlk path (required)")
	fs.Parse(args)
	if *in == "" {
		return errors.New("-in is required")
	}
	blob, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	info, err := InspectVault(blob)
	if err != nil {
		return err
	}
	fmt.Println(info)
	return nil
}

func cmdSplit(args []string) error {
	fs := flag.NewFlagSet("split", flag.ExitOnError)
	mn := fs.String("mnemonic", "", "mnemonic to split (or omit to be prompted)")
	threshold := fs.Int("threshold", 2, "shares required to reconstruct (k)")
	shares := fs.Int("shares", 3, "total shares to produce (n)")
	fs.Parse(args)
	mnem := *mn
	if mnem == "" {
		b, err := readSecret("Mnemonic to split: ")
		if err != nil {
			return err
		}
		mnem = string(b)
	}
	m, err := mustMnemonic(mnem)
	if err != nil {
		return err
	}
	ent, err := MnemonicToEntropy(m)
	if err != nil {
		return err
	}
	sh, err := splitBytes(ent, *threshold, *shares)
	Zero(ent)
	if err != nil {
		return err
	}
	lines := encodeShares(*threshold, *shares, sh)
	fmt.Fprintf(os.Stderr, "%d shares, any %d reconstruct. Store each in a SEPARATE place.\n\n", *shares, *threshold)
	for _, l := range lines {
		fmt.Println(l)
	}
	return nil
}

func cmdCombine(args []string) error {
	fs := flag.NewFlagSet("combine", flag.ExitOnError)
	var shareFlags multiFlag
	fs.Var(&shareFlags, "share", "a share string (repeat for each); or pipe shares on stdin")
	fs.Parse(args)

	var strs []string
	strs = append(strs, shareFlags...)
	// also accept shares piped on stdin (one per line)
	if fi, _ := os.Stdin.Stat(); (fi.Mode() & os.ModeCharDevice) == 0 {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" {
				strs = append(strs, line)
			}
		}
	}
	if len(strs) == 0 {
		return errors.New("provide shares via -share or on stdin")
	}
	ent, err := combineShareStrings(strs)
	if err != nil {
		return err
	}
	m, err := EntropyToMnemonic(ent)
	Zero(ent)
	if err != nil {
		return err
	}
	fmt.Println(m)
	return nil
}

// multiFlag collects repeated -share flags.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error {
	*m = append(*m, s)
	return nil
}

// ---- self test -------------------------------------------------------------

func cmdSelftest() error {
	fail := 0
	check := func(name, got, want string) {
		if got == want {
			fmt.Printf("PASS  %s\n", name)
		} else {
			fail++
			fmt.Printf("FAIL  %s\n        got:  %s\n        want: %s\n", name, got, want)
		}
	}

	// BIP-32 official test vector 1: seed 000102...0f
	seed1, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	mk, err := masterFromSeed(seed1)
	if err != nil {
		return err
	}
	check("BIP32 v1 master xprv", mk.xprv(),
		"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
	check("BIP32 v1 master xpub", mk.xpub(),
		"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
	m0h, err := mk.child(hardened + 0)
	if err != nil {
		return err
	}
	check("BIP32 v1 m/0' xprv", m0h.xprv(),
		"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7")

	// BIP-39/44 vectors for the canonical all-zeros mnemonic.
	m := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	seed := MnemonicToSeed(m, "")
	check("BIP39 seed(abandon..about)", hex.EncodeToString(seed),
		"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")

	eth, _ := deriveAccount(seed, "eth", 0, 0, 0)
	check("ETH  m/44'/60'/0'/0/0", eth.ETH, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94")

	btc, _ := deriveAccount(seed, "btc", 0, 0, 0)
	check("BTC  m/44'/0'/0'/0/0 (P2PKH)", btc.BTCLeg, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA")
	check("BTC  WIF (compressed)", btcWIF(btc.privKey), "L4p2b9VAf8k5aUahF1JCJUzZkgNEAqLfq8DDdQiyAprQAKSbu8hf")

	seg, _ := deriveAccount(seed, "btc-segwit", 0, 0, 0)
	check("BTC  m/84'/0'/0'/0/0 (bech32)", seg.BTCSeg, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")

	// Shamir round-trips.
	ent, _ := MnemonicToEntropy(m)
	sh, err := splitBytes(ent, 3, 5)
	if err != nil {
		return err
	}
	tryCombine := func(idxs ...int) string {
		var xs []byte
		var ys [][]byte
		for _, i := range idxs {
			xs = append(xs, byte(i))
			ys = append(ys, sh[byte(i)])
		}
		rec, err := combineBytes(xs, ys)
		if err != nil {
			return "ERR:" + err.Error()
		}
		return hex.EncodeToString(rec)
	}
	want := hex.EncodeToString(ent)
	check("Shamir 3-of-5 combine {1,2,3}", tryCombine(1, 2, 3), want)
	check("Shamir 3-of-5 combine {2,4,5}", tryCombine(2, 4, 5), want)
	check("Shamir 3-of-5 combine {1,3,5}", tryCombine(1, 3, 5), want)
	// Encoded-share path + threshold enforcement.
	enc := encodeShares(3, 5, sh)
	rec, err := combineShareStrings([]string{enc[0], enc[2], enc[4]})
	if err != nil {
		return err
	}
	check("Shamir encoded-share combine", hex.EncodeToString(rec), want)
	if _, err := combineShareStrings([]string{enc[0], enc[1]}); err == nil {
		fail++
		fmt.Println("FAIL  Shamir under-threshold should error")
	} else {
		fmt.Println("PASS  Shamir under-threshold correctly rejected")
	}
	// tamper a share -> CRC must catch it
	bad := []byte(enc[0])
	if bad[len(bad)-1] == 'a' {
		bad[len(bad)-1] = 'b'
	} else {
		bad[len(bad)-1] = 'a'
	}
	if _, err := parseShare(string(bad)); err == nil {
		fail++
		fmt.Println("FAIL  Shamir mistyped-share should be rejected")
	} else {
		fmt.Println("PASS  Shamir mistyped-share correctly rejected")
	}

	// Vault round-trip.
	pw := []byte("correct horse battery staple")
	blob, err := EncryptVault(m, "selftest", 12, pw)
	if err != nil {
		return err
	}
	pl, err := DecryptVault(blob, pw)
	if err != nil {
		return err
	}
	check("Vault decrypt (right pw)", pl.Mnemonic, m)
	if _, err := DecryptVault(blob, []byte("wrong password!!")); err == nil {
		fail++
		fmt.Println("FAIL  Vault wrong-password should fail")
	} else {
		fmt.Println("PASS  Vault wrong-password correctly rejected")
	}

	// Multisig: xpub export, CKDpub, BIP-67 sorted addresses, descriptors.
	// Cosigner account xpubs at m/48'/0'/0'/2' for three known mnemonics,
	// cross-checked against embit (Specter) + bip_utils.
	msMnems := []string{
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"legal winner thank year wave sausage worth useful legal winner thank yellow",
		"letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
	}
	wantXpub := []string{
		"xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf",
		"xpub6FQya7zGhR92kacYsNnjreouvnHJMpXYsUXnW6NJJAJRCKsa26TzDy4LdnGhEurr3d6y1J8PJ7EEMKQp74XTqYvmGJNogYXSKDszYHtF8mX",
		"xpub6DnEBNkSJKBYQmsbhS1sP9cNdtU5c9PLFGCjTJmxicxc13WB8zNNGQazabQpyFAGW5bV9tMko4uBxDxjUKL6dSAcx1tEbgEHtgSqyRsekh6",
	}
	var xpubs []string
	for i, mm := range msMnems {
		s := MnemonicToSeed(mm, "")
		acct, _ := derivePath(s, defaultMultisigPath)
		check(fmt.Sprintf("Multisig xpub cosigner %d", i+1), acct.xpub(), wantXpub[i])
		xpubs = append(xpubs, acct.xpub())
	}
	// master fingerprint of cosigner 1
	mfp, _ := masterFromSeed(MnemonicToSeed(msMnems[0], ""))
	fpx := mfp.fingerprint()
	check("Multisig master fingerprint c1", fmt.Sprintf("%x", fpx[:]), "73c5da0a")

	msAddr := func(kind string, change, idx uint32) string {
		var pubs [][]byte
		for _, x := range xpubs {
			p, _ := parseXpub(x)
			pk, err := deriveChildPub(p, change, idx)
			if err != nil {
				return "ERR:" + err.Error()
			}
			pubs = append(pubs, pk)
		}
		a, err := multisigAddress(kind, 2, pubs)
		if err != nil {
			return "ERR:" + err.Error()
		}
		return a
	}
	check("Multisig 2of3 wsh    /0/0", msAddr("wsh", 0, 0), "bc1qm43n7nnev58aj3nrznz2xscgv98t7gxycq5pmp20a5vzfp5t0q2s7r6twa")
	check("Multisig 2of3 wsh    /0/1", msAddr("wsh", 0, 1), "bc1qh0jxweder0zfwz363juas8vhav6p4d4hmk6yx7kphd3gvf769fzq2dp3an")
	check("Multisig 2of3 sh     /0/0", msAddr("sh", 0, 0), "39tmmWUjbK9SeTK4L6vjZi7kEkPx4DjcJb")
	check("Multisig 2of3 sh-wsh /0/0", msAddr("sh-wsh", 0, 0), "3HTVa2FKu5zq9e95qEoJX8Cy5vBo5y9Ljc")

	// descriptor checksums (Bitcoin Core reference)
	dsum := func(kind string) string {
		d, err := buildDescriptor(kind, 2, xpubs, 0)
		if err != nil {
			return "ERR:" + err.Error()
		}
		return d[strings.LastIndex(d, "#")+1:]
	}
	check("Descriptor checksum wsh", dsum("wsh"), "0mht4nqm")
	check("Descriptor checksum sh", dsum("sh"), "akvz8wm4")
	check("Descriptor checksum sh-wsh", dsum("sh-wsh"), "f09ekcrp")

	fmt.Println()
	if fail == 0 {
		fmt.Println("ALL CHECKS PASSED")
		return nil
	}
	return fmt.Errorf("%d check(s) failed", fail)
}
