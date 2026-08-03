// SeedForge — an offline BIP-39 seed phrase generator.
//
// Security model (read this):
//   - The program makes NO network connections. There is no "net" import
//     anywhere in the source; the compiled binary cannot open a socket.
//   - Randomness comes only from the OS CSPRNG (crypto/rand).
//   - Nothing is written to disk or logged. The phrase exists only on screen.
//   - The embedded wordlist is SHA-256 verified at startup.
//   - Best-effort memory scrubbing of entropy/seed buffers after use.
//
// It still cannot protect you from a compromised operating system (keyloggers,
// screen capture, RAM scrapers). For real value, run it on a clean, offline
// machine and write the phrase on paper. See SECURITY.md.
package main

import (
	"bufio"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const version = "1.0.0"

const banner = `
  ███████╗███████╗███████╗██████╗ ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
  ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
  ███████╗█████╗  █████╗  ██║  ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
  ╚════██║██╔══╝  ██╔══╝  ██║  ██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
  ███████║███████╗███████╗██████╔╝██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
  ╚══════╝╚══════╝╚══════╝╚═════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
        offline BIP-39 seed generator · no network · v` + version + `
`

func main() {
	var (
		words      = flag.Int("words", 24, "word count: 12, 15, 18, 21 or 24")
		extra      = flag.String("extra", "", "optional extra entropy to mix in (dice rolls, coin flips, random text)")
		passphrase = flag.String("passphrase", "", "optional BIP-39 passphrase (25th word) for seed derivation")
		showSeed   = flag.Bool("seed", false, "also derive and print the 64-byte BIP-39 seed (hex)")
		showEnt    = flag.Bool("entropy", false, "also print the raw entropy (hex)")
		verify     = flag.String("verify", "", "validate an existing phrase instead of generating")
		selftest   = flag.Bool("selftest", false, "run BIP-39 test vectors and exit")
		batch      = flag.Bool("batch", false, "non-interactive: print one phrase and exit")
	)
	flag.Parse()

	// Always self-verify correctness before doing anything sensitive.
	if err := runSelfTest(!*selftest); err != nil {
		fmt.Fprintln(os.Stderr, "FATAL self-test failure:", err)
		os.Exit(2)
	}
	if *selftest {
		return
	}

	if *verify != "" {
		printVerify(*verify)
		return
	}

	if *batch || flagPassed("words") || flagPassed("extra") || flagPassed("passphrase") {
		generateOnce(*words, []byte(*extra), *passphrase, *showSeed, *showEnt)
		return
	}

	interactive()
}

func flagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// ---------------------------------------------------------------------------
// Self-test: prove the implementation matches the official BIP-39 vectors.
// ---------------------------------------------------------------------------

func runSelfTest(silent bool) error {
	type vec struct {
		entropyHex string
		mnemonic   string
	}
	vectors := []vec{
		{"00000000000000000000000000000000",
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"},
		{"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
			"legal winner thank year wave sausage worth useful legal winner thank yellow"},
		{"8080808080808080808080808080808080808080808080808080808080808080",
			"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"},
		{"0000000000000000000000000000000000000000000000000000000000000000",
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"},
	}
	for i, v := range vectors {
		ent, _ := hex.DecodeString(v.entropyHex)
		got, err := EntropyToMnemonic(ent)
		if err != nil {
			return fmt.Errorf("vector %d: %w", i, err)
		}
		if got != v.mnemonic {
			return fmt.Errorf("vector %d mismatch:\n  want %q\n  got  %q", i, v.mnemonic, got)
		}
		if !ValidateMnemonic(got) {
			return fmt.Errorf("vector %d failed round-trip validation", i)
		}
	}
	// Seed derivation vector (Trezor): first vector + passphrase "TREZOR".
	const wantSeed = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
	seed := MnemonicToSeed(vectors[0].mnemonic, "TREZOR")
	if hex.EncodeToString(seed) != wantSeed {
		return fmt.Errorf("seed derivation vector mismatch")
	}
	Zero(seed)

	if !silent {
		fmt.Print(banner)
		fmt.Printf("Self-test: %d mnemonic vectors + seed derivation vector — ALL PASSED\n", len(vectors))
		fmt.Println("Wordlist SHA-256 verified:", wordlistSHA256)
	}
	return nil
}

// ---------------------------------------------------------------------------
// One-shot generation (flag / batch mode).
// ---------------------------------------------------------------------------

func generateOnce(words int, extra []byte, passphrase string, seed, ent bool) {
	m, entropy, err := GenerateMnemonic(words, extra)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	defer Zero(entropy)

	fmt.Println(m)
	if ent {
		fmt.Println("entropy:", hex.EncodeToString(entropy))
	}
	if seed {
		s := MnemonicToSeed(m, passphrase)
		fmt.Println("seed:", hex.EncodeToString(s))
		Zero(s)
	}
}

// ---------------------------------------------------------------------------
// Verification.
// ---------------------------------------------------------------------------

func printVerify(phrase string) {
	entropy, err := MnemonicToEntropy(phrase)
	if err != nil {
		fmt.Printf("INVALID: %v\n", err)
		os.Exit(1)
	}
	defer Zero(entropy)
	n := len(strings.Fields(NormalizeMnemonic(phrase)))
	fmt.Printf("VALID · %d words · %d bits entropy · checksum OK\n", n, len(entropy)*8)
}

// ---------------------------------------------------------------------------
// Interactive menu (default when launched with no arguments — e.g. a
// double-click on Windows).
// ---------------------------------------------------------------------------

func interactive() {
	in := bufio.NewScanner(os.Stdin)
	fmt.Print(banner)
	for {
		fmt.Print(`
  [1] Generate a seed phrase
  [2] Advanced generate (extra entropy · passphrase · derive seed)
  [3] Verify an existing phrase
  [4] Security notes
  [5] Exit

  Select > `)
		if !in.Scan() {
			return
		}
		switch strings.TrimSpace(in.Text()) {
		case "1":
			doGenerate(in, false)
		case "2":
			doGenerate(in, true)
		case "3":
			doVerify(in)
		case "4":
			printSecurityNotes()
		case "5", "q", "quit", "exit":
			fmt.Println("\n  Stay safe. Wipe the screen when you're done.")
			return
		default:
			fmt.Println("  Unknown option.")
		}
	}
}

func askWordCount(in *bufio.Scanner) int {
	for {
		fmt.Print("  Word count [12/15/18/21/24] (default 24): ")
		if !in.Scan() {
			return 24
		}
		t := strings.TrimSpace(in.Text())
		if t == "" {
			return 24
		}
		if n, err := strconv.Atoi(t); err == nil {
			if _, ok := entropyBitsForWords(n); ok {
				return n
			}
		}
		fmt.Println("  Must be 12, 15, 18, 21 or 24.")
	}
}

func doGenerate(in *bufio.Scanner, advanced bool) {
	words := askWordCount(in)

	var extra []byte
	passphrase := ""
	if advanced {
		fmt.Println("\n  Extra entropy is OPTIONAL. Roll dice, flip coins, or mash the keyboard.")
		fmt.Println("  It is folded into the OS randomness so even a compromised RNG can't")
		fmt.Println("  determine your phrase. Leave blank to use OS randomness alone.")
		fmt.Print("  Extra entropy > ")
		if in.Scan() {
			extra = []byte(strings.TrimSpace(in.Text()))
		}
		fmt.Print("\n  BIP-39 passphrase for seed derivation (optional, blank = none): ")
		if in.Scan() {
			passphrase = strings.TrimSpace(in.Text())
		}
	}

	m, entropy, err := GenerateMnemonic(words, extra)
	Zero(extra)
	if err != nil {
		fmt.Println("  error:", err)
		return
	}
	defer Zero(entropy)

	printPhrase(m)
	fmt.Printf("\n  entropy (%d-bit): %s\n", len(entropy)*8, hex.EncodeToString(entropy))
	fmt.Print("  checksum: ")
	if ValidateMnemonic(m) {
		fmt.Println("VALID (self-verified)")
	} else {
		fmt.Println("*** FAILED — do not use ***")
	}

	if advanced {
		s := MnemonicToSeed(m, passphrase)
		fmt.Println("\n  BIP-39 seed (PBKDF2-HMAC-SHA512, 2048 rounds):")
		fmt.Println("    " + hex.EncodeToString(s))
		if passphrase != "" {
			fmt.Println("  (a different passphrase yields a completely different wallet)")
		}
		Zero(s)
	}

	fmt.Println("\n  " + strings.Repeat("!", 60))
	fmt.Println("  Write these words on PAPER, in order. Never type them into any")
	fmt.Println("  website, wallet import box, chat, or photo. Anyone with these")
	fmt.Println("  words controls the funds. There is no recovery if they are lost.")
	fmt.Println("  " + strings.Repeat("!", 60))
	pause(in)
}

func doVerify(in *bufio.Scanner) {
	fmt.Print("\n  Paste the phrase to verify:\n  > ")
	if !in.Scan() {
		return
	}
	phrase := in.Text()
	entropy, err := MnemonicToEntropy(phrase)
	if err != nil {
		fmt.Printf("\n  INVALID: %v\n", err)
		pause(in)
		return
	}
	defer Zero(entropy)
	n := len(strings.Fields(NormalizeMnemonic(phrase)))
	fmt.Printf("\n  VALID  ·  %d words  ·  %d-bit entropy  ·  checksum OK\n", n, len(entropy)*8)
	pause(in)
}

func printPhrase(m string) {
	words := strings.Fields(m)
	fmt.Printf("\n  Your %d-word phrase:\n\n", len(words))
	for i, w := range words {
		fmt.Printf("  %2d. %-10s", i+1, w)
		if (i+1)%3 == 0 {
			fmt.Println()
		}
	}
	if len(words)%3 != 0 {
		fmt.Println()
	}
}

func printSecurityNotes() {
	fmt.Print(`
  SECURITY NOTES
  --------------
  * This tool never touches the network. Best practice: run it on a
    computer that has Wi-Fi/Ethernet physically OFF or that is wiped after.
  * Randomness is the OS CSPRNG (getrandom / BCryptGenRandom). Add your own
    dice/coin entropy in "Advanced" if you don't fully trust the machine.
  * Nothing is saved or logged. The phrase lives only in this window.
  * Verify: type the phrase back in option [3] to confirm the checksum.
  * Threats this CANNOT stop: keyloggers, screen recorders, RAM scrapers,
    shoulder-surfers, cameras. A clean/offline device is your job.
  * Store the words on paper or metal, offline, ideally in two places.
`)
}

func pause(in *bufio.Scanner) {
	fmt.Print("\n  Press Enter to return to the menu (clears prompt)... ")
	in.Scan()
	// Push the sensitive output up out of easy view.
	fmt.Print(strings.Repeat("\n", 40))
}

// keep the sha512 import used even if seed features are compiled out in forks
var _ = sha512.Size
