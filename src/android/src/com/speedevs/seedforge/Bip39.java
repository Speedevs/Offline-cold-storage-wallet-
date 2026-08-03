package com.speedevs.seedforge;

import android.content.Context;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * BIP-39 mnemonic generation and validation for Android.
 *
 * Uses only the platform's java.security primitives. Randomness comes from
 * {@link SecureRandom}, which on Android is backed by the kernel CSPRNG.
 * The 2048-word English wordlist is loaded from assets and its SHA-256 is
 * verified before use, so a tampered asset cannot silently change results.
 */
public final class Bip39 {

    /** Canonical SHA-256 of the official BIP-39 English wordlist. */
    private static final String WORDLIST_SHA256 =
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

    private static String[] WORDLIST;
    private static Map<String, Integer> INDEX;

    private Bip39() {}

    /** Load and integrity-check the wordlist from assets. Safe to call repeatedly. */
    public static synchronized void ensureLoaded(Context ctx) throws Exception {
        if (WORDLIST != null) return;
        byte[] raw;
        try (InputStream in = ctx.getAssets().open("english.txt")) {
            raw = readAll(in);
        }
        String hash = toHex(sha256(raw));
        if (!hash.equals(WORDLIST_SHA256)) {
            throw new SecurityException("Wordlist integrity check FAILED — refusing to run");
        }
        List<String> words = new ArrayList<>(2048);
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(new java.io.ByteArrayInputStream(raw), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) words.add(line);
            }
        }
        if (words.size() != 2048) {
            throw new IllegalStateException("Wordlist must contain 2048 words, found " + words.size());
        }
        WORDLIST = words.toArray(new String[0]);
        INDEX = new HashMap<>(4096);
        for (int i = 0; i < WORDLIST.length; i++) INDEX.put(WORDLIST[i], i);
    }

    private static int entropyBitsForWords(int words) {
        switch (words) {
            case 12: return 128;
            case 15: return 160;
            case 18: return 192;
            case 21: return 224;
            case 24: return 256;
            default: return -1;
        }
    }

    /**
     * Generate a fresh mnemonic using the system CSPRNG, optionally folding in
     * user-supplied extra entropy. When extraEntropy is non-empty the entropy is
     * the leftmost bytes of SHA-512(system || user), so a compromised system RNG
     * cannot determine the phrase as long as the user contributes real entropy.
     */
    public static String generate(Context ctx, int words, byte[] extraEntropy) throws Exception {
        ensureLoaded(ctx);
        int bits = entropyBitsForWords(words);
        if (bits < 0) throw new IllegalArgumentException("Word count must be 12/15/18/21/24");

        byte[] entropy = new byte[bits / 8];
        SecureRandom rng = new SecureRandom();       // kernel-backed CSPRNG
        rng.nextBytes(entropy);

        if (extraEntropy != null && extraEntropy.length > 0) {
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            sha512.update(entropy);
            sha512.update(extraEntropy);
            byte[] digest = sha512.digest();
            byte[] mixed = new byte[entropy.length];
            System.arraycopy(digest, 0, mixed, 0, mixed.length);
            wipe(entropy);
            wipe(digest);
            entropy = mixed;
        }

        String mnemonic = entropyToMnemonic(entropy);
        wipe(entropy);
        return mnemonic;
    }

    /** Convert entropy bytes (16/20/24/28/32) into a BIP-39 mnemonic. */
    public static String entropyToMnemonic(byte[] entropy) throws Exception {
        int ent = entropy.length * 8;
        if (ent < 128 || ent > 256 || ent % 32 != 0) {
            throw new IllegalArgumentException("Entropy must be 128–256 bits in 32-bit steps");
        }
        int cs = ent / 32;
        byte[] hash = sha256(entropy);

        byte[] combined = new byte[entropy.length + 1];
        System.arraycopy(entropy, 0, combined, 0, entropy.length);
        combined[entropy.length] = hash[0]; // cs <= 8

        int nWords = (ent + cs) / 11;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < nWords; i++) {
            if (i > 0) sb.append(' ');
            sb.append(WORDLIST[readBits(combined, i * 11, 11)]);
        }
        return sb.toString();
    }

    /** Validate word membership and checksum. Returns null if valid, else a reason. */
    public static String validationError(Context ctx, String mnemonic) {
        try {
            ensureLoaded(ctx);
            String[] words = mnemonic.trim().toLowerCase().split("\\s+");
            if (entropyBitsForWords(words.length) < 0) {
                return "Phrase must have 12/15/18/21/24 words (got " + words.length + ")";
            }
            int totalBits = words.length * 11;
            int ent = totalBits / 33 * 32;
            int csLen = totalBits - ent;

            byte[] bits = new byte[(totalBits + 7) / 8];
            int pos = 0;
            for (String w : words) {
                Integer idx = INDEX.get(w);
                if (idx == null) return "Word not in wordlist: " + w;
                for (int b = 10; b >= 0; b--) {
                    if (((idx >> b) & 1) == 1) bits[pos / 8] |= (1 << (7 - (pos % 8)));
                    pos++;
                }
            }
            byte[] entropy = new byte[ent / 8];
            System.arraycopy(bits, 0, entropy, 0, entropy.length);
            byte[] hash = sha256(entropy);
            for (int i = 0; i < csLen; i++) {
                int want = (hash[i / 8] >> (7 - (i % 8))) & 1;
                int got = readBits(bits, ent + i, 1);
                if (want != got) return "Checksum mismatch — phrase invalid or mistyped";
            }
            wipe(entropy);
            return null;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // ---- helpers ----

    private static int readBits(byte[] data, int start, int n) {
        int v = 0;
        for (int i = 0; i < n; i++) {
            int p = start + i;
            int bit = (data[p / 8] >> (7 - (p % 8))) & 1;
            v = (v << 1) | bit;
        }
        return v;
    }

    private static byte[] sha256(byte[] b) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(b);
    }

    private static byte[] readAll(InputStream in) throws Exception {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
        return out.toByteArray();
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(Character.forDigit((x >> 4) & 0xF, 16))
                            .append(Character.forDigit(x & 0xF, 16));
        return sb.toString();
    }

    public static void wipe(byte[] b) {
        if (b != null) java.util.Arrays.fill(b, (byte) 0);
    }
}
