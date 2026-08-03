package com.speedevs.seedforge;

import android.app.Activity;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.text.InputType;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup.LayoutParams;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.nio.charset.StandardCharsets;

/**
 * SeedForge - offline BIP-39 seed phrase generator.
 *
 * Security properties of this app:
 *   - The manifest declares NO android.permission.INTERNET, so the process is
 *     physically unable to open a network socket. It is offline by construction.
 *   - FLAG_SECURE is set, so the OS blocks screenshots and screen recording of
 *     this window (and hides it from the recent-apps thumbnail).
 *   - The phrase is shown on screen only; it is never copied to the clipboard,
 *     saved to disk, or logged.
 *   - Randomness is the kernel-backed SecureRandom; optional user entropy can be
 *     mixed in. The wordlist is SHA-256 verified before use.
 *
 * NOTE: this class deliberately avoids anonymous inner classes (it implements
 * OnClickListener itself and dispatches by tag) so it dexes cleanly with the
 * command-line d8 toolchain.
 */
public class MainActivity extends Activity implements View.OnClickListener {

    private static final int BG    = 0xFF0A0A0F;
    private static final int PANEL = 0xFF13131C;
    private static final int GREEN = 0xFF00FF9C;
    private static final int CYAN  = 0xFF00D9FF;
    private static final int AMBER = 0xFFFFB000;
    private static final int DIM   = 0xFF6A6A7A;
    private static final int TXT   = 0xFFE8E8F0;

    private final int[] WORD_OPTIONS = {12, 15, 18, 21, 24};
    private int selectedWords = 24;
    private final Button[] segButtons = new Button[5];

    private EditText extraField;
    private TextView output;
    private Button generateBtn;
    private Button clearBtn;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Block screenshots / screen recording / recents preview of key material.
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                             WindowManager.LayoutParams.FLAG_SECURE);

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(BG);
        scroll.setFillViewport(true);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(22);
        root.setPadding(pad, dp(28), pad, dp(28));
        scroll.addView(root);

        TextView title = new TextView(this);
        title.setText("SEEDFORGE");
        title.setTextColor(GREEN);
        title.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 30);
        title.setLetterSpacing(0.18f);
        root.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText("offline BIP-39 seed generator");
        subtitle.setTextColor(CYAN);
        subtitle.setTypeface(Typeface.MONOSPACE);
        subtitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        subtitle.setPadding(0, dp(2), 0, dp(14));
        root.addView(subtitle);

        TextView badge = new TextView(this);
        badge.setText("\u25CF  NO NETWORK PERMISSION \u2014 FULLY OFFLINE");
        badge.setTextColor(GREEN);
        badge.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        badge.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        badge.setBackground(panelBg(0xFF0E1F16, GREEN));
        badge.setPadding(dp(12), dp(9), dp(12), dp(9));
        root.addView(badge, marginParams(0, dp(4), 0, dp(6)));

        TextView shots = new TextView(this);
        shots.setText("Screenshots & screen-recording are disabled on this screen.");
        shots.setTextColor(DIM);
        shots.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        shots.setPadding(0, 0, 0, dp(18));
        root.addView(shots);

        root.addView(label("PHRASE LENGTH"));

        LinearLayout seg = new LinearLayout(this);
        seg.setOrientation(LinearLayout.HORIZONTAL);
        for (int i = 0; i < WORD_OPTIONS.length; i++) {
            Button b = new Button(this);
            b.setAllCaps(false);
            b.setText(String.valueOf(WORD_OPTIONS[i]));
            b.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
            b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, dp(46), 1f);
            if (i > 0) lp.leftMargin = dp(8);
            b.setLayoutParams(lp);
            b.setTag(Integer.valueOf(i));
            b.setOnClickListener(this);
            segButtons[i] = b;
            seg.addView(b);
        }
        root.addView(seg, marginParams(0, dp(6), 0, dp(4)));
        restyleSegments();

        TextView wordsHint = new TextView(this);
        wordsHint.setText("24 words = 256-bit entropy (strongest). 12 = 128-bit.");
        wordsHint.setTextColor(DIM);
        wordsHint.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        wordsHint.setPadding(0, dp(2), 0, dp(18));
        root.addView(wordsHint);

        root.addView(label("EXTRA ENTROPY  (optional)"));
        extraField = new EditText(this);
        extraField.setHint("dice rolls, coin flips, random typing\u2026");
        extraField.setHintTextColor(DIM);
        extraField.setTextColor(TXT);
        extraField.setTypeface(Typeface.MONOSPACE);
        extraField.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        extraField.setInputType(InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        extraField.setMinLines(2);
        extraField.setGravity(Gravity.TOP | Gravity.START);
        extraField.setBackground(panelBg(PANEL, 0xFF2A2A3A));
        extraField.setPadding(dp(12), dp(10), dp(12), dp(10));
        root.addView(extraField, marginParams(0, dp(6), 0, dp(4)));

        TextView entHint = new TextView(this);
        entHint.setText("Folded into the OS randomness. Even a compromised RNG can't\ndetermine your phrase if you add real randomness here.");
        entHint.setTextColor(DIM);
        entHint.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        entHint.setPadding(0, dp(2), 0, dp(20));
        root.addView(entHint);

        generateBtn = new Button(this);
        generateBtn.setAllCaps(false);
        generateBtn.setText("\u26A1  GENERATE SEED PHRASE");
        generateBtn.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        generateBtn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        generateBtn.setTextColor(0xFF07120C);
        generateBtn.setBackground(solidBg(GREEN));
        generateBtn.setOnClickListener(this);
        root.addView(generateBtn, new LinearLayout.LayoutParams(LayoutParams.MATCH_PARENT, dp(56)));

        output = new TextView(this);
        output.setText("Your phrase will appear here.\nWrite it on paper \u2014 never type it into any website.");
        output.setTextColor(GREEN);
        output.setTypeface(Typeface.MONOSPACE);
        output.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        output.setLineSpacing(dp(3), 1f);
        output.setBackground(panelBg(0xFF0C0C12, 0xFF203026));
        output.setPadding(dp(16), dp(16), dp(16), dp(16));
        output.setTextIsSelectable(false);
        root.addView(output, marginParams(0, dp(18), 0, dp(14)));

        TextView warn = new TextView(this);
        warn.setText("Anyone who sees these words controls the funds. There is no\nrecovery if they are lost. Store them offline, on paper or metal.");
        warn.setTextColor(AMBER);
        warn.setTypeface(Typeface.MONOSPACE);
        warn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        root.addView(warn, marginParams(0, 0, 0, dp(16)));

        clearBtn = new Button(this);
        clearBtn.setAllCaps(false);
        clearBtn.setText("Clear screen");
        clearBtn.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        clearBtn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        clearBtn.setTextColor(CYAN);
        clearBtn.setBackground(panelBg(0x00000000, 0xFF244049));
        clearBtn.setOnClickListener(this);
        root.addView(clearBtn, new LinearLayout.LayoutParams(LayoutParams.MATCH_PARENT, dp(48)));

        TextView foot = new TextView(this);
        foot.setText("SeedForge \u00B7 by @speedevs \u00B7 no telemetry \u00B7 open source");
        foot.setTextColor(DIM);
        foot.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
        foot.setGravity(Gravity.CENTER);
        foot.setPadding(0, dp(20), 0, 0);
        root.addView(foot);

        setContentView(scroll);
    }

    @Override
    public void onClick(View v) {
        if (v == generateBtn) {
            onGenerate();
        } else if (v == clearBtn) {
            output.setTextColor(GREEN);
            output.setText("Cleared.");
            extraField.setText("");
        } else {
            Object tag = v.getTag();
            if (tag instanceof Integer) {
                selectedWords = WORD_OPTIONS[((Integer) tag).intValue()];
                restyleSegments();
            }
        }
    }

    private void onGenerate() {
        String extra = extraField.getText().toString();
        byte[] ex = extra.getBytes(StandardCharsets.UTF_8);
        try {
            String mnemonic = Bip39.generate(this, selectedWords, ex);
            output.setTextColor(GREEN);
            output.setText(numbered(mnemonic));
        } catch (Throwable t) {
            output.setTextColor(AMBER);
            output.setText("Generation failed: " + t.getMessage());
        } finally {
            Bip39.wipe(ex);
        }
    }

    private String numbered(String mnemonic) {
        String[] w = mnemonic.split(" ");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < w.length; i++) {
            sb.append(String.format("%2d.  %s", Integer.valueOf(i + 1), w[i]));
            if (i < w.length - 1) sb.append('\n');
        }
        return sb.toString();
    }

    private void restyleSegments() {
        for (int i = 0; i < segButtons.length; i++) {
            boolean sel = WORD_OPTIONS[i] == selectedWords;
            Button b = segButtons[i];
            if (sel) {
                b.setBackground(solidBg(GREEN));
                b.setTextColor(0xFF07120C);
            } else {
                b.setBackground(panelBg(PANEL, 0xFF2E2E40));
                b.setTextColor(GREEN);
            }
        }
    }

    private GradientDrawable panelBg(int fill, int stroke) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(fill);
        g.setCornerRadius(dp(12));
        g.setStroke(dp(1), stroke);
        return g;
    }

    private GradientDrawable solidBg(int fill) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(fill);
        g.setCornerRadius(dp(12));
        return g;
    }

    private TextView label(String s) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextColor(DIM);
        t.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        t.setLetterSpacing(0.1f);
        return t;
    }

    private LinearLayout.LayoutParams marginParams(int l, int t, int r, int b) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT);
        lp.setMargins(l, t, r, b);
        return lp;
    }

    private int dp(float v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}
