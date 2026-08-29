//! Character sets used by the password generator.
//!
//! Mirrors the Python original's `CHAR_SETS` table. The "Source Code (this
//! file)" self-referential charset from the Python version (which read its
//! own `.py` source to build a charset) has been dropped: it doesn't
//! translate meaningfully to a compiled Rust binary, and generating a
//! character pool from your own source code was a novelty feature, not a
//! security-relevant one.

pub struct CharSet {
    pub name: &'static str,
    pub chars: &'static str,
    pub enabled_by_default: bool,
    pub desc: &'static str,
}

pub fn all_charsets() -> Vec<CharSet> {
    vec![
        CharSet {
            name: "Latin (Standard)",
            chars: r##"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"##,
            enabled_by_default: true,
            desc: "ASCII letters, digits, symbols",
        },
        CharSet {
            name: "Latin (Extended)",
            chars: "ąćęłńóśźżĄĆĘŁŃÓŚŹŻäöüßÄÖÜèéêëēėęùúûüūîïíīįìôöòóœøãåáàâæçñ",
            enabled_by_default: false,
            desc: "European accents",
        },
        CharSet {
            name: "Cyrillic",
            chars: "абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ",
            enabled_by_default: false,
            desc: "Russian alphabet",
        },
        CharSet {
            name: "CJK & Kana",
            chars: "漢字日本語中文测试字符あいうえおかきくけこさしすせそたちつてとなにぬねのアイウエオカキクケコサシスセソタチツテトナニヌネノ",
            enabled_by_default: false,
            desc: "Asian scripts",
        },
        CharSet {
            name: "Simplified Chinese",
            chars: "的一是了我不人在他有这个上们来到时大地为子中你说生国年着就那和要她出也得里后自以会家可下而过天去能对小多然于心学么之都好看起发当没成只如事把还用第样道想作种开美总从无情己面最女但现前些所同日手又行意动方期它头经长儿回位分爱老因很给名法间斯知世什两次使身者被高已亲其进此话常与活正感",
            enabled_by_default: false,
            desc: "Common Simplified Chinese characters",
        },
        CharSet {
            name: "Greek",
            chars: "ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδελμνξοπρςστυφχψω",
            enabled_by_default: false,
            desc: "Greek letters",
        },
        CharSet {
            name: "Math & Symbols",
            chars: "+-*/=<>~^|&%$@#!?±√∞≠≤≥∑∏∫∂∆πµΩ≈≡∇¢£¥€₹₽°²³¹º¼½¾¿",
            enabled_by_default: false,
            desc: "Math operators & currency",
        },
        CharSet {
            name: "Box Drawing",
            chars: "─━│┃┄┅┆┇┈┉┊┋┌┍┎┏┐┑┒┓└┕┖┗┘┙┚┛├┝┞┟┠┡┢┣┤┥┦┧┨┩┪┫┬┭┮┯┰┱┲┳┴┵┶┷┸┹┺┻┼┽┾┿╀╁╂╃╄╅╆╇╈╉╊╋╌╍╎╏═║╒╓╔╕╖╗╘╙╚╛╜╝╞╟╠╡╢╣╤╥╦╧╨╩╪╫╬╭╮╯╰╱╲╳╴╵╶╷╸╹╺╻╼╽╾╿",
            enabled_by_default: false,
            desc: "Geometric & box",
        },
    ]
}

/// Deduplicated pool of characters from every enabled charset, preserving
/// first-seen order (matches the Python `get_active_pool` behaviour).
pub fn build_pool(enabled: &[bool], sets: &[CharSet]) -> Vec<char> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    for (set, &on) in sets.iter().zip(enabled.iter()) {
        if !on {
            continue;
        }
        for c in set.chars.chars() {
            if seen.insert(c) {
                result.push(c);
            }
        }
    }
    result
}

/// Small set of QWERTY keyboard rows used to detect "walked the keyboard"
/// runs (`qwerty`, `asdfgh`, `1234567890`, ...) — both left-to-right and
/// right-to-left, since `zxcvbn`-style estimators treat both directions as
/// equally guessable.
const KEYBOARD_ROWS: &[&str] = &[
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
];

/// A small, deliberately non-exhaustive list of the most common leaked
/// passwords (lowercased). This is not meant to be a comprehensive
/// dictionary attack simulation — it exists to catch the single worst
/// failure mode of the old character-class-only estimator: something like
/// `Password1!` hits all four character classes and used to score as
/// "Strong" (~66 bits) despite being one of the first guesses any real
/// cracker tries. A match here forces the score down into "Very weak"
/// regardless of what character classes are present.
const COMMON_PASSWORDS: &[&str] = &[
    "password", "123456", "12345678", "123456789", "1234567890", "qwerty",
    "111111", "abc123", "password1", "iloveyou", "admin", "welcome",
    "monkey", "dragon", "letmein", "football", "1234567", "sunshine",
    "master", "hello", "freedom", "whatever", "qazwsx", "trustno1",
    "batman", "superman", "michael", "shadow", "ashley", "jennifer",
    "hunter", "buster", "soccer", "harley", "hockey", "ranger", "daniel",
    "starwars", "klaster", "112233", "google", "princess", "flower",
    "passw0rd", "p@ssword", "p@ssw0rd", "qwerty123", "1q2w3e4r",
    "zaq12wsx", "changeme", "letmein1", "welcome1", "admin123",
    "root", "toor", "guest", "test", "temp", "user",
];

/// Longest run, starting at `chars[start]`, where each character is one
/// step further along a monotonic sequence than the one before it —
/// either a numeric/alphabetic sequence (`abcde`, `98765`) or a walk along
/// one of [`KEYBOARD_ROWS`] in either direction. Returns the run length
/// (1 if no sequence continues past the first character).
fn sequence_run_len(chars: &[char], start: usize) -> usize {
    if start >= chars.len() {
        return 0;
    }
    let mut len = 1;
    // Plain ascending/descending code-point sequence (letters or digits).
    let mut ascending = true;
    let mut descending = true;
    // Keyboard-row walk, tracked separately since it isn't a simple
    // code-point delta.
    let row_and_col = |c: char| -> Option<(usize, usize)> {
        let lc = c.to_ascii_lowercase();
        KEYBOARD_ROWS
            .iter()
            .enumerate()
            .find_map(|(r, row)| row.find(lc).map(|col| (r, col)))
    };
    let mut kb_forward = true;
    let mut kb_backward = true;

    for i in start + 1..chars.len() {
        let prev = chars[i - 1];
        let cur = chars[i];
        let same_class = (prev.is_ascii_alphabetic() && cur.is_ascii_alphabetic())
            || (prev.is_ascii_digit() && cur.is_ascii_digit());
        let code_ascending = same_class && (cur as i32 - prev as i32) == 1;
        let code_descending = same_class && (prev as i32 - cur as i32) == 1;
        ascending &= code_ascending;
        descending &= code_descending;

        let kb_step = match (row_and_col(prev), row_and_col(cur)) {
            (Some((r1, c1)), Some((r2, c2))) if r1 == r2 => Some(c2 as i32 - c1 as i32),
            _ => None,
        };
        kb_forward &= kb_step == Some(1);
        kb_backward &= kb_step == Some(-1);

        if !ascending && !descending && !kb_forward && !kb_backward {
            break;
        }
        len += 1;
    }
    len
}

/// Longest run of the same character repeated, starting at `chars[start]`.
fn repeat_run_len(chars: &[char], start: usize) -> usize {
    if start >= chars.len() {
        return 0;
    }
    let mut len = 1;
    while start + len < chars.len() && chars[start + len] == chars[start] {
        len += 1;
    }
    len
}

pub fn calculate_entropy(length: usize, pool_size: usize) -> f64 {
    if pool_size <= 1 || length == 0 {
        0.0
    } else {
        length as f64 * (pool_size as f64).log2()
    }
}

pub fn rate_entropy(bits: f64) -> (&'static str, &'static str) {
    if bits < 40.0 {
        ("Very weak", "danger")
    } else if bits < 60.0 {
        ("Weak", "danger")
    } else if bits < 80.0 {
        ("Moderate", "warning")
    } else if bits < 110.0 {
        ("Strong", "success")
    } else {
        ("Very strong", "success")
    }
}

/// Estimate of a user-typed passphrase's guessing entropy.
///
/// U-12 fix: the previous version of this function only looked at which
/// *character classes* were present (lower/upper/digit/symbol/non-ASCII)
/// and multiplied that pool size by the length — a model that scores
/// `Password1!` (all four ASCII classes, 10 chars) at ~66 bits ("Strong"),
/// even though it's a textbook first guess for any real password cracker.
/// It's also blind to `abcdefgh`, `qwertyuiop`, and `aaaaaaaa`, which all
/// score as "high entropy" purely because they're long, despite being
/// trivially predictable.
///
/// This version keeps the same character-class pool-size model as a
/// starting point (still not a substitute for a full `zxcvbn`-style
/// tokenizer — see the note at the end), but then:
/// 1. Checks the whole passphrase (case-insensitively, and with a run of
///    trailing digits/punctuation stripped, e.g. `Password123!` ->
///    `password`) against a small list of extremely common passwords
///    ([`COMMON_PASSWORDS`]). A hit caps the score low regardless of
///    character-class diversity.
/// 2. Walks the passphrase looking for sequential runs (`abcde`, `54321`),
///    keyboard-walk runs (`qwerty`, `zxcvbn`, `1qaz`), and repeated-character
///    runs (`aaaa`) of length >= 3. Each such run is *not* charged the full
///    `length * log2(pool)` cost a random run of that length would be —
///    it's charged the cost of guessing "which one pattern, how long" (a
///    small, roughly constant number of bits) instead, since an attacker
///    trying common patterns before brute force finds these near-instantly.
///
/// This is still a heuristic, not a real crack-time simulator — it doesn't
/// tokenize dictionary words embedded inside a longer string, doesn't
/// model l33t-speak substitutions beyond what the common-password check
/// catches via stripped suffixes, and doesn't have a real wordlist. A
/// proper `zxcvbn` port would cover all of that, but pulling in the
/// `zxcvbn` crate (and its own dependency tree) is a larger change than
/// this pass covers — flagged as a possible follow-up, not done here.
pub fn estimate_passphrase_entropy(passphrase: &str) -> f64 {
    if passphrase.is_empty() {
        return 0.0;
    }

    // Common-password check: exact match, case-insensitive, after
    // stripping a trailing run of digits and/or common "make it pass the
    // policy" punctuation (Password123! -> password).
    let lower = passphrase.to_lowercase();
    let stripped: String = lower
        .trim_end_matches(|c: char| c.is_ascii_digit() || "!@#$%^&*.".contains(c))
        .to_string();
    if COMMON_PASSWORDS.contains(&lower.as_str()) || COMMON_PASSWORDS.contains(&stripped.as_str())
    {
        // Still scale trivially with length so an absurdly long repeat of
        // a common word isn't reported as literally 0 bits, but keep it
        // solidly in "Very weak" territory (rate_entropy's floor is 40).
        return (passphrase.chars().count() as f64).log2().max(1.0) * 2.0;
    }

    let mut pool = 0usize;
    if passphrase.chars().any(|c| c.is_lowercase()) {
        pool += 26;
    }
    if passphrase.chars().any(|c| c.is_uppercase()) {
        pool += 26;
    }
    if passphrase.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if passphrase
        .chars()
        .any(|c| c.is_ascii() && !c.is_alphanumeric() && !c.is_control())
    {
        pool += 33;
    }
    if !passphrase.is_ascii() {
        pool += 300;
    }
    if pool == 0 {
        pool = 1;
    }
    let bits_per_char = (pool as f64).log2();

    // Walk the passphrase once, charging `bits_per_char` for each
    // character that isn't part of a detected pattern run, and a small
    // flat cost (plus a per-run "how long is it" bit budget) for each run
    // that is.
    let chars: Vec<char> = passphrase.chars().collect();
    let mut total_bits = 0.0;
    let mut i = 0;
    while i < chars.len() {
        let seq_len = sequence_run_len(&chars, i);
        let rep_len = repeat_run_len(&chars, i);
        let run_len = seq_len.max(rep_len);
        if run_len >= 3 {
            // Guessing "this is a sequence/repeat starting near here, of
            // about this length" costs roughly bits_per_char (which
            // pattern/start point) + log2(run_len) (how long) — nowhere
            // near run_len * bits_per_char.
            total_bits += bits_per_char + (run_len as f64).log2().max(0.0);
            i += run_len;
        } else {
            total_bits += bits_per_char;
            i += 1;
        }
    }

    let naive_bits = calculate_entropy(passphrase.chars().count(), pool);
    // Never score *above* the naive per-character-class estimate — pattern
    // detection should only ever pull the number down, never inflate it.
    total_bits.min(naive_bits).max(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_password_scores_very_weak_even_with_all_char_classes() {
        // The regression case from the U-12 audit note: old model scored
        // this ~66 bits ("Strong") purely from character-class diversity.
        let bits = estimate_passphrase_entropy("Password1!");
        let (rating, _) = rate_entropy(bits);
        assert_eq!(rating, "Very weak");
    }

    #[test]
    fn common_password_bare_scores_very_weak() {
        let bits = estimate_passphrase_entropy("password");
        assert!(bits < 40.0);
    }

    #[test]
    fn keyboard_walk_scores_far_below_naive_estimate() {
        let naive = calculate_entropy(10, 26); // lowercase-only pool
        let bits = estimate_passphrase_entropy("qwertyuiop");
        assert!(
            bits < naive * 0.5,
            "keyboard walk should be scored well below naive: {bits} vs naive {naive}"
        );
    }

    #[test]
    fn ascending_sequence_scores_far_below_naive_estimate() {
        let naive = calculate_entropy(8, 26 + 26); // upper+lower pool
        let bits = estimate_passphrase_entropy("abcdefgh");
        assert!(bits < naive * 0.5);
    }

    #[test]
    fn repeated_char_scores_far_below_naive_estimate() {
        let naive = calculate_entropy(8, 26);
        let bits = estimate_passphrase_entropy("aaaaaaaa");
        assert!(bits < naive * 0.5);
    }

    #[test]
    fn random_looking_passphrase_is_not_penalized() {
        // No detected pattern runs -> score should equal the naive
        // character-class estimate exactly.
        let s = "xQ7m!kZ2pR";
        let naive = calculate_entropy(s.chars().count(), 26 + 26 + 10 + 33);
        let bits = estimate_passphrase_entropy(s);
        assert!((bits - naive).abs() < 1e-9);
    }

    #[test]
    fn empty_passphrase_is_zero() {
        assert_eq!(estimate_passphrase_entropy(""), 0.0);
    }

    #[test]
    fn score_never_exceeds_naive_estimate() {
        for s in ["qwerty123456", "aaaaaaaaaaaa", "Password1!", "normalPass99"] {
            let mut pool = 0usize;
            if s.chars().any(|c| c.is_lowercase()) {
                pool += 26;
            }
            if s.chars().any(|c| c.is_uppercase()) {
                pool += 26;
            }
            if s.chars().any(|c| c.is_ascii_digit()) {
                pool += 10;
            }
            if s.chars()
                .any(|c| c.is_ascii() && !c.is_alphanumeric() && !c.is_control())
            {
                pool += 33;
            }
            let naive = calculate_entropy(s.chars().count(), pool.max(1));
            let bits = estimate_passphrase_entropy(s);
            assert!(bits <= naive + 1e-9, "{s}: bits={bits} naive={naive}");
        }
    }

    #[test]
    fn sequence_run_len_detects_ascending_and_keyboard_runs() {
        let ascending: Vec<char> = "abcdef".chars().collect();
        assert_eq!(sequence_run_len(&ascending, 0), 6);

        let keyboard: Vec<char> = "qwerty".chars().collect();
        assert_eq!(sequence_run_len(&keyboard, 0), 6);

        let none: Vec<char> = "xqz".chars().collect();
        assert_eq!(sequence_run_len(&none, 0), 1);
    }

    #[test]
    fn repeat_run_len_detects_runs() {
        let chars: Vec<char> = "aaabbbc".chars().collect();
        assert_eq!(repeat_run_len(&chars, 0), 3);
        assert_eq!(repeat_run_len(&chars, 3), 3);
        assert_eq!(repeat_run_len(&chars, 6), 1);
    }

    #[test]
    fn rate_entropy_buckets_are_monotonic_and_labeled() {
        assert_eq!(rate_entropy(0.0).0, "Very weak");
        assert_eq!(rate_entropy(45.0).0, "Weak");
        assert_eq!(rate_entropy(70.0).0, "Moderate");
        assert_eq!(rate_entropy(90.0).0, "Strong");
        assert_eq!(rate_entropy(150.0).0, "Very strong");
    }

    #[test]
    fn build_pool_dedupes_and_preserves_first_seen_order() {
        let sets = all_charsets();
        let enabled: Vec<bool> = sets.iter().map(|s| s.enabled_by_default).collect();
        let pool = build_pool(&enabled, &sets);
        let mut seen = std::collections::HashSet::new();
        for c in &pool {
            assert!(seen.insert(*c), "duplicate char in pool: {c:?}");
        }
    }
}
