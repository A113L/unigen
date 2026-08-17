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

/// Rough floor estimate for a user-typed passphrase's entropy, same
/// conservative character-class-based model as the Python original.
pub fn estimate_passphrase_entropy(passphrase: &str) -> f64 {
    if passphrase.is_empty() {
        return 0.0;
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
    if passphrase.chars().any(|c| !c.is_ascii()) {
        pool += 300;
    }
    if pool == 0 {
        pool = 1;
    }
    calculate_entropy(passphrase.chars().count(), pool)
}
