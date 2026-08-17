# CJK / Kana font

egui's bundled `default_fonts` (Ubuntu-Light + a Latin/emoji fallback) has
**no glyphs for Han, Hiragana, or Katakana**. That's why generated passwords
using the "CJK & Kana" charset show as tofu boxes (▯) even though the
correct code points are being generated and copied correctly — this is a
rendering-only issue, not a data issue.

`main.rs` now loads any `.ttf` / `.otf` file it finds in this folder at
startup and registers it as a fallback font (tried only for glyphs the
default font can't render), so Latin/Cyrillic/Greek keep using the crisp
default font and CJK glyphs are filled in from whatever you drop here.

## What to add

Download **Noto Sans JP** (covers Kana + the common Han subset used by the
generator) or **Noto Sans SC/TC** for fuller Han coverage, from Google Fonts:

- https://fonts.google.com/noto/specimen/Noto+Sans+JP
- https://fonts.google.com/noto/specimen/Noto+Sans+SC

Pick the **static** "Regular" weight `.ttf` and place it in this folder,
e.g.:

```
assets/fonts/NotoSansJP-Regular.ttf
```

No code changes or recompilation needed to swap fonts — just replace the
file and restart the app. If this folder has no font files, the app runs
exactly as before (silently skips the fallback registration).

## Distributing a release build

For a packaged/release build, ship this `assets/fonts/` folder next to the
executable (the app looks for it relative to the running binary first, then
falls back to the crate root for `cargo run`), or embed a specific font
permanently with `include_bytes!` in `main.rs` if you'd rather not depend on
an external file at runtime.

--

The structure of assets folder should keep in the following format

```
tree assets
assets
└── fonts
    ├── Noto_Sans_JP
    │   ├── NotoSansJP-VariableFont_wght.ttf
    │   ├── OFL.txt
    │   ├── README.txt
    │   └── static
    │       └── NotoSansJP-Regular.ttf
    ├── Noto_Sans_JP,Noto_Sans_SC
    │   ├── Noto_Sans_JP
    │   │   ├── NotoSansJP-VariableFont_wght.ttf
    │   │   ├── OFL.txt
    │   │   ├── README.txt
    │   │   └── static
    │   │       └── NotoSansJP-Regular.ttf
    │   └── Noto_Sans_SC
    │       ├── NotoSansSC-VariableFont_wght.ttf
    │       ├── OFL.txt
    │       ├── README.txt
    │       └── static
    │           └── NotoSansSC-Regular.ttf
    └── README.md
```
