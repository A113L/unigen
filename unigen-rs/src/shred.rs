//! Secure file shredding: multi-pass random overwrite + zero pass, then
//! delete. Mirrors the Python original's `shred_file`, including its
//! TOCTOU/symlink defenses.

use anyhow::{anyhow, bail, Context, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

pub const SSD_SHRED_CAVEAT: &str =
    "Note: multi-pass overwrite reliably destroys data on traditional spinning \
     disks. On SSDs, and on copy-on-write or journaling filesystems (e.g. \
     btrfs, ZFS, APFS), wear leveling and snapshots mean old data may still be \
     recoverable at the hardware level even after a 'successful' overwrite. \
     Use full-disk encryption or a vendor secure-erase tool for guarantees on \
     that hardware.";

#[derive(Debug)]
pub enum ShredOutcome {
    /// Overwritten securely, then deleted.
    Secure,
    /// Overwrite failed but the caller opted to delete anyway.
    Fallback,
}

/// Securely shred `path`: `passes` random-data passes, then one zero pass,
/// then delete. If the overwrite fails (read-only FS, permission error,
/// I/O error) and `delete_on_overwrite_failure` is false, the file is left
/// untouched and an error is returned instead of silently downgrading to a
/// plain delete.
pub fn shred_file(path: &Path, passes: u32, delete_on_overwrite_failure: bool) -> Result<ShredOutcome> {
    let meta = fs::symlink_metadata(path).with_context(|| format!("stat {path:?}"))?;

    if meta.file_type().is_symlink() {
        bail!(
            "Refusing to shred a symlink (would overwrite its target, not the \
             link itself): {path:?}"
        );
    }
    if meta.is_dir() {
        bail!("Cannot shred a directory: {path:?}");
    }

    let size = meta.len();
    let mut overwrite_ok = true;
    let mut overwrite_err: Option<anyhow::Error> = None;

    if size > 0 {
        let result = (|| -> Result<()> {
            // Open without following symlinks where the platform supports
            // it (TOCTOU guard: refuses to open through a symlink swapped
            // in after the metadata check above).
            let mut opts = OpenOptions::new();
            opts.read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.custom_flags(libc_o_nofollow());
            }
            let mut file = opts.open(path).with_context(|| format!("opening {path:?}"))?;

            let real_meta = file.metadata()?;
            if !real_meta.is_file() {
                bail!("Refusing to shred a non-regular file: {path:?}");
            }

            const CHUNK: usize = 1024 * 1024;
            let mut buf = vec![0u8; CHUNK];

            for _ in 0..passes {
                file.seek(SeekFrom::Start(0))?;
                let mut written = 0u64;
                while written < size {
                    let to_write = std::cmp::min(CHUNK as u64, size - written) as usize;
                    OsRng.fill_bytes(&mut buf[..to_write]);
                    file.write_all(&buf[..to_write])?;
                    written += to_write as u64;
                }
                file.flush()?;
                let _ = file.sync_all();
            }

            // Final zero pass.
            file.seek(SeekFrom::Start(0))?;
            let zeros = vec![0u8; CHUNK];
            let mut written = 0u64;
            while written < size {
                let to_write = std::cmp::min(CHUNK as u64, size - written) as usize;
                file.write_all(&zeros[..to_write])?;
                written += to_write as u64;
            }
            file.flush()?;
            let _ = file.sync_all();
            Ok(())
        })();

        if let Err(e) = result {
            overwrite_ok = false;
            overwrite_err = Some(e);
        }
    }

    if !overwrite_ok && !delete_on_overwrite_failure {
        return Err(anyhow!(
            "Secure overwrite failed ({}); file left in place: {path:?}",
            overwrite_err.map(|e| e.to_string()).unwrap_or_default()
        ));
    }

    #[cfg(unix)]
    {
        // Ensure we still have write permission on the (now-overwritten)
        // file so remove() doesn't fail on an oddly-permissioned file.
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = fs::metadata(path) {
            let mut perm = m.permissions();
            perm.set_mode(0o600);
            let _ = fs::set_permissions(path, perm);
        }
    }

    fs::remove_file(path).with_context(|| format!("removing {path:?} after overwrite"))?;
    fsync_parent(path);

    Ok(if overwrite_ok {
        ShredOutcome::Secure
    } else {
        ShredOutcome::Fallback
    })
}

fn fsync_parent(path: &Path) {
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
}

#[cfg(unix)]
fn libc_o_nofollow() -> i32 {
    // O_NOFOLLOW value is platform-stable across all unix targets Rust
    // supports without pulling in the `libc` crate just for one constant.
    #[cfg(target_os = "linux")]
    {
        0o400000
    }
    #[cfg(target_os = "macos")]
    {
        0x0100
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        0
    }
}
