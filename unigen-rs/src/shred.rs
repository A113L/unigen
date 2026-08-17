//! Secure file shredding: multi-pass random overwrite + zero pass, then
//! delete. The destructive path opens the file first, verifies its identity,
//! overwrites that open handle, and only then deletes it. Windows uses
//! handle-based deletion to avoid a final pathname race; Unix keeps the
//! open-handle identity check and refuses to delete a pathname that no longer
//! names the verified inode.

use anyhow::{bail, Context, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    #[cfg(unix)]
    pub dev: u64,
    #[cfg(unix)]
    pub ino: u64,
    #[cfg(windows)]
    pub volume_serial: u32,
    #[cfg(windows)]
    pub file_index: u64,
    #[cfg(not(any(unix, windows)))]
    pub len: u64,
    #[cfg(not(any(unix, windows)))]
    pub modified: Option<std::time::SystemTime>,
}

pub fn file_identity(path: &Path) -> Result<FileIdentity> {
    let file = open_shred_handle(path)?;
    file_identity_from_file(&file)
}

fn file_identity_from_file(file: &fs::File) -> Result<FileIdentity> {
    let meta = file.metadata()?;
    if !meta.is_file() {
        bail!("Refusing to identify a non-regular file");
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(FileIdentity {
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;

        #[repr(C)]
        struct FileTime {
            low_date_time: u32,
            high_date_time: u32,
        }

        #[repr(C)]
        struct ByHandleFileInformation {
            dw_file_attributes: u32,
            ft_creation_time: FileTime,
            ft_last_access_time: FileTime,
            ft_last_write_time: FileTime,
            dw_volume_serial_number: u32,
            n_file_size_high: u32,
            n_file_size_low: u32,
            n_number_of_links: u32,
            n_file_index_high: u32,
            n_file_index_low: u32,
        }

        extern "system" {
            fn GetFileInformationByHandle(
                h_file: *mut std::ffi::c_void,
                lp_file_information: *mut ByHandleFileInformation,
            ) -> i32;
        }

        let mut info = std::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
        let ok = unsafe {
            GetFileInformationByHandle(
                file.as_raw_handle() as *mut std::ffi::c_void,
                info.as_mut_ptr(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let info = unsafe { info.assume_init() };
        Ok(FileIdentity {
            volume_serial: info.dw_volume_serial_number,
            file_index: ((info.n_file_index_high as u64) << 32) | info.n_file_index_low as u64,
        })
    }

    #[cfg(not(any(unix, windows)))]
    {
        Ok(FileIdentity {
            len: meta.len(),
            modified: meta.modified().ok(),
        })
    }
}

fn open_shred_handle(path: &Path) -> Result<fs::File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc_o_nofollow());
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const GENERIC_READ: u32 = 0x8000_0000;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const DELETE: u32 = 0x0001_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        const FILE_SHARE_DELETE: u32 = 0x0000_0004;
        opts.access_mode(GENERIC_READ | GENERIC_WRITE | DELETE);
        opts.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    }

    opts.open(path)
        .with_context(|| format!("opening {path:?} for secure shredding"))
}

fn overwrite_open_file(file: &mut fs::File, passes: u32) -> Result<()> {
    let size = file.metadata()?.len();
    const CHUNK: usize = 1024 * 1024;
    let mut buf = vec![0u8; CHUNK];

    for _ in 0..passes {
        file.seek(SeekFrom::Start(0))?;
        let mut written = 0u64;
        while written < size {
            let n = std::cmp::min(CHUNK as u64, size - written) as usize;
            OsRng.fill_bytes(&mut buf[..n]);
            file.write_all(&buf[..n])?;
            written += n as u64;
        }
        file.flush()?;
        file.sync_all()?;
    }

    // Final zero pass.
    file.seek(SeekFrom::Start(0))?;
    let zeros = vec![0u8; CHUNK];
    let mut written = 0u64;
    while written < size {
        let n = std::cmp::min(CHUNK as u64, size - written) as usize;
        file.write_all(&zeros[..n])?;
        written += n as u64;
    }
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn delete_open_handle(file: &fs::File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;

    // FILE_DISPOSITION_INFO_EX = 21. Mark the already-open handle for delete
    // using POSIX semantics when supported. This avoids resolving the
    // pathname again after the overwrite.
    #[repr(C)]
    struct FileDispositionInfoEx {
        flags: u32,
    }

    const FILE_DISPOSITION_INFO_EX: u32 = 21;
    const FILE_DISPOSITION_FLAG_DELETE: u32 = 0x0000_0001;
    const FILE_DISPOSITION_FLAG_POSIX_SEMANTICS: u32 = 0x0000_0002;
    const FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE: u32 = 0x0000_0010;

    extern "system" {
        fn SetFileInformationByHandle(
            h_file: *mut std::ffi::c_void,
            file_information_class: u32,
            file_information: *const std::ffi::c_void,
            buffer_size: u32,
        ) -> i32;
    }

    let info = FileDispositionInfoEx {
        flags: FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };

    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as *mut std::ffi::c_void,
            FILE_DISPOSITION_INFO_EX,
            &info as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<FileDispositionInfoEx>() as u32,
        )
    };

    if ok == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Shred only the file whose identity was captured before verification.
///
/// The file is opened with symlink protection where supported, its identity is
/// checked against the expected identity, and all overwrites happen through
/// that open handle. On Windows the final deletion is also performed through
/// the same handle. On Unix, unlinking necessarily uses the directory entry;
/// the pathname is re-checked immediately before unlinking and a mismatch
/// causes a safe failure rather than deleting the replacement.
pub fn shred_file_if_identity(
    path: &Path,
    expected: FileIdentity,
    passes: u32,
) -> Result<ShredOutcome> {
    let mut file = open_shred_handle(path)?;
    let actual = file_identity_from_file(&file)?;
    if actual != expected {
        bail!("File changed after verification; refusing to overwrite the replacement: {path:?}");
    }

    overwrite_open_file(&mut file, passes)?;

    #[cfg(windows)]
    {
        delete_open_handle(&file)?;
        // The handle itself is now marked for deletion; dropping it completes
        // the deletion without resolving the pathname again.
        drop(file);
        Ok(ShredOutcome::Secure)
    }

    #[cfg(unix)]
    {
        // Unix has no portable standard-library equivalent of Windows'
        // delete-by-handle primitive. Re-check the inode immediately before
        // unlinking so a pathname replacement is detected rather than
        // destroyed. This is the strongest portable pathname-based guarantee.
        match file_identity(path) {
            Ok(current) if current == expected => {
                drop(file);
                fs::remove_file(path)
                    .with_context(|| format!("removing {path:?} after overwrite"))?;
                fsync_parent(path);
                Ok(ShredOutcome::Secure)
            }
            Ok(_) | Err(_) => {
                drop(file);
                bail!(
                    "File name changed during shredding; verified file was overwritten but the current pathname was left untouched: {path:?}"
                );
            }
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        match file_identity(path) {
            Ok(current) if current == expected => {
                drop(file);
                fs::remove_file(path)
                    .with_context(|| format!("removing {path:?} after overwrite"))?;
                fsync_parent(path);
                Ok(ShredOutcome::Secure)
            }
            _ => bail!(
                "File name changed during shredding; verified file was overwritten but the current pathname was left untouched: {path:?}"
            ),
        }
    }
}

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
}

/// Securely shred `path`: capture its identity, then perform the destructive
/// operation only on a handle whose identity still matches that capture.
/// This replaces the older metadata-check/open-by-path implementation and is
/// also used by the GUI's manual shred action.
pub fn shred_file(
    path: &Path,
    passes: u32,
    delete_on_overwrite_failure: bool,
) -> Result<ShredOutcome> {
    let expected = file_identity(path)?;
    let _ = delete_on_overwrite_failure;
    // Never downgrade a failed secure overwrite to a plain pathname delete.
    // The parameter is retained for source compatibility with the previous API,
    // but is intentionally ignored because deleting plaintext after an overwrite
    // failure would defeat the security purpose of shredding.
    shred_file_if_identity(path, expected, passes)
}

#[cfg(not(windows))]
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX_EPOCH")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "unigen_shred_{name}_{}_{}",
            std::process::id(),
            stamp
        ))
    }

    #[test]
    fn shred_deletes_verified_file() {
        let path = test_path("delete");
        fs::write(&path, b"secret data that must not remain").unwrap();

        let result = shred_file(&path, 1, false);

        assert!(result.is_ok(), "shred failed: {result:?}");
        assert!(!path.exists(), "shredded file still exists");
    }

    #[test]
    fn shred_refuses_identity_mismatch_without_overwriting_replacement() {
        let path = test_path("identity");
        let replacement = test_path("replacement");

        fs::write(&path, b"original secret").unwrap();
        let expected = file_identity(&path).unwrap();

        // Replace the pathname with a different inode/file object after the
        // expected identity was captured.
        fs::rename(&path, &replacement).unwrap();
        fs::write(&path, b"do not destroy this replacement").unwrap();

        let result = shred_file_if_identity(&path, expected, 1);

        assert!(result.is_err(), "identity mismatch was not rejected");
        assert_eq!(
            fs::read(&path).unwrap(),
            b"do not destroy this replacement",
            "replacement file was modified despite identity mismatch"
        );

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&replacement);
    }
}
