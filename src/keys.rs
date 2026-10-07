//! Key files are raw 32-byte RFC 8032 seeds; public keys are base64.
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

pub fn load(path: &Path) -> Result<SigningKey> {
    load_with_policy(path, false)
}

/// systemd credentials are root-owned 0440 files in a protected mount,
/// with access granted only to the service. Ordinary key files stay 0600.
pub(crate) fn load_credential(path: &Path) -> Result<SigningKey> {
    let suffix = path
        .strip_prefix("/run/credentials")
        .context("credential outside systemd credential directory")?;
    let parts = suffix.components().collect::<Vec<_>>();
    ensure!(
        parts.len() == 2
            && parts
                .iter()
                .all(|c| matches!(c, std::path::Component::Normal(_))),
        "invalid credential path"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let parent = std::fs::symlink_metadata(path.parent().context("credential parent")?)?;
        ensure!(
            parent.is_dir()
                && parent.uid() == 0
                && parent.gid() == 0
                && parent.permissions().mode() & 0o027 == 0,
            "unprotected credential directory"
        );
    }
    load_with_policy(path, true)
}

fn load_with_policy(path: &Path, credential: bool) -> Result<SigningKey> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .context("open private key without following symlinks")?;
    let meta = file.metadata().context("inspect open key file")?;
    ensure!(
        meta.file_type().is_file(),
        "key must be a regular file (no symlinks)"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        ensure!(
            meta.permissions().mode() & 0o077 == 0
                || (credential
                    && meta.uid() == 0
                    && meta.gid() == 0
                    && meta.permissions().mode() & 0o027 == 0),
            "key permissions must be 0600 or stricter"
        );
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(33)
        .read_to_end(&mut bytes)
        .context("read private key")?;
    let seed = Zeroizing::new(crate::wire::fixed::<32>(&bytes)?);
    Ok(SigningKey::from_bytes(&seed))
}

pub fn create(path: &Path) -> Result<SigningKey> {
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::RngCore::try_fill_bytes(&mut OsRng, &mut seed[..])
        .context("operating-system random generator")?;
    let key = SigningKey::from_bytes(&seed);
    write_new(path, &Zeroizing::new(key.to_bytes())[..], true)?;
    Ok(key)
}

/// Never overwrite a key or certificate accidentally.
pub fn write_new(path: &Path, data: &[u8], secret: bool) -> Result<()> {
    write_all(&mut create_new(path, secret)?, data)
}

/// Exclusively creates an output file, failing if anything exists at `path`.
pub fn create_new(path: &Path, secret: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if secret { 0o600 } else { 0o644 });
    }
    options
        .open(path)
        .with_context(|| format!("create {}", path.display()))
}

/// Writes and flushes to stable storage.
pub fn write_all(file: &mut File, data: &[u8]) -> Result<()> {
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}
