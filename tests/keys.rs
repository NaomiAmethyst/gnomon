#![allow(clippy::unwrap_used)]
use gnomon::keys;
#[test]
fn key_permissions_lengths_and_no_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("seed");
    let key = keys::create(&path).unwrap();
    assert_eq!(key.to_bytes(), keys::load(&path).unwrap().to_bytes());
    assert!(keys::create(&path).is_err());
    std::fs::write(&path, [0; 33]).unwrap();
    assert!(keys::load(&path).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        std::fs::write(&path, [0; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(keys::load(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(keys::load(&link).is_err());
    }
}
