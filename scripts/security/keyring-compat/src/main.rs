use dbus_secret_service::{EncryptionType, SecretService};
use keyring_core::Error;
use keyring_core::api::CredentialStoreApi;
use std::collections::HashMap;

fn main() {
    // Only run against the private test bus created by run-keyring-compat.sh.
    assert_eq!(
        std::env::var("BUZZ_ISOLATED_KEYRING_TEST").as_deref(),
        Ok("1")
    );
    if std::env::args().any(|arg| arg == "--no-bus") {
        assert!(old_store::Store::new().is_err());
        assert!(new_store::Store::new().is_err());
        assert!(keyring::Entry::new("mesh-llm", "owner-keystore").is_err());
        assert!(matches!(
            keyring::Entry::store_status(),
            Err(Error::PlatformFailure(_))
        ));
        println!("PASS: unavailable bus is a backend error, never a new identity");
        return;
    }
    if std::env::args().any(|arg| arg == "--fault-approved") {
        let service = SecretService::connect(EncryptionType::Dh).unwrap();
        let item = dbus_secret_service::Item::new(
            &service,
            dbus_secret_service::Path::new("/item").unwrap(),
        );
        service.unlock_all(&[&item]).unwrap();
        println!("PASS: approved prompt retains successful unlock behavior");
        return;
    }
    if let Some(mode) = std::env::args()
        .nth(1)
        .filter(|arg| arg.starts_with("--fault-"))
    {
        let store = new_store::Store::new().unwrap();
        let entry = store.build("mesh-llm", "owner-keystore", None).unwrap();
        let error = entry.get_secret().unwrap_err();
        if mode == "--fault-denied" {
            assert!(matches!(error, Error::NoStorageAccess(_)));
        } else {
            assert!(matches!(
                error,
                Error::NoStorageAccess(_) | Error::PlatformFailure(_)
            ));
        }
        // A subsequent update must also fail instead of replacing the identity.
        assert!(entry.set_secret(b"must-not-write").is_err());
        println!("PASS: {mode} fails closed without replacing an identity");
        return;
    }
    let old = old_store::Store::new().unwrap();
    let new = new_store::Store::new().unwrap();
    let service = SecretService::connect(EncryptionType::Dh).unwrap();
    let collection = service.get_default_collection().unwrap();
    for user in ["owner-keystore", "unicode-🔐"] {
        let before = old.build("mesh-llm", user, None).unwrap();
        let after = new.build("mesh-llm", user, None).unwrap();
        assert!(matches!(before.get_secret(), Err(Error::NoEntry)));
        assert!(matches!(after.get_secret(), Err(Error::NoEntry)));
        before.set_secret(&[0, 255, 1, 128]).unwrap();
        assert_eq!(after.get_secret().unwrap(), [0, 255, 1, 128]);
        let attrs = HashMap::from([("service", "mesh-llm"), ("username", user)]);
        let binary_items = collection.search_items(attrs.clone()).unwrap();
        assert_eq!(binary_items.len(), 1);
        let old_binary_mime = binary_items[0].get_secret_content_type().unwrap();
        after.set_secret(&[11, 0, 222]).unwrap();
        assert_eq!(before.get_secret().unwrap(), [11, 0, 222]);
        assert_eq!(
            binary_items[0].get_secret_content_type().unwrap(),
            old_binary_mime
        );
        // Secret Service providers may normalize content types. Compare both
        // backends for binary and UTF-8 data rather than assume a provider MIME.
        before.set_password("alter Text–🔑").unwrap();
        let old_text_mime = binary_items[0].get_secret_content_type().unwrap();
        after.set_password("aktualisiert–🔑").unwrap();
        assert_eq!(before.get_password().unwrap(), "aktualisiert–🔑");
        let items = collection.search_items(attrs.clone()).unwrap();
        assert_eq!(items.len(), 1, "updating must not duplicate the identity");
        assert_eq!(
            items[0].get_label().unwrap(),
            format!("keyring:{user}@mesh-llm")
        );
        assert_eq!(items[0].get_secret_content_type().unwrap(), old_text_mime);
        let metadata = items[0].get_attributes().unwrap();
        assert_eq!(
            metadata.get("service").map(String::as_str),
            Some("mesh-llm")
        );
        assert_eq!(metadata.get("username").map(String::as_str), Some(user));
        assert!(!metadata.contains_key("target"));
        after.delete_credential().unwrap();
        assert!(matches!(before.get_secret(), Err(Error::NoEntry)));
        // Reverse direction, using the exact facade that Mesh calls.
        let facade = keyring::Entry::new("mesh-llm", user).unwrap();
        facade.set_secret(&[11, 0, 222]).unwrap();
        assert_eq!(before.get_secret().unwrap(), [11, 0, 222]);
        before.set_password("old-store-update").unwrap();
        assert_eq!(facade.get_password().unwrap(), "old-store-update");
        // Ambiguous identities must never select or overwrite one match.
        let duplicate = collection
            .create_item(
                "duplicate",
                attrs.clone(),
                b"second",
                false,
                "application/octet-stream",
            )
            .unwrap();
        assert!(matches!(after.get_secret(), Err(Error::Ambiguous(_))));
        assert!(matches!(before.get_secret(), Err(Error::Ambiguous(_))));
        assert!(matches!(
            after.set_secret(b"must not overwrite"),
            Err(Error::Ambiguous(_))
        ));
        assert_eq!(duplicate.get_secret().unwrap(), b"second");
        duplicate.delete().unwrap();
        assert_eq!(facade.get_password().unwrap(), "old-store-update");
        facade.delete_credential().unwrap();
        assert!(collection.search_items(attrs).unwrap().is_empty());
    }
    // Reuse the existing unlocked collection by label as an explicit target.
    let target = collection.get_label().unwrap();
    let modifiers = HashMap::from([("target", target.as_str())]);
    let before = old
        .build("mesh-llm", "named-target", Some(&modifiers))
        .unwrap();
    let after = new
        .build("mesh-llm", "named-target", Some(&modifiers))
        .unwrap();
    before.set_password("target-old").unwrap();
    assert_eq!(after.get_password().unwrap(), "target-old");
    after.set_password("target-new").unwrap();
    assert_eq!(before.get_password().unwrap(), "target-new");
    after.delete_credential().unwrap();
    assert!(matches!(before.get_password(), Err(Error::NoEntry)));
    println!(
        "PASS: bidirectional old/new keyring interoperability, binary/Unicode, labels, attributes, targets, no duplicates, ambiguity, deletion"
    );
}
