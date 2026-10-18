// Tests the actual Windows updater extraction boundary without launching installers.
use super::*;
use std::io::Write;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

fn update() -> Update {
    Update {
        run_on_main_thread: Arc::new(Box::new(|task| {
            task();
            Ok(())
        })),
        config: Config::default(),
        on_before_exit: None,
        body: None,
        current_version: "1.0.0".into(),
        version: "1.0.1".into(),
        date: None,
        target: "windows".into(),
        download_url: Url::parse("https://example.invalid/update").unwrap(),
        signature: String::new(),
        raw_json: serde_json::Value::Null,
        timeout: None,
        proxy: None,
        no_proxy: true,
        headers: HeaderMap::new(),
        extract_path: PathBuf::new(),
        app_name: "buzz-zip-regression".into(),
        installer_args: Vec::new(),
        current_exe_args: Vec::new(),
        configure_client: None,
    }
}

fn archive(name: &str) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            name,
            SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
        )
        .unwrap();
    writer
        .write_all(b"synthetic installer: never execute")
        .unwrap();
    writer.finish().unwrap().into_inner()
}

#[test]
fn accepts_nsis_and_msi_zip_payloads_with_unicode_names() {
    for name in ["Buzz ä-setup.exe", "Buzz ä.msi"] {
        let installer = update().extract_zip(&archive(name)).unwrap();
        let path = match installer {
            WindowsUpdaterType::Nsis { path, .. } => {
                assert!(name.ends_with(".exe"));
                path
            }
            WindowsUpdaterType::Msi { path, .. } => {
                assert!(name.ends_with(".msi"));
                PathBuf::from(path.to_string_lossy().trim_matches('"'))
            }
        };
        assert_eq!(path.file_name().unwrap(), name);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"synthetic installer: never execute"
        );
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}

#[test]
fn rejects_corrupt_archives_and_missing_installers() {
    assert!(update().extract_zip(b"not a zip").is_err());
    assert!(matches!(
        update().extract_zip(&archive("notes.txt")),
        Err(Error::BinaryNotFoundInArchive)
    ));
}

#[test]
fn extraction_cannot_escape_the_temporary_directory() {
    let name = format!("buzz-zip-escape-{}.exe", std::process::id());
    let outside = std::env::temp_dir().join(&name);
    assert!(!outside.exists());
    assert!(update()
        .extract_zip(&archive(&format!("../{name}")))
        .is_err());
    assert!(!outside.exists());
}
