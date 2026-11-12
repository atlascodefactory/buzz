//! Deployment policy for direct uploads, applied before either storage pipeline.

use buzz_media::{MediaConfig, MediaError};

pub(super) fn body_read_error(error: axum::Error, max: u64) -> MediaError {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    while let Some(cause) = source {
        if cause.is::<http_body_util::LengthLimitError>() {
            return MediaError::FileTooLarge { size: 0, max };
        }
        source = cause.source();
    }
    MediaError::Io(error.to_string())
}

/// What the policy admits for one upload, decided from the bytes actually sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Admitted {
    /// Policy disabled: the upstream pipelines decide.
    Any,
    /// JPEG, PNG, GIF or WebP; the image pipeline still decodes and validates it.
    Image,
    /// PDF; stored through the generic-file pipeline and served as a download.
    Pdf,
}

impl Admitted {
    /// Bytes to buffer for the non-streaming pipelines: each admitted kind keeps
    /// the cap of the pipeline that will validate it.
    pub(super) fn buffer_limit(self, media: &MediaConfig) -> u64 {
        match self {
            Self::Any => media.max_image_bytes.max(media.max_file_bytes),
            Self::Image => media.max_image_bytes,
            Self::Pdf => media.max_file_bytes,
        }
    }
}

/// Largest request body an upload route may have to read.
pub(super) fn request_body_limit(media: &MediaConfig, images_only: bool) -> u64 {
    if images_only {
        // The kind is unknown until the first bytes arrive, so admit the larger
        // of the two allowed kinds; `Admitted::buffer_limit` narrows it after.
        media.max_image_bytes.max(media.max_file_bytes)
    } else {
        media.max_image_bytes.max(media.max_video_bytes)
    }
}

/// Admit an upload from its leading bytes. Filenames and the request
/// Content-Type are never consulted, so a renamed Office document (a ZIP or
/// OLE2 container) cannot be admitted as a PDF.
pub(super) fn admit_upload(prefix: &[u8], images_only: bool) -> Result<Admitted, MediaError> {
    if !images_only {
        return Ok(Admitted::Any);
    }
    let mime = infer::get(prefix)
        .map(|kind| kind.mime_type())
        .unwrap_or("application/octet-stream");
    match mime {
        "image/jpeg" | "image/png" | "image/gif" | "image/webp" => Ok(Admitted::Image),
        "application/pdf" if has_pdf_header(prefix) => Ok(Admitted::Pdf),
        _ => Err(denied(mime)),
    }
}

/// Re-check the complete buffered body against the kind admitted from the
/// probe, so the generic-file pipeline can only ever receive a PDF under this
/// policy. A PDF signature alone is not enough: the body must also end like one.
pub(super) fn confirm_upload(body: &[u8], admitted: Admitted) -> Result<(), MediaError> {
    if admitted == Admitted::Any {
        return Ok(());
    }
    if admit_upload(body, true)? != admitted {
        return Err(denied("ambiguous content"));
    }
    if admitted == Admitted::Pdf && !has_pdf_end_marker(body) {
        return Err(denied("application/pdf without an end-of-file marker"));
    }
    Ok(())
}

/// `%PDF-<major>.<minor>` at byte zero, as ISO 32000 requires.
fn has_pdf_header(bytes: &[u8]) -> bool {
    matches!(
        bytes,
        [b'%', b'P', b'D', b'F', b'-', major, b'.', minor, ..]
            if major.is_ascii_digit() && minor.is_ascii_digit()
    )
}

/// `%%EOF` within the final 1024 bytes, the window PDF readers accept.
fn has_pdf_end_marker(bytes: &[u8]) -> bool {
    const MARKER: &[u8] = b"%%EOF";
    let tail = &bytes[bytes.len().saturating_sub(1024)..];
    tail.windows(MARKER.len()).any(|window| window == MARKER)
}

fn denied(found: &str) -> MediaError {
    MediaError::DisallowedContentType(format!(
        "{found}; only JPEG, PNG, GIF and WebP images and PDF documents can be \
         uploaded directly. Upload other files to Google Drive and share the link."
    ))
}

#[cfg(test)]
pub(super) mod fixtures {
    /// Smallest PDF shape the policy admits: versioned header plus end marker.
    pub(crate) const PDF: &[u8] =
        b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\nstartxref\n9\n%%EOF\n";

    /// One stored ZIP entry, as at the start of every OOXML file.
    fn zip_entry(name: &str, data: &[u8]) -> Vec<u8> {
        let mut entry = b"PK\x03\x04\x14\0\0\0\0\0\0\0\0\0\0\0\0\0".to_vec();
        entry.extend_from_slice(&(data.len() as u32).to_le_bytes());
        entry.extend_from_slice(&(data.len() as u32).to_le_bytes());
        entry.extend_from_slice(&(name.len() as u16).to_le_bytes());
        entry.extend_from_slice(&[0, 0]);
        entry.extend_from_slice(name.as_bytes());
        entry.extend_from_slice(data);
        entry
    }

    /// OOXML (ZIP) container with its parts under `directory` (`word`, `xl`,
    /// `ppt`), in the entry order Office writes and content sniffers expect.
    fn ooxml(directory: &str) -> Vec<u8> {
        let mut file = zip_entry("[Content_Types].xml", b"<Types/>");
        file.extend(zip_entry("_rels/.rels", b"<Relationships/>"));
        file.extend(zip_entry(
            &format!("{directory}/main.xml"),
            b"<main>document content</main>",
        ));
        file.extend(zip_entry(
            &format!("{directory}/_rels/main.xml.rels"),
            b"<Relationships/>",
        ));
        file
    }

    /// Legacy Office (OLE2 compound) file whose root storage carries `clsid`.
    fn ole2(clsid: &str) -> Vec<u8> {
        let mut file =
            cfb::CompoundFile::create(std::io::Cursor::new(Vec::new())).expect("compound file");
        file.set_storage_clsid("/", clsid.parse().expect("class id"))
            .expect("root class id");
        file.flush().expect("flush");
        file.into_inner().into_inner()
    }

    /// Every Office format the policy must keep out: `(extension, MIME, bytes)`.
    pub(crate) fn office_files() -> Vec<(&'static str, &'static str, Vec<u8>)> {
        vec![
            (
                "docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                ooxml("word"),
            ),
            (
                "xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                ooxml("xl"),
            ),
            (
                "pptx",
                "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                ooxml("ppt"),
            ),
            (
                "doc",
                "application/msword",
                ole2("00020906-0000-0000-c000-000000000046"),
            ),
            (
                "xls",
                "application/vnd.ms-excel",
                ole2("00020820-0000-0000-c000-000000000046"),
            ),
            (
                "ppt",
                "application/vnd.ms-powerpoint",
                ole2("64818d10-4f9b-11cf-86ea-00aa00b929e8"),
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_admits_only_images_and_pdf_by_content() {
        let cases: &[(&[u8], Option<Admitted>)] = &[
            (b"\xff\xd8\xff\xe0", Some(Admitted::Image)),
            (b"\x89PNG\r\n\x1a\n", Some(Admitted::Image)),
            (b"GIF89a", Some(Admitted::Image)),
            (b"RIFF\x10\0\0\0WEBPVP8 ", Some(Admitted::Image)),
            (b"%PDF-1.7\n", Some(Admitted::Pdf)),
            (b"%PDF-2.0\n", Some(Admitted::Pdf)),
            (fixtures::PDF, Some(Admitted::Pdf)),
            // A PDF signature without the mandatory version is not a PDF header.
            (b"%PDF", None),
            (b"%PDFftypisom", None),
            (b"%PDF-x.y\n", None),
            // The signature must sit at byte zero, not merely appear in the file.
            (b" %PDF-1.7\n", None),
            (b"PK\x03\x04%PDF-1.7\n", None),
            (b"PK\x03\x04", None),
            (b"ID3\x04\0\0\0\0\0\0", None),
            (b"\0\0\0\x18ftypisom\0\0\0\0isommp42", None),
            (b"\0\0\0\x18ftypPRIV\0\0\0\0isommp42", None),
            (b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>", None),
            (b"<html>not an image</html>", None),
            (b"# Markdown\n", None),
            (b"not an image", None),
            (b"", None),
        ];
        for &(bytes, admitted) in cases {
            assert_eq!(admit_upload(bytes, true).ok(), admitted, "{bytes:?}");
            assert_eq!(admit_upload(bytes, false).ok(), Some(Admitted::Any));
        }
    }

    #[test]
    fn policy_rejects_every_office_format_with_the_drive_instruction() {
        for (extension, mime, bytes) in fixtures::office_files() {
            // Guards the fixture: if it stopped sniffing as this Office format,
            // the rejection below would pass for the wrong reason.
            assert_eq!(
                infer::get(&bytes).map(|kind| kind.mime_type()),
                Some(mime),
                "{extension}"
            );
            let error = admit_upload(&bytes, true).expect_err(extension);
            assert!(
                matches!(&error, MediaError::DisallowedContentType(message)
                    if message.starts_with(mime) && message.contains("Google Drive")),
                "{extension}: {error:?}"
            );
            // The whole file cannot confirm as either allowed kind.
            for admitted in [Admitted::Image, Admitted::Pdf] {
                assert!(confirm_upload(&bytes, admitted).is_err(), "{extension}");
            }
            assert!(
                admit_upload(&bytes, false).is_ok(),
                "{extension}: policy off"
            );
        }
    }

    #[test]
    fn confirmation_binds_the_whole_body_to_the_admitted_kind() {
        assert!(confirm_upload(fixtures::PDF, Admitted::Pdf).is_ok());
        assert!(confirm_upload(b"\x89PNG\r\n\x1a\n", Admitted::Image).is_ok());
        // Policy off: nothing to confirm, whatever the body is.
        assert!(confirm_upload(b"PK\x03\x04", Admitted::Any).is_ok());
        // A body may not switch kinds between the probe and the pipeline.
        assert!(confirm_upload(fixtures::PDF, Admitted::Image).is_err());
        assert!(confirm_upload(b"\x89PNG\r\n\x1a\n", Admitted::Pdf).is_err());
        // A PDF signature in front of something else is not a PDF.
        assert!(confirm_upload(b"%PDF-1.7\nnot a document", Admitted::Pdf).is_err());
        for (extension, _, office) in fixtures::office_files() {
            let mut disguised = b"%PDF-1.7\n".to_vec();
            disguised.extend(office);
            assert!(
                confirm_upload(&disguised, Admitted::Pdf).is_err(),
                "{extension}"
            );
        }
        // The end marker must close the file, not merely occur early in it.
        let mut early_marker = fixtures::PDF.to_vec();
        early_marker.extend(std::iter::repeat_n(b' ', 2048));
        assert!(confirm_upload(&early_marker, Admitted::Pdf).is_err());
    }

    #[test]
    fn body_limits_follow_the_allowed_kinds() {
        let mut media = crate::config::Config::for_test().media;
        (
            media.max_image_bytes,
            media.max_file_bytes,
            media.max_video_bytes,
        ) = (10, 20, 90);
        assert_eq!(request_body_limit(&media, true), 20, "PDF cap is larger");
        assert_eq!(request_body_limit(&media, false), 90, "policy off: video");
        assert_eq!(Admitted::Image.buffer_limit(&media), 10);
        assert_eq!(Admitted::Pdf.buffer_limit(&media), 20);
        assert_eq!(Admitted::Any.buffer_limit(&media), 20);
        media.max_image_bytes = 30;
        assert_eq!(request_body_limit(&media, true), 30, "image cap is larger");
    }
}
