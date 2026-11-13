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
    /// Markdown, HTML or other plain UTF-8 text; stored and served like a PDF.
    /// Markdown has no signature, so text is admitted as a class.
    Text,
}

impl Admitted {
    /// Bytes to buffer for the non-streaming pipelines: each admitted kind keeps
    /// the cap of the pipeline that will validate it.
    pub(super) fn buffer_limit(self, media: &MediaConfig) -> u64 {
        match self {
            Self::Any => media.max_image_bytes.max(media.max_file_bytes),
            Self::Image => media.max_image_bytes,
            Self::Pdf | Self::Text => media.max_file_bytes,
        }
    }
}

/// Largest request body an upload route may have to read.
pub(super) fn request_body_limit(media: &MediaConfig, images_only: bool) -> u64 {
    if images_only {
        // The kind is unknown until the first bytes arrive, so admit the larger
        // of the allowed kinds; `Admitted::buffer_limit` narrows it after.
        media.max_image_bytes.max(media.max_file_bytes)
    } else {
        media.max_image_bytes.max(media.max_video_bytes)
    }
}

/// Admit an upload from its leading bytes. Filenames and the request
/// Content-Type are never consulted, so a renamed Office document (a ZIP or
/// OLE2 container) cannot be admitted as a PDF or as text.
pub(super) fn admit_upload(prefix: &[u8], images_only: bool) -> Result<Admitted, MediaError> {
    if !images_only {
        return Ok(Admitted::Any);
    }
    classify(prefix, false)
}

/// `complete` is false for the leading probe, whose last character may be cut.
fn classify(bytes: &[u8], complete: bool) -> Result<Admitted, MediaError> {
    let sniffed = infer::get(bytes).map(|kind| kind.mime_type());
    match sniffed {
        Some("image/jpeg" | "image/png" | "image/gif" | "image/webp") => Ok(Admitted::Image),
        Some("application/pdf") if has_pdf_header(bytes) => Ok(Admitted::Pdf),
        // No signature at all, or recognizable HTML. Anything else with a
        // signature is a format of its own, including the text-based ones:
        // RTF, shell scripts, and XML-declared documents such as SVG and the
        // Word and Excel 2003 XML formats.
        None | Some("text/html") if is_plain_text(bytes, complete) => Ok(Admitted::Text),
        _ => Err(denied(sniffed.unwrap_or("application/octet-stream"))),
    }
}

/// Re-check the complete buffered body against the kind admitted from the
/// probe, so the generic-file pipeline can only ever receive a PDF under this
/// policy. A PDF signature alone is not enough: the body must also end like a
/// PDF and must not contain a ZIP archive, which is how an Office document
/// could otherwise travel behind a PDF header.
pub(super) fn confirm_upload(body: &[u8], admitted: Admitted) -> Result<(), MediaError> {
    if admitted == Admitted::Any {
        return Ok(());
    }
    if classify(body, true)? != admitted {
        return Err(denied("ambiguous content"));
    }
    if admitted == Admitted::Text && is_office_xml(body) {
        return Err(denied("Office XML document"));
    }
    if admitted == Admitted::Pdf && !has_pdf_end_marker(body) {
        return Err(denied("application/pdf without an end-of-file marker"));
    }
    if admitted == Admitted::Pdf && has_zip_entry(body) {
        return Err(denied("application/pdf containing a ZIP archive"));
    }
    Ok(())
}

/// Non-empty UTF-8 text without control characters other than tab, line feed,
/// form feed and carriage return. Binary formats, UTF-16 and legacy 8-bit
/// encodings fail this; so does anything with a NUL. Two text formats that the
/// signature sniffing misses are excluded by how they open: an SVG document
/// without an XML declaration, and a PDF whose header sits behind whitespace.
/// Text that merely mentions or embeds either further down is unaffected.
fn is_plain_text(bytes: &[u8], complete: bool) -> bool {
    let valid_utf8 = match std::str::from_utf8(bytes) {
        Ok(_) => true,
        // An incomplete final character is expected in a cut-off probe only.
        Err(error) => !complete && error.error_len().is_none(),
    };
    let control = |byte: &u8| matches!(byte, 0..=8 | 11 | 14..=31 | 127);
    let content = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let content = content.trim_ascii_start();
    let opens_with = |tag: &[u8]| {
        content
            .get(..tag.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(tag))
    };
    !bytes.is_empty()
        && valid_utf8
        && !bytes.iter().any(control)
        && !opens_with(b"<svg")
        && !opens_with(b"%PDF-")
}

/// Word, Excel and PowerPoint documents saved in their XML text formats (Excel
/// and Word 2003 XML, Flat OPC), which carry one of these markers on the root
/// element or in a processing instruction. With an XML declaration they are
/// refused as XML already; this covers files written without one.
fn is_office_xml(text: &[u8]) -> bool {
    const MARKERS: [&[u8]; 4] = [
        b"<?mso-application",
        b"urn:schemas-microsoft-com:office:spreadsheet",
        b"schemas.microsoft.com/office/word/2003/wordml",
        b"schemas.microsoft.com/office/2006/xmlPackage",
    ];
    MARKERS
        .iter()
        .any(|marker| memchr::memmem::find(text, marker).is_some())
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

/// Whether a ZIP entry header occurs anywhere in the body. Every archive with
/// content has one local header and one central-directory header per file, and
/// readers that repair damaged archives rebuild them from the local headers
/// alone, so this holds wherever the archive sits and whatever state its
/// end-of-directory record is in.
///
/// The four signature bytes alone turn up by chance in large compressed PDF
/// streams, so a match must also carry a defined compression method and a
/// non-empty name that fits in the body. An entry failing that cannot be
/// extracted by any reader.
fn has_zip_entry(bytes: &[u8]) -> bool {
    // (third and fourth signature byte, offset of method, of name length, of name)
    const HEADERS: [([u8; 2], usize, usize, usize); 2] =
        [([3, 4], 8, 26, 30), ([1, 2], 10, 28, 46)];
    // APPNOTE 4.4.5 defines methods 0-20 and 93-99.
    const MAX_METHOD: u16 = 99;
    let field = |at: usize| {
        bytes
            .get(at..at + 2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
    };
    memchr::memmem::find_iter(bytes, b"PK").any(|at| {
        HEADERS.iter().any(|&(kind, method, name_length, name)| {
            bytes.get(at + 2..at + 4) == Some(kind.as_slice())
                && field(at + method).is_some_and(|method| method <= MAX_METHOD)
                && field(at + name_length).is_some_and(|length| {
                    length > 0 && at + name + usize::from(length) <= bytes.len()
                })
        })
    })
}

fn denied(found: &str) -> MediaError {
    MediaError::DisallowedContentType(format!(
        "{found}; only JPEG, PNG, GIF and WebP images, PDF documents and Markdown, \
         HTML or other plain-text files can be uploaded directly. Upload other \
         files to Google Drive and share the link."
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
        let directory_offset = file.len();
        file.extend(zip_end(4, directory_offset));
        file
    }

    /// ZIP end-of-central-directory record without an archive comment.
    fn zip_end(entries: u16, directory_offset: usize) -> Vec<u8> {
        let mut record = b"PK\x05\x06\0\0\0\0".to_vec();
        record.extend_from_slice(&entries.to_le_bytes());
        record.extend_from_slice(&entries.to_le_bytes());
        record.extend_from_slice(&0u32.to_le_bytes());
        record.extend_from_slice(&(directory_offset as u32).to_le_bytes());
        record.extend_from_slice(&[0, 0]);
        record
    }

    /// A Word document dressed as a PDF: PDF header in front, then the archive,
    /// then `filler` bytes and the PDF end marker. With `end_record` false the
    /// archive lacks its end-of-directory record, as a damaged file that Office
    /// offers to repair would.
    pub(crate) fn pdf_wrapped_docx(filler: usize, end_record: bool) -> Vec<u8> {
        let mut file = b"%PDF-1.7\n".to_vec();
        let mut docx = ooxml("word");
        if !end_record {
            docx.truncate(docx.len() - 22);
        }
        file.extend(docx);
        file.extend(std::iter::repeat_n(b' ', filler));
        file.extend_from_slice(b"\n%%EOF\n");
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
    fn policy_admits_only_images_pdf_and_plain_text_by_content() {
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
            // Markdown has no signature: plain UTF-8 text is admitted as a class,
            // and HTML with it, whether or not its opening is recognizable.
            (b"# Markdown\n", Some(Admitted::Text)),
            (
                "# \u{dc}berschrift \u{2013} \u{1f600}\n".as_bytes(),
                Some(Admitted::Text),
            ),
            (
                b"\xef\xbb\xbf# With byte-order mark\r\n",
                Some(Admitted::Text),
            ),
            (
                b"<!DOCTYPE html><html><body>hi</body></html>",
                Some(Admitted::Text),
            ),
            (b"<html>page</html>", Some(Admitted::Text)),
            (
                b"<p align=\"center\">README</p>\n\n# Title\n",
                Some(Admitted::Text),
            ),
            (
                b"<section><svg viewBox=\"0 0 1 1\"></svg></section>",
                Some(Admitted::Text),
            ),
            (b"plain notes", Some(Admitted::Text)),
            // Text-based formats with a signature of their own stay out.
            (b"{\\rtf1\\ansi Word document}", None),
            (
                b"<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"/>",
                None,
            ),
            (
                b"<?xml version=\"1.0\"?><?mso-application progid=\"Excel.Sheet\"?>",
                None,
            ),
            (b"#!/bin/sh\nrm -rf /\n", None),
            // An SVG document without a declaration is not plain text either.
            (b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>", None),
            (b"\xef\xbb\xbf \n<SVG></SVG>", None),
            (
                b"The header reads `%PDF-1.7`, see ISO 32000.\n",
                Some(Admitted::Text),
            ),
            // Not UTF-8 text: NUL and other controls, UTF-16, Latin-1.
            (b"text with a \0 byte", None),
            (b"escape \x1b[0m sequence", None),
            (b"\xff\xfe#\0 \0U\0T\0F\0-\x001\x006\0", None),
            (b"Gr\xfc\xdfe in Latin-1", None),
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
            for admitted in [Admitted::Image, Admitted::Pdf, Admitted::Text] {
                assert!(confirm_upload(&bytes, admitted).is_err(), "{extension}");
            }
            assert!(
                admit_upload(&bytes, false).is_ok(),
                "{extension}: policy off"
            );
        }
    }

    #[test]
    fn text_probe_tolerates_only_a_character_cut_by_the_probe_boundary() {
        // "ü" is two bytes; a 4 KiB probe may end between them.
        let cut = &"Gr\u{fc}".as_bytes()[..3];
        assert_eq!(admit_upload(cut, true).ok(), Some(Admitted::Text));
        // The complete body gets no such allowance, and a broken sequence in
        // the middle is never text.
        assert!(confirm_upload(cut, Admitted::Text).is_err());
        assert!(admit_upload(b"Gr\xc3 e", true).is_err());
        assert!(confirm_upload("Gr\u{fc}\u{df}e\n".as_bytes(), Admitted::Text).is_ok());
    }

    #[test]
    fn office_documents_in_xml_text_form_are_not_plain_text() {
        // Without an XML declaration these sniff as nothing, so the probe
        // admits them as text; the whole-body check must refuse them.
        let spreadsheet: &[u8] =
            b"<Workbook xmlns=\"urn:schemas-microsoft-com:office:spreadsheet\"><Worksheet/></Workbook>";
        let word: &[u8] =
            b"<w:wordDocument xmlns:w=\"http://schemas.microsoft.com/office/word/2003/wordml\"/>";
        let flat_opc: &[u8] =
            b"<pkg:package xmlns:pkg=\"http://schemas.microsoft.com/office/2006/xmlPackage\"/>";
        let late_marker = [
            vec![b'\n'; 100_000],
            b"<?mso-application progid=\"Word.Document\"?>".to_vec(),
        ]
        .concat();
        for body in [spreadsheet, word, flat_opc, late_marker.as_slice()] {
            assert_eq!(
                admit_upload(&body[..body.len().min(4096)], true).ok(),
                Some(Admitted::Text)
            );
            assert!(
                confirm_upload(body, Admitted::Text).is_err(),
                "{:?}",
                &body[..20]
            );
        }
        // Ordinary Markdown and HTML confirm.
        for body in [
            &b"# Notes\n\n- one\n- two\n"[..],
            b"<!DOCTYPE html><html><body>hi</body></html>",
        ] {
            assert!(confirm_upload(body, Admitted::Text).is_ok());
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
        assert!(confirm_upload(fixtures::PDF, Admitted::Text).is_err());
        assert!(confirm_upload(b"# Markdown\n", Admitted::Pdf).is_err());
        assert!(confirm_upload(b"# Markdown\n", Admitted::Image).is_err());
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
        // Nor is an Office document that carries both PDF markers, wherever the
        // archive sits before the end marker and whether or not it is intact.
        for (filler, end_record) in [(0, true), (900, true), (200_000, true), (0, false)] {
            let polyglot = fixtures::pdf_wrapped_docx(filler, end_record);
            assert_eq!(admit_upload(&polyglot, true).ok(), Some(Admitted::Pdf));
            assert!(has_pdf_end_marker(&polyglot), "fixture must end like a PDF");
            assert!(
                confirm_upload(&polyglot, Admitted::Pdf).is_err(),
                "filler {filler}, end record {end_record}"
            );
        }
        // A central-directory header alone is refused as well.
        let mut directory_only = b"%PDF-1.7\nPK\x01\x02".to_vec();
        directory_only.extend([0; 24]);
        directory_only.extend([1, 0]);
        directory_only.extend([0; 16]);
        directory_only.extend(b"a\n%%EOF\n");
        assert!(confirm_upload(&directory_only, Admitted::Pdf).is_err());
        // Bare ZIP signature bytes inside PDF stream data are not an entry:
        // no reader could extract one with an undefined compression method.
        for signature in [b"PK\x03\x04", b"PK\x01\x02", b"PK\x05\x06"] {
            let mut stream_bytes = b"%PDF-1.7\nstream\n".to_vec();
            stream_bytes.extend_from_slice(signature);
            stream_bytes.extend([0xff; 64]);
            stream_bytes.extend(b"\nendstream\n%%EOF\n");
            assert!(confirm_upload(&stream_bytes, Admitted::Pdf).is_ok());
            // Nor is a signature cut off by the end of the body.
            let mut truncated = b"%PDF-1.7\n%%EOF\n".to_vec();
            truncated.extend_from_slice(signature);
            assert!(confirm_upload(&truncated, Admitted::Pdf).is_ok());
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
        assert_eq!(Admitted::Text.buffer_limit(&media), 20);
        assert_eq!(Admitted::Any.buffer_limit(&media), 20);
        media.max_image_bytes = 30;
        assert_eq!(request_body_limit(&media, true), 30, "image cap is larger");
    }
}
