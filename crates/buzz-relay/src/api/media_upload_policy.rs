//! Deployment policy for direct uploads, applied before either storage pipeline.

use buzz_media::MediaError;

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

pub(super) fn check_image_upload(prefix: &[u8], images_only: bool) -> Result<(), MediaError> {
    if !images_only {
        return Ok(());
    }
    let mime = infer::get(prefix)
        .map(|kind| kind.mime_type())
        .unwrap_or("application/octet-stream");
    if matches!(
        mime,
        "image/jpeg" | "image/png" | "image/gif" | "image/webp"
    ) {
        return Ok(());
    }
    Err(MediaError::DisallowedContentType(format!(
        "{mime}; only JPEG, PNG, GIF and WebP images can be uploaded directly. \
         Upload other files to Google Drive and share the link."
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn images_only_uses_content_allowlist_including_unknown_and_video_denials() {
        let cases: &[(&[u8], bool)] = &[
            (b"\xff\xd8\xff\xe0", true),
            (b"\x89PNG\r\n\x1a\n", true),
            (b"GIF89a", true),
            (b"RIFF\x10\0\0\0WEBPVP8 ", true),
            (b"%PDF-1.7\n", false),
            (b"PK\x03\x04", false),
            (b"ID3\x04\0\0\0\0\0\0", false),
            (b"\0\0\0\x18ftypisom\0\0\0\0isommp42", false),
            (b"\0\0\0\x18ftypPRIV\0\0\0\0isommp42", false),
            (b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>", false),
            (b"<html>not an image</html>", false),
            (b"not an image", false),
            (b"", false),
        ];
        for &(bytes, allowed) in cases {
            assert_eq!(
                check_image_upload(bytes, true).is_ok(),
                allowed,
                "{bytes:?}"
            );
            assert!(check_image_upload(bytes, false).is_ok(), "policy off");
        }
    }
}
