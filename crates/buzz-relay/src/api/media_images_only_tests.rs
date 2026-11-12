// Router regression tests sharing the existing signed-request fixtures.
mod image_policy_postgres_tests {
    use super::*;
    // Included in media::tests::postgres_tests to exercise the production router
    // using its existing signed-request and isolated database fixtures.

    use crate::api::media::upload_policy::fixtures;

    #[test]
    #[ignore = "requires Postgres"]
    fn policy_blocks_office_and_other_files_on_both_upload_routes_despite_spoofed_headers() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let mut state = rt
            .block_on(media_off_test_state())
            .expect("local Postgres reachable");
        mutate_state(&mut state, |config| {
            config.media_images_only = true;
            // The matrix below is larger than one uploader's per-minute allowance.
            config.media_uploads_per_minute = 1_000;
        });
        let host = format!("images-only-{}.local", uuid::Uuid::new_v4().simple());
        rt.block_on(state.db.ensure_configured_community(&host))
            .expect("seed community");
        let keys = Keys::generate();
        // A PDF signature in front of an Office container is still not a PDF.
        let mut pdf_prefixed_docx = b"%PDF-1.7\n".to_vec();
        pdf_prefixed_docx.extend(fixtures::office_files().remove(0).2);
        let mut bodies: Vec<(String, Vec<u8>)> = fixtures::office_files()
            .into_iter()
            .map(|(extension, _, bytes)| (extension.to_string(), bytes))
            .collect();
        bodies.extend(
            [
                ("pdf-prefixed docx", pdf_prefixed_docx.as_slice()),
                ("pdf-wrapped docx", fixtures::pdf_wrapped_docx(0).as_slice()),
                ("pdf signature only", b"%PDF-1.7\nnot a document"),
                ("pdf without version", b"%PDF\n%%EOF\n"),
                ("zip", b"PK\x03\x04not an image"),
                ("mp4", b"\0\0\0\x18ftypisom\0\0\0\0isommp42"),
                ("iso-bmff", b"\0\0\0\x18ftypPRIV\0\0\0\0isommp42"),
                ("svg", b"<svg></svg>"),
                ("html", b"<!DOCTYPE html><html><body>hi</body></html>"),
                ("markdown", b"# Heading\n\nplain text"),
                ("empty", b""),
            ]
            .map(|(label, bytes)| (label.to_string(), bytes.to_vec())),
        );
        // Neither claimed type nor filename may grant admission: every body is
        // sent once posing as an image and once posing as a PDF.
        let disguises = [
            ("image/png", "attachment; filename=pretend.png"),
            ("application/pdf", "attachment; filename=report.pdf"),
        ];
        for route in UPLOAD_ROUTES {
            for (label, body) in &bodies {
                for (claimed_type, claimed_name) in disguises {
                    let sha = sha256_hex(body);
                    let token = blossom_upload_auth_value(&keys, &host, &sha);
                    let mut headers = axum::http::HeaderMap::new();
                    headers.insert("authorization", token.parse().expect("auth"));
                    headers.insert("x-sha-256", sha.parse().expect("hash"));
                    headers.insert("content-type", claimed_type.parse().expect("MIME"));
                    headers.insert(
                        "content-disposition",
                        claimed_name.parse().expect("filename"),
                    );
                    let (status, _, response) = rt.block_on(media_oneshot(
                        Arc::clone(&state),
                        "PUT",
                        route,
                        &host,
                        headers,
                        body,
                    ));
                    assert_eq!(
                        status,
                        StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        "{route} {label} as {claimed_type}: {response:?}"
                    );
                    let json: serde_json::Value =
                        serde_json::from_slice(&response).expect("JSON error");
                    assert!(
                        json["error"]
                            .as_str()
                            .expect("error message")
                            .contains("Google Drive"),
                        "{route} {label} as {claimed_type}: {response:?}"
                    );
                }
            }
        }
    }

    // In-process S3 wire fixture: only the object PUT/GET/HEAD operations used by
    // the real upload/download pipeline. No external object store or credentials.
    async fn images_only_object_store() -> String {
        use axum::{
            body::Body,
            extract::{Request, State},
            response::Response,
            routing::any,
            Router,
        };
        type Objects = Arc<tokio::sync::Mutex<std::collections::HashMap<String, bytes::Bytes>>>;
        async fn object(State(objects): State<Objects>, request: Request) -> Response {
            let key = request.uri().path().to_owned();
            if request.method() == axum::http::Method::PUT {
                let body = axum::body::to_bytes(request.into_body(), 1024 * 1024)
                    .await
                    .unwrap();
                objects.lock().await.insert(key, body);
                return Response::builder().status(200).body(Body::empty()).unwrap();
            }
            let objects = objects.lock().await;
            let Some(body) = objects.get(&key) else {
                return Response::builder().status(404).body(Body::empty()).unwrap();
            };
            let head = request.method() == axum::http::Method::HEAD;
            Response::builder()
                .status(200)
                .header("content-length", body.len())
                .body(if head {
                    Body::empty()
                } else {
                    Body::from(body.clone())
                })
                .unwrap()
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = Router::new()
            .fallback(any(object))
            .with_state(Objects::default());
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://{address}")
    }

    #[test]
    #[ignore = "requires Postgres"]
    fn policy_preserves_image_and_pdf_round_trips_and_existing_file_download() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut state = rt
            .block_on(media_off_test_state())
            .expect("local Postgres reachable");
        let host = format!("images-roundtrip-{}.local", uuid::Uuid::new_v4().simple());
        rt.block_on(state.db.ensure_configured_community(&host))
            .unwrap();
        let endpoint = rt.block_on(images_only_object_store());
        mutate_state(&mut state, |config| {
            config.media_images_only = false;
            config.media.s3_endpoint = endpoint;
            config.media.s3_bucket = "test-images".to_string();
            config.media.s3_access_key = "synthetic-test-access".to_string();
            config.media.s3_secret_key = "synthetic-test-secret".to_string();
            config.media.s3_addressing_style = buzz_media::S3AddressingStyle::Path;
        });
        Arc::get_mut(&mut state).unwrap().media_storage =
            Arc::new(buzz_media::MediaStorage::new(&state.config.media).unwrap());
        let keys = Keys::generate();
        let upload = |state: &Arc<AppState>, route: &str, body: &[u8]| {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                "authorization",
                blossom_upload_auth_value(&keys, &host, &sha256_hex(body))
                    .parse()
                    .unwrap(),
            );
            headers.insert("x-sha-256", sha256_hex(body).parse().unwrap());
            rt.block_on(media_oneshot(
                Arc::clone(state),
                "PUT",
                route,
                &host,
                headers,
                body,
            ))
        };
        let old_file = b"existing non-image file";
        let old = upload(&state, "/upload", old_file);
        assert_eq!(old.0, StatusCode::OK, "policy off: {:?}", old.2);
        mutate_state(&mut state, |config| config.media_images_only = true);
        let png = images_only_png();
        for route in UPLOAD_ROUTES {
            let uploaded = upload(&state, route, &png);
            assert_eq!(uploaded.0, StatusCode::OK, "{route}: {:?}", uploaded.2);
            let descriptor: serde_json::Value = serde_json::from_slice(&uploaded.2).unwrap();
            assert_eq!(descriptor["type"], "image/png");
        }
        // A PDF is admitted on `/upload` and stored byte-identical as a `.pdf`
        // download, even when the client claims a different type. The legacy
        // `/media/upload` alias keeps its upstream media-only contract.
        let pdf = fixtures::PDF;
        let uploaded = upload(&state, "/upload", pdf);
        assert_eq!(uploaded.0, StatusCode::OK, "PDF: {:?}", uploaded.2);
        let descriptor: serde_json::Value = serde_json::from_slice(&uploaded.2).unwrap();
        assert_eq!(descriptor["type"], "application/pdf");
        assert_eq!(
            descriptor["url"],
            format!("https://{host}/media/{}.pdf", sha256_hex(pdf))
        );
        let legacy = upload(&state, "/media/upload", pdf);
        assert_eq!(legacy.0, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{:?}", legacy.2);
        for body in [old_file.as_slice(), png.as_slice(), pdf] {
            let hash = sha256_hex(body);
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                "authorization",
                blossom_get_auth_value(&keys, &host, &hash).parse().unwrap(),
            );
            let download = rt.block_on(media_oneshot(
                Arc::clone(&state),
                "GET",
                &format!("/media/{hash}"),
                &host,
                headers,
                b"",
            ));
            assert_eq!(download.0, StatusCode::OK, "download: {:?}", download.2);
            assert_eq!(download.2.as_ref(), body);
        }
        // A magic-byte prefix alone must not pass full image validation.
        for body in [
            b"\x89PNG\r\n\x1a\ninvalid".as_slice(),
            // Both a JPEG signature and an ISO-BMFF-looking header: image-only
            // admission must still use image validation, never the video path.
            b"\xff\xd8\xff\xe0ftypPRIV\0\0\0\0isommp42".as_slice(),
        ] {
            let corrupt = upload(&state, "/upload", body);
            assert_eq!(
                corrupt.0,
                StatusCode::UNPROCESSABLE_ENTITY,
                "{:?}",
                corrupt.2
            );
        }
        let unauthenticated = rt.block_on(media_oneshot(
            Arc::clone(&state),
            "PUT",
            "/upload",
            &host,
            axum::http::HeaderMap::new(),
            &png,
        ));
        assert_eq!(unauthenticated.0, StatusCode::UNAUTHORIZED);
        // Each kind keeps its own cap: a tiny image cap rejects the PNG but
        // leaves the PDF to the generic-file cap, and the reverse.
        mutate_state(&mut state, |config| config.media.max_image_bytes = 32);
        let oversized = upload(&state, "/upload", &png);
        assert_eq!(oversized.0, StatusCode::PAYLOAD_TOO_LARGE);
        let mut second_pdf = pdf.to_vec();
        second_pdf.extend_from_slice(b"\n");
        let within_file_cap = upload(&state, "/upload", &second_pdf);
        assert_eq!(within_file_cap.0, StatusCode::OK, "{:?}", within_file_cap.2);
        mutate_state(&mut state, |config| {
            config.media.max_image_bytes = 50 * 1024 * 1024;
            config.media.max_file_bytes = 32;
        });
        let mut third_pdf = second_pdf.clone();
        third_pdf.extend_from_slice(b"\n");
        let oversized_pdf = upload(&state, "/upload", &third_pdf);
        assert_eq!(oversized_pdf.0, StatusCode::PAYLOAD_TOO_LARGE);
    }

    fn images_only_png() -> Vec<u8> {
        // Valid 2x2 red PNG generated by ffmpeg, with ffmpeg's pHYs chunk stripped:
        // `validate_png_metadata_free` rejects pHYs as an identity channel, so the
        // original fixture uploaded as 422 MetadataForbidden. IHDR/IDAT/IEND only.
        vec![
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x08, 0x02, 0x00, 0x00,
            0x00, 0xfd, 0xd4, 0x9a, 0x73, 0x00, 0x00, 0x00, 0x10, 0x49, 0x44, 0x41, 0x54, 0x78,
            0x9c, 0x63, 0xfc, 0xc3, 0x00, 0x02, 0x2c, 0x60, 0x92, 0x01, 0x00, 0x0d, 0x04, 0x01,
            0x02, 0xbf, 0x50, 0x15, 0xb3, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
            0x42, 0x60, 0x82,
        ]
    }
}
