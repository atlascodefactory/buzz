// Router regression tests sharing the existing signed-request fixtures.
mod image_policy_postgres_tests {
    use super::*;
    // Included in media::tests::postgres_tests to exercise the production router
    // using its existing signed-request and isolated database fixtures.

    #[test]
    #[ignore = "requires Postgres"]
    fn images_only_blocks_non_images_on_both_upload_routes_despite_spoofed_headers() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let mut state = rt
            .block_on(media_off_test_state())
            .expect("local Postgres reachable");
        mutate_state(&mut state, |config| config.media_images_only = true);
        let host = format!("images-only-{}.local", uuid::Uuid::new_v4().simple());
        rt.block_on(state.db.ensure_configured_community(&host))
            .expect("seed community");
        let keys = Keys::generate();
        for route in UPLOAD_ROUTES {
            for body in [
                b"%PDF-1.7\nnot an image".as_slice(),
                b"PK\x03\x04not an image".as_slice(),
                b"\0\0\0\x18ftypisom\0\0\0\0isommp42".as_slice(),
                b"\0\0\0\x18ftypPRIV\0\0\0\0isommp42".as_slice(),
                b"<svg></svg>".as_slice(),
                b"plain text".as_slice(),
                b"".as_slice(),
            ] {
                let sha = sha256_hex(body);
                let token = blossom_upload_auth_value(&keys, &host, &sha);
                let mut headers = axum::http::HeaderMap::new();
                headers.insert("authorization", token.parse().expect("auth"));
                headers.insert("x-sha-256", sha.parse().expect("hash"));
                headers.insert("content-type", "image/png".parse().expect("MIME"));
                headers.insert(
                    "content-disposition",
                    "attachment; filename=pretend.png"
                        .parse()
                        .expect("filename"),
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
                    "{route}: {response:?}"
                );
                let json: serde_json::Value =
                    serde_json::from_slice(&response).expect("JSON error");
                assert!(json["error"]
                    .as_str()
                    .expect("error message")
                    .contains("Google Drive"));
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
    fn images_only_preserves_image_round_trip_and_existing_file_download() {
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
        for body in [old_file.as_slice(), png.as_slice()] {
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
        mutate_state(&mut state, |config| config.media.max_image_bytes = 32);
        let oversized = upload(&state, "/upload", &png);
        assert_eq!(oversized.0, StatusCode::PAYLOAD_TOO_LARGE);
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
