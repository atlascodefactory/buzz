//! Optional independent Git object storage. Media providers need not support CAS.

use super::ConfigError;
use buzz_media::{config::S3AddressingStyle, MediaConfig};

const NAMES: [&str; 6] = [
    "BUZZ_GIT_S3_ENDPOINT",
    "BUZZ_GIT_S3_ACCESS_KEY",
    "BUZZ_GIT_S3_SECRET_KEY",
    "BUZZ_GIT_S3_BUCKET",
    "BUZZ_GIT_S3_REGION",
    "BUZZ_GIT_S3_ADDRESSING_STYLE",
];

/// Complete connection settings for the Git backend's conditional-write store.
#[derive(Clone)]
pub struct GitStorageConfig {
    /// S3-compatible HTTP(S) endpoint.
    pub endpoint: String,
    /// Static access ID, kept out of Debug output.
    pub access_key: String,
    /// Static secret, kept out of Debug output.
    pub secret_key: String,
    /// Bucket containing Git manifests, packs and pointers.
    pub bucket: String,
    /// Signing region.
    pub region: String,
    /// Path or virtual-hosted request addressing.
    pub addressing_style: S3AddressingStyle,
}

impl std::fmt::Debug for GitStorageConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitStorageConfig")
            .field("endpoint", &self.endpoint)
            .field("access_key", &"[REDACTED]")
            .field("secret_key", &"[REDACTED]")
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("addressing_style", &self.addressing_style)
            .finish()
    }
}

impl GitStorageConfig {
    pub(super) fn from_env() -> Result<Option<Self>, ConfigError> {
        Self::from_lookup(|name| match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(ConfigError::InvalidValue(format!(
                "{name} must be valid Unicode"
            ))),
        })
    }

    fn from_lookup(
        lookup: impl Fn(&str) -> Result<Option<String>, ConfigError>,
    ) -> Result<Option<Self>, ConfigError> {
        let values = NAMES
            .iter()
            .map(|name| lookup(name))
            .collect::<Result<Vec<_>, _>>()?;
        if values.iter().all(Option::is_none) {
            return Ok(None);
        }
        // A partial override must never send media credentials to a different
        // backend or silently leave Git on the media bucket.
        let mut complete = Vec::with_capacity(NAMES.len());
        for (name, value) in NAMES.iter().zip(values) {
            let value = value
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    ConfigError::InvalidValue(format!(
                        "{name} is required when any BUZZ_GIT_S3_* setting is configured"
                    ))
                })?;
            complete.push(value);
        }
        let endpoint = url::Url::parse(&complete[0]).map_err(|_| {
            ConfigError::InvalidValue("BUZZ_GIT_S3_ENDPOINT must be an HTTP(S) URL".into())
        })?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(ConfigError::InvalidValue(
                "BUZZ_GIT_S3_ENDPOINT must be an HTTP(S) URL without credentials, query or fragment"
                    .into(),
            ));
        }
        let addressing_style = complete[5].parse().map_err(|_| {
            ConfigError::InvalidValue("BUZZ_GIT_S3_ADDRESSING_STYLE must be path or virtual".into())
        })?;
        Ok(Some(Self {
            endpoint: complete[0].clone(),
            access_key: complete[1].clone(),
            secret_key: complete[2].clone(),
            bucket: complete[3].clone(),
            region: complete[4].clone(),
            addressing_style,
        }))
    }

    pub(super) fn from_media(media: &MediaConfig) -> Self {
        Self {
            endpoint: media.s3_endpoint.clone(),
            access_key: media.s3_access_key.clone(),
            secret_key: media.s3_secret_key.clone(),
            bucket: media.s3_bucket.clone(),
            region: media.s3_region.clone(),
            addressing_style: media.s3_addressing_style,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values() -> [String; 6] {
        [
            "http://minio:9000",
            "git-access",
            "git-secret",
            "git",
            "us-east-1",
            "path",
        ]
        .map(String::from)
    }

    fn parse(values: &[Option<String>]) -> Result<Option<GitStorageConfig>, ConfigError> {
        GitStorageConfig::from_lookup(|name| {
            Ok(NAMES
                .iter()
                .position(|key| *key == name)
                .and_then(|i| values[i].clone()))
        })
    }

    #[test]
    fn no_overrides_preserves_shared_storage() {
        assert!(parse(&[None, None, None, None, None, None])
            .unwrap()
            .is_none());
    }

    #[test]
    fn every_partial_override_is_rejected() {
        for mask in 1u8..63 {
            let configured: Vec<_> = values()
                .into_iter()
                .enumerate()
                .map(|(i, value)| (mask & (1 << i) != 0).then_some(value))
                .collect();
            assert!(parse(&configured).is_err(), "partial override {mask}");
        }
    }

    #[test]
    fn complete_override_and_redacted_debug() {
        let config = parse(&values().map(Some)).unwrap().unwrap();
        assert_eq!(config.endpoint, "http://minio:9000");
        assert_eq!(config.bucket, "git");
        let debug = format!("{config:?}");
        assert!(!debug.contains("git-secret"));
        assert!(!debug.contains("git-access"));
    }

    #[test]
    fn resolved_git_config_follows_media_only_without_override() {
        let mut config = super::super::Config::test_default();
        config.git_storage = None;
        config.media.s3_endpoint = "https://media.example.invalid".into();
        config.media.s3_bucket = "media-only".into();
        assert_eq!(config.resolved_git_storage().bucket, "media-only");
        config.git_storage = parse(&values().map(Some)).unwrap();
        assert_eq!(config.resolved_git_storage().endpoint, "http://minio:9000");
        assert_eq!(config.resolved_git_storage().bucket, "git");
        assert_eq!(config.media.s3_bucket, "media-only");
    }

    #[test]
    fn invalid_values_fail_without_echoing_credentials() {
        for (index, value) in [
            (0, "https://secret@host.invalid"),
            (0, "file:///tmp/test"),
            (2, " "),
            (5, "unknown"),
        ] {
            let mut input = values().map(Some);
            input[index] = Some(value.into());
            let error = parse(&input).unwrap_err().to_string();
            assert!(!error.contains("git-secret"));
            assert!(!error.contains("secret@"));
        }
    }
}
