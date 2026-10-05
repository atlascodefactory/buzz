//! Explicit single-community assignment-authority pin, disabled by default.

use buzz_core::CommunityId;
use nostr::PublicKey;
use uuid::Uuid;

use crate::config::ConfigError;

/// Separate service authority; not an owner, operator, or NIP-FI login issuer.
#[derive(Debug, Clone)]
pub struct AssignedBotAuthority {
    community: CommunityId,
    public_key: PublicKey,
}

impl AssignedBotAuthority {
    /// Strictly load the pair. Missing both disables; a partial/invalid pin fails.
    pub fn parse(
        community: Option<&str>,
        public_key: Option<&str>,
    ) -> Result<Option<Self>, ConfigError> {
        let (community, public_key) = match (community, public_key) {
            (None, None) => return Ok(None),
            (Some(community), Some(public_key)) => (community, public_key),
            _ => {
                return Err(ConfigError::InvalidValue(
                    "assigned bot authority requires both community and public key".into(),
                ))
            }
        };
        let id = community
            .parse::<Uuid>()
            .map_err(|_| ConfigError::InvalidValue("invalid assigned bot community pin".into()))?;
        if id.is_nil() || id.to_string() != community {
            return Err(ConfigError::InvalidValue(
                "non-canonical assigned bot community pin".into(),
            ));
        }
        if public_key.len() != 64
            || !public_key
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(ConfigError::InvalidValue(
                "invalid assigned bot authority key pin".into(),
            ));
        }
        let public_key = PublicKey::from_hex(public_key).map_err(|_| {
            ConfigError::InvalidValue("invalid assigned bot authority key pin".into())
        })?;
        public_key.xonly().map_err(|_| {
            ConfigError::InvalidValue("invalid assigned bot authority curve point".into())
        })?;
        Ok(Some(Self {
            community: CommunityId::from_uuid(id),
            public_key,
        }))
    }

    /// Return a pin only for the already server-resolved exact community.
    pub fn for_community(&self, community: CommunityId) -> Option<PublicKey> {
        (community == self.community).then_some(self.public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_is_opt_in_exact_and_fail_closed() {
        let id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let key = nostr::Keys::generate().public_key().to_hex();
        assert!(AssignedBotAuthority::parse(None, None).unwrap().is_none());
        for (community, key) in [
            (None, Some(key.as_str())),
            (Some(id), None),
            (Some(""), Some(key.as_str())),
            (
                Some("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
                Some(key.as_str()),
            ),
            (
                Some("00000000-0000-0000-0000-000000000000"),
                Some(key.as_str()),
            ),
            (Some(id), Some("")),
            (
                Some(id),
                Some("0000000000000000000000000000000000000000000000000000000000000000"),
            ),
        ] {
            assert!(AssignedBotAuthority::parse(community, key).is_err());
        }
        let pin = AssignedBotAuthority::parse(Some(id), Some(&key))
            .unwrap()
            .unwrap();
        assert!(pin
            .for_community(CommunityId::from_uuid(Uuid::new_v4()))
            .is_none());
        assert_eq!(
            pin.for_community(CommunityId::from_uuid(id.parse().unwrap()))
                .unwrap()
                .to_hex(),
            key
        );
    }
}
