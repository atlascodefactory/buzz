use super::*;
use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag, Timestamp};

struct Fixture {
    authority: Keys,
    owner: Keys,
    bot: Keys,
    community: CommunityId,
    channel: Uuid,
    assignment: Uuid,
    nonce: Uuid,
}

#[test]
fn inspection_binds_optional_cursor_and_receipt_without_admission_tags() {
    let f = Fixture::new();
    let receipt = f.event(true).id;
    for cursor in [None, Some(f.channel)] {
        for receipt in [None, Some(receipt)] {
            let mut tags = f.tags(false);
            if let Some(cursor) = cursor {
                tags.push(vec!["cursor".into(), cursor.to_string()]);
            }
            if let Some(receipt) = receipt {
                tags.push(vec!["receipt".into(), receipt.to_hex()]);
            }
            let event = f.signed(kind::KIND_ASSIGNED_BOT_INSPECTION, tags, "");
            assert_eq!(
                f.verify(&event, 1000).unwrap().operation(),
                AssignedBotOperation::Inspect { cursor, receipt }
            );
        }
    }
}

#[test]
fn inspection_rejects_ambiguous_unknown_or_noncanonical_fields() {
    let f = Fixture::new();
    for extra in [
        vec![vec!["cursor".into(), Uuid::nil().to_string()]],
        vec![vec!["receipt".into(), "A".repeat(64)]],
        vec![vec!["receipt".into(), "00".into()]],
        vec![
            vec!["cursor".into(), f.channel.to_string()],
            vec!["cursor".into(), f.channel.to_string()],
        ],
        vec![
            vec!["receipt".into(), "a".repeat(64)],
            vec!["receipt".into(), "b".repeat(64)],
        ],
        vec![vec!["h".into(), f.channel.to_string()]],
        vec![vec!["cursor".into(), f.channel.to_string(), "extra".into()]],
    ] {
        let mut tags = f.tags(false);
        tags.extend(extra);
        assert!(f
            .verify(
                &f.signed(kind::KIND_ASSIGNED_BOT_INSPECTION, tags, ""),
                1000
            )
            .is_err());
    }
    let good = f.tags(false);
    for index in 0..good.len() {
        let mut tags = good.clone();
        tags.remove(index);
        assert!(f
            .verify(
                &f.signed(kind::KIND_ASSIGNED_BOT_INSPECTION, tags, ""),
                1000
            )
            .is_err());
    }
}

#[test]
fn inspection_requires_current_lifetime_actual_signature_and_pinned_actor() {
    let f = Fixture::new();
    let event = f.signed(kind::KIND_ASSIGNED_BOT_INSPECTION, f.tags(false), "");
    for now in [999, 1060, 1061] {
        assert!(f.verify(&event, now).is_err());
    }
    assert!(AssignedBotCommand::verify(
        &event,
        f.community,
        &f.owner.public_key(),
        Some(&f.authority.public_key()),
        1000
    )
    .is_err());
    assert!(
        AssignedBotCommand::verify(&event, f.community, &f.authority.public_key(), None, 1000)
            .is_err()
    );
    assert!(AssignedBotCommand::verify(
        &event,
        CommunityId::from_uuid(Uuid::new_v4()),
        &f.authority.public_key(),
        Some(&f.authority.public_key()),
        1000
    )
    .is_err());
    let mut tampered: serde_json::Value = serde_json::from_str(&event.as_json()).unwrap();
    tampered["sig"] = serde_json::Value::String("0".repeat(128));
    assert_eq!(
        f.verify(&Event::from_json(tampered.to_string()).unwrap(), 1000)
            .unwrap_err(),
        AssignmentCommandError::Signature
    );
}

impl Fixture {
    fn new() -> Self {
        Self {
            authority: Keys::generate(),
            owner: Keys::generate(),
            bot: Keys::generate(),
            community: CommunityId::from_uuid(Uuid::new_v4()),
            channel: Uuid::new_v4(),
            assignment: Uuid::new_v4(),
            nonce: Uuid::new_v4(),
        }
    }
    fn tags(&self, admit: bool) -> Vec<Vec<String>> {
        let mut tags: Vec<Vec<String>> = [
            ["community".into(), self.community.to_string()],
            ["owner".into(), self.owner.public_key().to_hex()],
            ["p".into(), self.bot.public_key().to_hex()],
            ["assignment".into(), self.assignment.to_string()],
            ["assignment-version".into(), "1".into()],
            ["nonce".into(), self.nonce.to_string()],
            ["expiration".into(), "1060".into()],
        ]
        .into_iter()
        .map(Vec::from)
        .collect();
        if admit {
            tags.extend([
                vec!["h".into(), self.channel.to_string()],
                vec!["role".into(), "bot".into()],
                vec!["expected-role".into(), "absent".into()],
            ]);
        }
        tags
    }
    fn signed(&self, kind: u32, tags: Vec<Vec<String>>, content: &str) -> Event {
        EventBuilder::new(Kind::Custom(kind as u16), content)
            .custom_created_at(Timestamp::from(1000))
            .tags(tags.into_iter().map(|tag| Tag::parse(tag).unwrap()))
            .sign_with_keys(&self.authority)
            .unwrap()
    }
    fn event(&self, admit: bool) -> Event {
        self.signed(
            if admit {
                kind::KIND_ASSIGNED_BOT_ADMISSION
            } else {
                kind::KIND_ASSIGNED_BOT_REVOCATION
            },
            self.tags(admit),
            "",
        )
    }
    fn verify(
        &self,
        event: &Event,
        now: u64,
    ) -> Result<AssignedBotCommand, AssignmentCommandError> {
        AssignedBotCommand::verify(
            event,
            self.community,
            &self.authority.public_key(),
            Some(&self.authority.public_key()),
            now,
        )
    }
}

#[test]
fn verifies_real_signature_and_exact_admission_coordinates() {
    let f = Fixture::new();
    for expected in ["absent", "bot"] {
        let mut tags = f.tags(true);
        tags.last_mut().unwrap()[1] = expected.into();
        let event = f.signed(kind::KIND_ASSIGNED_BOT_ADMISSION, tags, "");
        let command = f.verify(&event, 1000).unwrap();
        assert_eq!(command.community(), f.community);
        assert_eq!(command.authority(), f.authority.public_key());
        assert_eq!(command.owner(), f.owner.public_key());
        assert_eq!(command.bot(), f.bot.public_key());
        assert_eq!(command.assignment_id(), f.assignment);
        assert_eq!(command.generation(), 1);
        assert_eq!(command.nonce(), f.nonce);
        assert_eq!(command.event_id(), event.id);
        assert_eq!(
            command.operation(),
            AssignedBotOperation::Admit {
                channel_id: f.channel,
                expected_role: if expected == "bot" {
                    ExpectedBotRole::Bot
                } else {
                    ExpectedBotRole::Absent
                },
            }
        );
    }
}

#[test]
fn revocation_is_global_and_does_not_admit_a_channel() {
    let f = Fixture::new();
    let command = f.verify(&f.event(false), 1000).unwrap();
    assert_eq!(command.operation(), AssignedBotOperation::Revoke);
    let mut tags = f.tags(false);
    tags.push(vec!["h".into(), f.channel.to_string()]);
    assert!(f
        .verify(
            &f.signed(kind::KIND_ASSIGNED_BOT_REVOCATION, tags, ""),
            1000
        )
        .is_err());
}

#[test]
fn refuses_unconfigured_or_foreign_authority_and_transport_actor() {
    let f = Fixture::new();
    let event = f.event(true);
    let foreign = Keys::generate().public_key();
    assert_eq!(
        AssignedBotCommand::verify(&event, f.community, &f.authority.public_key(), None, 1000)
            .unwrap_err(),
        AssignmentCommandError::NotConfigured
    );
    for (actor, pin) in [
        (foreign, f.authority.public_key()),
        (f.authority.public_key(), foreign),
    ] {
        assert_eq!(
            AssignedBotCommand::verify(&event, f.community, &actor, Some(&pin), 1000).unwrap_err(),
            AssignmentCommandError::AuthorityMismatch
        );
    }
}

#[test]
fn never_resolves_community_from_the_claim_or_accepts_other_proof_kinds() {
    let f = Fixture::new();
    assert!(AssignedBotCommand::verify(
        &f.event(true),
        CommunityId::from_uuid(Uuid::new_v4()),
        &f.authority.public_key(),
        Some(&f.authority.public_key()),
        1000
    )
    .is_err());
    for kind in [0, 9, 9000, 9010, 22242, 24243, 27235] {
        assert!(f.verify(&f.signed(kind, f.tags(true), ""), 1000).is_err());
    }
}

#[test]
fn detects_id_and_signature_tampering_before_using_claims() {
    let f = Fixture::new();
    let event = f.event(true);
    for (field, value) in [
        ("content", "tampered".into()),
        ("sig", "0".repeat(128)),
        ("id", "0".repeat(64)),
    ] {
        let mut json: serde_json::Value = serde_json::from_str(&event.as_json()).unwrap();
        json[field] = serde_json::Value::String(value);
        let tampered = Event::from_json(json.to_string()).unwrap();
        assert_eq!(
            f.verify(&tampered, 1000).unwrap_err(),
            AssignmentCommandError::Signature
        );
    }
}

#[test]
fn every_missing_duplicate_extra_and_unknown_tag_fails_closed() {
    let f = Fixture::new();
    for admit in [false, true] {
        let kind = if admit {
            kind::KIND_ASSIGNED_BOT_ADMISSION
        } else {
            kind::KIND_ASSIGNED_BOT_REVOCATION
        };
        let good = f.tags(admit);
        for index in 0..good.len() {
            let mut missing = good.clone();
            missing.remove(index);
            assert!(f.verify(&f.signed(kind, missing, ""), 1000).is_err());
            let mut duplicate = good.clone();
            duplicate.push(good[index].clone());
            assert!(f.verify(&f.signed(kind, duplicate, ""), 1000).is_err());
            for replacement in [
                vec![good[index][0].clone()],
                vec![
                    good[index][0].clone(),
                    good[index][1].clone(),
                    "extra".into(),
                ],
                vec!["unknown".into(), good[index][1].clone()],
            ] {
                let mut bad = good.clone();
                bad[index] = replacement;
                assert!(f.verify(&f.signed(kind, bad, ""), 1000).is_err());
            }
        }
        assert!(f.verify(&f.signed(kind, good, "payload"), 1000).is_err());
    }
}

#[test]
fn canonical_coordinates_and_distinct_key_custody_are_required() {
    let f = Fixture::new();
    for (name, values) in [
        (
            "owner",
            vec![
                f.bot.public_key().to_hex(),
                f.authority.public_key().to_hex(),
                format!("A{}", &f.owner.public_key().to_hex()[1..]),
                "npub1nothex".into(),
                "0".repeat(64),
            ],
        ),
        (
            "p",
            vec![
                f.owner.public_key().to_hex(),
                f.authority.public_key().to_hex(),
                "0".repeat(64),
            ],
        ),
        (
            "assignment",
            vec![
                Uuid::nil().to_string(),
                "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA".into(),
            ],
        ),
        ("nonce", vec![Uuid::nil().to_string(), "not-a-uuid".into()]),
        ("h", vec![Uuid::nil().to_string(), "not-a-channel".into()]),
        (
            "assignment-version",
            vec![
                "0".into(),
                "01".into(),
                "+1".into(),
                "-1".into(),
                (i64::MAX as u64 + 1).to_string(),
            ],
        ),
        (
            "role",
            vec!["owner".into(), "admin".into(), "member".into()],
        ),
        (
            "expected-role",
            vec!["owner".into(), "admin".into(), "member".into()],
        ),
    ] {
        for value in values {
            let mut tags = f.tags(true);
            tags.iter_mut().find(|tag| tag[0] == name).unwrap()[1] = value;
            assert!(
                f.verify(&f.signed(kind::KIND_ASSIGNED_BOT_ADMISSION, tags, ""), 1000)
                    .is_err(),
                "accepted malformed {name}"
            );
        }
    }
}

#[test]
fn lifetime_is_wall_clock_bounded_and_can_be_rechecked_after_waiting() {
    let f = Fixture::new();
    let event = f.event(true);
    let command = f.verify(&event, 1000).unwrap();
    assert!(!command.valid_at(999));
    assert!(command.valid_at(1000));
    assert!(command.valid_at(1059));
    assert!(!command.valid_at(1060));
    for now in [999, 1060, u64::MAX] {
        assert_eq!(
            f.verify(&event, now).unwrap_err(),
            AssignmentCommandError::Lifetime
        );
    }
    for expiration in [
        "999",
        "1000",
        "1061",
        "01060",
        "+1060",
        "18446744073709551616",
    ] {
        let mut tags = f.tags(true);
        tags.iter_mut().find(|tag| tag[0] == "expiration").unwrap()[1] = expiration.into();
        assert!(f
            .verify(&f.signed(kind::KIND_ASSIGNED_BOT_ADMISSION, tags, ""), 1000)
            .is_err());
    }
}

#[test]
fn nonce_and_generation_are_signed_not_replay_authorization() {
    let f = Fixture::new();
    let original = f.event(true);
    let duplicate = f.verify(&original, 1001).unwrap();
    assert_eq!(duplicate.event_id(), original.id);
    assert_eq!(duplicate.nonce(), f.nonce);
    let mut tags = f.tags(true);
    tags.iter_mut().find(|tag| tag[0] == "nonce").unwrap()[1] = Uuid::new_v4().to_string();
    let changed = f.signed(kind::KIND_ASSIGNED_BOT_ADMISSION, tags, "");
    assert_ne!(changed.id, original.id);
    // These checks deliberately make no claim about DB replay/revocation: that
    // requires the transactional consumer, not a signature codec.
}
