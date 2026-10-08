use super::*;

fn inspection(
    f: &Fixture,
    cursor: Option<Uuid>,
    receipt: Option<nostr::EventId>,
) -> AssignedBotCommand {
    // Host and the isolated Docker VM may straddle a second boundary. Keep the
    // signed fixture in the past; production's strict lifetime is unchanged.
    let base = f.command_at(
        true,
        1,
        Uuid::new_v4(),
        &f.owner,
        Timestamp::now().as_secs().saturating_sub(1),
        60,
    );
    let mut tags: Vec<Tag> = base.event().tags.iter().cloned().collect();
    if let Some(cursor) = cursor {
        tags.push(Tag::parse(["cursor".to_string(), cursor.to_string()]).unwrap());
    }
    if let Some(receipt) = receipt {
        tags.push(Tag::parse(["receipt".to_string(), receipt.to_hex()]).unwrap());
    }
    let event = EventBuilder::new(Kind::Custom(kind::KIND_ASSIGNED_BOT_INSPECTION as u16), "")
        .custom_created_at(base.event().created_at)
        .tags(tags)
        .sign_with_keys(&f.authority)
        .unwrap();
    AssignedBotCommand::verify(
        &event,
        f.community,
        &f.authority.public_key(),
        Some(&f.authority.public_key()),
        Timestamp::now().as_secs(),
    )
    .unwrap()
}

async fn inspect(f: &Fixture, command: &AssignedBotCommand) -> Result<serde_json::Value> {
    let mut tx = f.pool.begin().await?;
    let observation = inspect_in_transaction(&mut tx, command).await?;
    tx.commit().await?;
    Ok(observation)
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn inspection_reports_missing_active_and_revoked_without_bootstrapping() {
    let f = Fixture::new().await;
    sqlx::query("UPDATE channels SET name = $3 WHERE community_id = $1 AND id = $2")
        .bind(f.community.as_uuid())
        .bind(f.channel)
        .bind("🦉".repeat(200))
        .execute(&f.pool)
        .await
        .unwrap();
    let command = inspection(&f, None, None);
    assert!(f.apply(&command).await.is_err());
    let missing = inspect(&f, &command).await.unwrap();
    assert_eq!(missing["assignmentState"], "missing");
    assert_eq!(missing["ownerActive"], true);
    assert_eq!(missing["accessReady"], false);
    assert_eq!(missing["channels"][0]["visibility"], "closed");
    assert_eq!(
        missing["channels"][0]["name"]
            .as_str()
            .unwrap()
            .encode_utf16()
            .count(),
        200
    );
    assert_eq!(missing["channels"][0]["botAccessReady"], false);
    assert_eq!(missing["channels"][0]["botRole"], serde_json::Value::Null);
    assert_eq!(f.count("assigned_bots").await, 0);
    assert_eq!(f.count("assigned_bot_commands").await, 0);
    assert!(f.role().await.is_none());
    assert!(inspect(&f, &command).await.is_err());
    let admission = f.command(false, 1, Uuid::new_v4());
    f.apply(&admission).await.unwrap();
    let active = inspect(&f, &inspection(&f, None, Some(admission.event_id())))
        .await
        .unwrap();
    assert_eq!(active["assignmentState"], "active");
    assert_eq!(active["receiptCommitted"], true);
    assert_eq!(active["accessReady"], true);
    assert_eq!(active["channels"][0]["botAccessReady"], true);
    let revoked = f.command(true, 1, Uuid::new_v4());
    f.apply(&revoked).await.unwrap();
    let observation = inspect(&f, &inspection(&f, None, Some(revoked.event_id())))
        .await
        .unwrap();
    assert_eq!(observation["assignmentState"], "revoked");
    assert_eq!(observation["receiptCommitted"], true);
    assert_eq!(observation["accessReady"], false);
    assert_eq!(observation["channels"][0]["botAccessReady"], false);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn inspection_rejects_coordinate_drift_and_concurrent_replay() {
    let mut f = Fixture::new().await;
    let command = inspection(&f, None, None);
    let (a, b) = tokio::join!(inspect(&f, &command), inspect(&f, &command));
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
    f.assignment = Uuid::new_v4();
    assert!(inspect(&f, &inspection(&f, None, None)).await.is_err());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn inspection_owner_departure_hides_private_channels_and_denies_access() {
    let f = Fixture::new().await;
    f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
    sqlx::query("DELETE FROM relay_members WHERE community_id = $1 AND pubkey = $2")
        .bind(f.community.as_uuid())
        .bind(f.owner.public_key().to_hex())
        .execute(&f.pool)
        .await
        .unwrap();
    let observation = inspect(&f, &inspection(&f, None, None)).await.unwrap();
    assert_eq!(observation["ownerActive"], false);
    assert_eq!(observation["accessReady"], false);
    assert_eq!(observation["channels"], serde_json::json!([]));
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn inspection_paginates_only_current_owner_channels_and_excludes_archived() {
    let f = Fixture::new().await;
    for index in 0..100 {
        crate::channel::create_channel(
            &f.pool,
            f.community,
            &format!("inspection-{index}"),
            crate::channel::ChannelType::Stream,
            crate::channel::ChannelVisibility::Private,
            None,
            &f.owner.public_key().to_bytes(),
            None,
        )
        .await
        .unwrap();
    }
    let first = inspect(&f, &inspection(&f, None, None)).await.unwrap();
    assert_eq!(first["channels"].as_array().unwrap().len(), 100);
    let cursor = first["nextCursor"].as_str().unwrap().parse().unwrap();
    let second = inspect(&f, &inspection(&f, Some(cursor), None))
        .await
        .unwrap();
    assert_eq!(second["channels"].as_array().unwrap().len(), 1);
    assert!(second["nextCursor"].is_null());
    let ids: std::collections::HashSet<_> = first["channels"]
        .as_array()
        .unwrap()
        .iter()
        .chain(second["channels"].as_array().unwrap())
        .map(|c| c["channelId"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 101);
    sqlx::query("UPDATE channels SET archived_at = now() WHERE community_id = $1 AND id = $2")
        .bind(f.community.as_uuid())
        .bind(f.channel)
        .execute(&f.pool)
        .await
        .unwrap();
    let after = inspect(&f, &inspection(&f, None, None)).await.unwrap();
    assert_eq!(after["channels"].as_array().unwrap().len(), 100);
    assert!(after["nextCursor"].is_null());
    assert!(after["channels"]
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["channelId"] != f.channel.to_string()));
}
