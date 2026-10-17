CREATE TABLE assigned_bot_commands (
    community_id UUID NOT NULL,
    bot_pubkey BYTEA NOT NULL,
    nonce UUID NOT NULL CHECK (nonce <> '00000000-0000-0000-0000-000000000000'::uuid),
    event_id BYTEA NOT NULL CHECK (length(event_id) = 32),
    PRIMARY KEY (community_id, bot_pubkey, nonce),
    UNIQUE (community_id, event_id),
    FOREIGN KEY (community_id, bot_pubkey) REFERENCES assigned_bots (community_id, bot_pubkey)
);
