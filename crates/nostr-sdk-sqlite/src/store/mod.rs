// Copyright (c) 2022-2023 Yuki Kishimoto
// Distributed under the MIT software license

use std::path::Path;
use std::str::FromStr;

use nostr::secp256k1::schnorr::Signature;
use nostr::secp256k1::XOnlyPublicKey;
use nostr::{Contact, Event, Kind, KindBase, Metadata, Sha256Hash, Tag};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::OpenFlags;
use serde::de::DeserializeOwned;
use serde::Serialize;

mod profile;
mod reaction;
mod relay;

use crate::error::Error;
use crate::model::Profile;
use crate::schema::{self, STARTUP_SQL};

pub(crate) type SqlitePool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;
pub(crate) type PooledConnection = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;

#[derive(Debug, Clone)]
pub struct Store {
    owner_pubkey: XOnlyPublicKey,
    pool: SqlitePool,
}

impl Drop for Store {
    fn drop(&mut self) {}
}

impl Store {
    pub fn open<P>(path: P, owner_pubkey: XOnlyPublicKey) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref().join(format!("{}.db", owner_pubkey));
        let manager = SqliteConnectionManager::file(path)
            .with_flags(OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE)
            .with_init(|c| c.execute_batch(STARTUP_SQL));
        let pool = r2d2::Pool::new(manager)?;
        schema::upgrade_db(&mut pool.get()?)?;
        Ok(Self { pool, owner_pubkey })
    }

    pub fn close(self) {
        drop(self);
    }

    fn serialize<T>(&self, data: T) -> Result<Vec<u8>, Error>
    where
        T: Serialize + std::fmt::Debug,
    {
        match serde_json::to_string(&data) {
            Ok(serialized) => Ok(serialized.into_bytes()),
            Err(_) => Err(Error::FailedToSerialize),
        }
    }

    fn deserialize<T>(&self, data: &[u8]) -> Result<T, Error>
    where
        T: DeserializeOwned,
    {
        match serde_json::from_slice::<T>(data) {
            Ok(u) => Ok(u),
            Err(_) => Err(Error::FailedToDeserialize),
        }
    }

    pub fn handle_event(&self, event: &Event) -> Result<(), Error> {
        match event.kind {
            Kind::Base(KindBase::Metadata) => {
                let metadata = Metadata::from_json(&event.content)?;
                let mut profile = Profile {
                    pubkey: event.pubkey,
                    name: metadata.name,
                    display_name: metadata.display_name,
                    about: metadata.about,
                    website: metadata.website,
                    picture: metadata.picture,
                    nip05: metadata.nip05,
                    lud06: metadata.lud06,
                    lud16: metadata.lud16,
                    followed: event.pubkey == self.owner_pubkey,
                    metadata_at: event.created_at,
                };

                if let Ok(saved_profile) = self.get_profile(event.pubkey) {
                    if event.created_at > saved_profile.metadata_at {
                        profile.followed = saved_profile.followed;
                        self.update_profile(profile)?;
                    }
                } else {
                    self.insert_profile(profile)?;
                }
            }
            Kind::Base(KindBase::ContactList) => {
                let mut contact_list: Vec<Contact> = Vec::new();
                for tag in event.tags.clone().into_iter() {
                    match tag {
                        Tag::PubKey(pk, relay_url) => {
                            contact_list.push(Contact::new::<String>(pk, relay_url, None))
                        }
                        Tag::ContactList {
                            pk,
                            relay_url,
                            alias,
                        } => contact_list.push(Contact::new(pk, relay_url, alias)),
                        _ => (),
                    }
                }
                self.set_contacts(contact_list)?;
            }
            Kind::Base(KindBase::Reaction) => self.insert_reaction(event)?,
            Kind::Base(KindBase::TextNote) | Kind::Base(KindBase::Boost) => {
                self.insert_event(event)?
            }
            _ => (),
        };
        Ok(())
    }

    pub fn insert_event(&self, event: &Event) -> Result<(), Error> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT OR IGNORE INTO profile (pubkey) VALUES (?)",
            [event.pubkey.to_string()],
        )?;
        conn.execute(
            "INSERT OR IGNORE INTO event (id, pubkey, created_at, kind, tags, content, sig) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                event.id.to_string(),
                event.pubkey.to_string(),
                event.created_at,
                event.kind.as_u64(),
                self.serialize(event.tags.clone())?,
                event.content.clone(),
                event.sig.to_string(),
            ),
        )?;

        Ok(())
    }

    pub fn get_feed(&self, since: Option<u64>, until: Option<u64>) -> Result<Vec<Event>, Error> {
        let conn = self.pool.get()?;
        let mut stmt = conn
            .prepare("SELECT * FROM event WHERE kind IN (?, ?) AND created_at >= ? AND created_at < ? ORDER BY created_at DESC")?;
        let mut rows = stmt.query([
            1,
            6,
            since.unwrap_or_default(),
            until.unwrap_or(i64::MAX as u64),
        ])?;

        let mut events = Vec::new();

        while let Ok(Some(row)) = rows.next() {
            let id: String = row.get(0)?;
            let pubkey: String = row.get(1)?;
            let tags: Vec<u8> = row.get(4)?;
            let sig: String = row.get(6)?;
            events.push(Event {
                id: Sha256Hash::from_str(&id)?,
                pubkey: XOnlyPublicKey::from_str(&pubkey)?,
                created_at: row.get(2)?,
                kind: Kind::Custom(row.get(3)?),
                tags: self.deserialize(&tags)?,
                content: row.get(5)?,
                ots: None,
                sig: Signature::from_str(&sig)?,
            })
        }

        Ok(events)
    }

    pub fn get_feed_with_limit(&self, limit: usize, page: usize) -> Result<Vec<Event>, Error> {
        let conn = self.pool.get()?;
        let mut stmt = conn
            .prepare("SELECT * FROM event WHERE kind IN (?, ?) ORDER BY created_at DESC LIMIT ?")?;
        let mut rows = stmt.query([1, 6, limit * page])?;

        let mut events = Vec::new();

        while let Ok(Some(row)) = rows.next() {
            let id: String = row.get(0)?;
            let pubkey: String = row.get(1)?;
            let tags: Vec<u8> = row.get(4)?;
            let sig: String = row.get(6)?;
            events.push(Event {
                id: Sha256Hash::from_str(&id)?,
                pubkey: XOnlyPublicKey::from_str(&pubkey)?,
                created_at: row.get(2)?,
                kind: Kind::Custom(row.get(3)?),
                tags: self.deserialize(&tags)?,
                content: row.get(5)?,
                ots: None,
                sig: Signature::from_str(&sig)?,
            })
        }

        Ok(events)
    }
}
