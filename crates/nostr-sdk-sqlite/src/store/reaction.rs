// Copyright (c) 2022-2023 Yuki Kishimoto
// Distributed under the MIT software license

use std::str::FromStr;

use nostr::secp256k1::XOnlyPublicKey;
use nostr::{Event, Sha256Hash};

use crate::error::Error;
use crate::store::Store;

impl Store {
    pub fn insert_reaction(&self, event: &Event) -> Result<(), Error> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT OR IGNORE INTO reaction (event_id, pubkey, content) VALUES (?, ?, ?);",
            (
                event.id.to_string(),
                event.pubkey.to_string(),
                event.content.clone(),
            ),
        )?;
        Ok(())
    }

    pub fn get_reactions(&self, event_id: Sha256Hash) -> Result<Vec<XOnlyPublicKey>, Error> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT pubkey FROM reaction WHERE event_id = ?")?;
        let mut rows = stmt.query([event_id.to_string()])?;

        let mut authors: Vec<XOnlyPublicKey> = Vec::new();
        while let Ok(Some(row)) = rows.next() {
            let pubkey: String = row.get(0)?;
            authors.push(XOnlyPublicKey::from_str(&pubkey)?);
        }
        Ok(authors)
    }

    pub fn count_reactions(&self, event_id: Sha256Hash) -> Result<usize, Error> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM reaction WHERE event_id = ?;")?;
        let mut rows = stmt.query([event_id.to_string()])?;

        match rows.next()? {
            Some(row) => {
                Ok(row.get(0)?)
            }
            None => Err(Error::ValueNotFound),
        }
    }
}
