// Copyright (c) 2022-2023 Yuki Kishimoto
// Distributed under the MIT software license

use std::collections::HashMap;
use std::net::SocketAddr;
#[cfg(feature = "sqlite")]
use std::path::Path;
use std::str::FromStr;
#[cfg(feature = "sqlite")]
use std::time::Duration;

#[cfg(feature = "sqlite")]
use futures_util::future::abortable;
use nostr::event::builder::Error as EventBuilderError;
use nostr::key::XOnlyPublicKey;
use nostr::url::Url;
use nostr::{
    ClientMessage, Contact, Entity, Event, EventBuilder, Keys, Kind, KindBase, Metadata,
    Sha256Hash, SubscriptionFilter, Tag,
};
#[cfg(feature = "sqlite")]
use nostr_sdk_sqlite::Store;
use tokio::sync::broadcast;

#[cfg(feature = "blocking")]
pub mod blocking;

use crate::relay::pool::{Error as RelayPoolError, RelayPool, RelayPoolNotification};
use crate::Relay;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Url parse error
    #[error("impossible to parse URL: {0}")]
    Url(#[from] nostr::url::ParseError),
    #[error("relay pool error: {0}")]
    RelayPool(#[from] RelayPoolError),
    #[error("relay not found")]
    RelayNotFound,
    #[error("event builder error: {0}")]
    EventBuilder(#[from] EventBuilderError),
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] nostr::secp256k1::Error),
    #[error("hex decoding error: {0}")]
    Hex(#[from] nostr::hashes::hex::Error),
    #[cfg(feature = "sqlite")]
    #[error(transparent)]
    Store(#[from] nostr_sdk_sqlite::Error),
    /// Store not initialized
    #[error("store not initialized")]
    StoreNotInitialized,
}

#[derive(Debug, Clone)]
pub struct Client {
    pool: RelayPool,
    keys: Keys,
    #[cfg(feature = "sqlite")]
    store: Option<Store>,
}

impl Client {
    /// Create a new `Client`
    ///
    /// # Example
    /// ```rust,no_run
    /// use nostr_sdk::Client;
    ///
    /// let my_keys = Client::generate_keys();
    /// let client = Client::new(&my_keys);
    /// ```
    pub fn new(keys: &Keys) -> Self {
        Self {
            pool: RelayPool::new(),
            keys: keys.clone(),
            #[cfg(feature = "sqlite")]
            store: None,
        }
    }

    #[cfg(feature = "sqlite")]
    pub fn new_with_store<P>(keys: &Keys, path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Ok(Self {
            pool: RelayPool::new(),
            keys: keys.clone(),
            store: Some(Store::open(path, keys.public_key())?),
        })
    }

    /// Generate new random keys using entorpy from OS
    pub fn generate_keys() -> Keys {
        Keys::generate_from_os_random()
    }

    /// Get current [`Keys`]
    pub fn keys(&self) -> Keys {
        self.keys.clone()
    }

    #[cfg(feature = "sqlite")]
    pub fn store(&self) -> Result<Store, Error> {
        self.store.clone().ok_or(Error::StoreNotInitialized)
    }

    /// Completly shutdown [`Client`]
    pub async fn shutdown(self) -> Result<(), Error> {
        Ok(self.pool.shutdown().await?)
    }

    /// Get new notification listener
    pub fn notifications(&self) -> broadcast::Receiver<RelayPoolNotification> {
        self.pool.notifications()
    }

    /// Get relays
    pub async fn relays(&self) -> HashMap<Url, Relay> {
        self.pool.relays().await
    }

    /// Add new relay
    ///
    /// # Example
    /// ```rust,no_run
    /// # use nostr_sdk::Client;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let my_keys = Client::generate_keys();
    /// #   let client = Client::new(&my_keys);
    /// client
    ///     .add_relay("wss://relay.nostr.info", None)
    ///     .await
    ///     .unwrap();
    /// client
    ///     .add_relay("wss://relay.damus.io", None)
    ///     .await
    ///     .unwrap();
    /// # }
    /// ```
    pub async fn add_relay<S>(&self, url: S, proxy: Option<SocketAddr>) -> Result<(), Error>
    where
        S: Into<String>,
    {
        let url = Url::parse(&url.into())?;
        #[cfg(feature = "sqlite")]
        {
            let store = self.store()?;
            store.insert_relay(url.clone(), proxy)?;
            store.enable_relay(url.clone())?;
        }
        self.pool.add_relay(url, proxy).await;
        Ok(())
    }

    /// Disconnect and remove relay
    ///
    /// # Example
    /// ```rust,no_run
    /// # use nostr_sdk::Client;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let my_keys = Client::generate_keys();
    /// #   let client = Client::new(&my_keys);
    /// client.remove_relay("wss://relay.nostr.info").await.unwrap();
    /// # }
    /// ```
    pub async fn remove_relay<S>(&self, url: S) -> Result<(), Error>
    where
        S: Into<String>,
    {
        let url = Url::parse(&url.into())?;
        #[cfg(feature = "sqlite")]
        self.store()?.delete_relay(url.clone())?;
        self.pool.remove_relay(url).await;
        Ok(())
    }

    /// Add multiple relays
    pub async fn add_relays<S>(&self, relays: Vec<(S, Option<SocketAddr>)>) -> Result<(), Error>
    where
        S: Into<String>,
    {
        for (url, proxy) in relays.into_iter() {
            self.add_relay(url, proxy).await?;
        }
        Ok(())
    }

    /// Restore previous added relays from store
    #[cfg(feature = "sqlite")]
    pub async fn restore_relays(&self) -> Result<(), Error> {
        let relays = self.store()?.get_relays(true)?;
        for (url, proxy) in relays.into_iter() {
            self.pool.add_relay(url, proxy).await;
        }
        Ok(())
    }

    /// Connect relay
    ///
    /// # Example
    /// ```rust,no_run
    /// # use nostr_sdk::Client;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let my_keys = Client::generate_keys();
    /// #   let client = Client::new(&my_keys);
    /// client
    ///     .connect_relay("wss://relay.nostr.info", true)
    ///     .await
    ///     .unwrap();
    /// # }
    /// ```
    pub async fn connect_relay<S>(&self, url: S, wait_for_connection: bool) -> Result<(), Error>
    where
        S: Into<String>,
    {
        let url = Url::parse(&url.into())?;
        if let Some(relay) = self.pool.relays().await.get(&url) {
            #[cfg(feature = "sqlite")]
            self.store()?.enable_relay(url)?;
            self.pool.connect_relay(relay, wait_for_connection).await;
            return Ok(());
        }
        Err(Error::RelayNotFound)
    }

    /// Disconnect relay
    ///
    /// # Example
    /// ```rust,no_run
    /// # use nostr_sdk::Client;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let my_keys = Client::generate_keys();
    /// #   let client = Client::new(&my_keys);
    /// client
    ///     .disconnect_relay("wss://relay.nostr.info")
    ///     .await
    ///     .unwrap();
    /// # }
    /// ```
    pub async fn disconnect_relay<S>(&self, url: S) -> Result<(), Error>
    where
        S: Into<String>,
    {
        let url = Url::parse(&url.into())?;
        if let Some(relay) = self.pool.relays().await.get(&url) {
            #[cfg(feature = "sqlite")]
            self.store()?.disable_relay(url)?;
            self.pool.disconnect_relay(relay).await?;
            return Ok(());
        }
        Err(Error::RelayNotFound)
    }

    /// Connect to all added relays without waiting for connection and keep connection alive
    ///
    /// # Example
    /// ```rust,no_run
    /// # use nostr_sdk::Client;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let my_keys = Client::generate_keys();
    /// #   let client = Client::new(&my_keys);
    /// client.connect().await;
    /// # }
    /// ```
    pub async fn connect(&self) {
        self.pool.connect(false).await;
    }

    /// Connect to all added relays waiting for initial connection and keep connection alive
    ///
    /// # Example
    /// ```rust,no_run
    /// # use nostr_sdk::Client;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let my_keys = Client::generate_keys();
    /// #   let client = Client::new(&my_keys);
    /// client.connect_and_wait().await;
    /// # }
    /// ```
    pub async fn connect_and_wait(&self) {
        self.pool.connect(true).await;
    }

    /// Disconnect from all relays
    ///
    /// # Example
    /// ```rust,no_run
    /// # use nostr_sdk::Client;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let my_keys = Client::generate_keys();
    /// #   let client = Client::new(&my_keys);
    /// client.disconnect().await.unwrap();
    /// # }
    /// ```
    pub async fn disconnect(&self) -> Result<(), Error> {
        Ok(self.pool.disconnect().await?)
    }

    /// Subscribe to filters
    ///
    /// # Example
    /// ```rust,no_run
    /// # use nostr_sdk::Client;
    /// use nostr::util::time;
    /// use nostr::SubscriptionFilter;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let my_keys = Client::generate_keys();
    /// #   let client = Client::new(&my_keys);
    /// let subscription = SubscriptionFilter::new()
    ///     .pubkeys(vec![my_keys.public_key()])
    ///     .since(time::timestamp());
    ///
    /// client.subscribe(vec![subscription]).await.unwrap();
    /// # }
    /// ```
    pub async fn subscribe(&self, filters: Vec<SubscriptionFilter>) -> Result<(), Error> {
        Ok(self.pool.subscribe(filters).await?)
    }

    /// Get events of filters
    ///
    /// # Example
    /// ```rust,no_run
    /// # use nostr_sdk::Client;
    /// use nostr::util::time;
    /// use nostr::SubscriptionFilter;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let my_keys = Client::generate_keys();
    /// #   let client = Client::new(&my_keys);
    /// let subscription = SubscriptionFilter::new()
    ///     .pubkeys(vec![my_keys.public_key()])
    ///     .since(time::timestamp());
    ///
    /// let _events = client.get_events_of(vec![subscription]).await.unwrap();
    /// # }
    /// ```
    pub async fn get_events_of(
        &self,
        filters: Vec<SubscriptionFilter>,
    ) -> Result<Vec<Event>, Error> {
        Ok(self.pool.get_events_of(filters).await?)
    }

    /// Request events of filters
    /// All events will be received on notification listener (`client.notifications()`)
    pub fn req_events_of(&self, filters: Vec<SubscriptionFilter>) {
        self.pool.req_events_of(filters);
    }

    /// Send client message
    pub async fn send_client_msg(&self, msg: ClientMessage) -> Result<(), Error> {
        Ok(self.pool.send_client_msg(msg).await?)
    }

    /// Send event
    pub async fn send_event(&self, event: Event) -> Result<(), Error> {
        Ok(self
            .pool
            .send_client_msg(ClientMessage::new_event(event))
            .await?)
    }

    /// Update profile metadata
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    ///
    /// # Example
    /// ```rust,no_run
    /// # use nostr_sdk::Client;
    /// use nostr::url::Url;
    /// use nostr_sdk::nostr::Metadata;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let my_keys = Client::generate_keys();
    /// #   let client = Client::new(&my_keys);
    /// let metadata = Metadata::new()
    ///     .name("username")
    ///     .display_name("My Username")
    ///     .about("Description")
    ///     .picture(Url::parse("https://example.com/avatar.png").unwrap())
    ///     .nip05("username@example.com");
    ///
    /// client.update_profile(metadata).await.unwrap();
    /// # }
    /// ```
    pub async fn update_profile(&self, metadata: Metadata) -> Result<(), Error> {
        let event: Event = EventBuilder::set_metadata(metadata)?.to_event(&self.keys)?;
        self.send_event(event).await
    }

    /// Publish text note
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    ///
    /// # Example
    /// ```rust,no_run
    /// # use nostr_sdk::Client;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let my_keys = Client::generate_keys();
    /// #   let client = Client::new(&my_keys);
    /// client
    ///     .publish_text_note("My first text note from Nostr SDK!", &[])
    ///     .await
    ///     .unwrap();
    /// # }
    /// ```
    pub async fn publish_text_note<S>(&self, content: S, tags: &[Tag]) -> Result<(), Error>
    where
        S: Into<String>,
    {
        let event: Event = EventBuilder::new_text_note(content, tags).to_event(&self.keys)?;
        self.send_event(event).await
    }

    /// Publish POW text note
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/13.md>
    ///
    /// # Example
    /// ```rust,no_run
    /// # use nostr_sdk::Client;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let my_keys = Client::generate_keys();
    /// #   let client = Client::new(&my_keys);
    /// client
    ///     .publish_pow_text_note("My first POW text note from Nostr SDK!", &[], 16)
    ///     .await
    ///     .unwrap();
    /// # }
    /// ```
    pub async fn publish_pow_text_note<S>(
        &self,
        content: S,
        tags: &[Tag],
        difficulty: u8,
    ) -> Result<(), Error>
    where
        S: Into<String>,
    {
        let event: Event =
            EventBuilder::new_text_note(content, tags).to_pow_event(&self.keys, difficulty)?;
        self.send_event(event).await
    }

    /// Add recommended relay
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    ///
    /// # Example
    /// ```rust,no_run
    /// # use nostr_sdk::Client;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let my_keys = Client::generate_keys();
    /// #   let client = Client::new(&my_keys);
    /// client
    ///     .add_recommended_relay("wss://relay.damus.io")
    ///     .await
    ///     .unwrap();
    /// # }
    /// ```
    pub async fn add_recommended_relay<S>(&self, url: S) -> Result<(), Error>
    where
        S: Into<String>,
    {
        let url = Url::parse(&url.into())?;
        let event: Event = EventBuilder::add_recommended_relay(&url).to_event(&self.keys)?;
        self.send_event(event).await
    }

    /// Set contact list
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/02.md>
    pub async fn set_contact_list(&self, list: Vec<Contact>) -> Result<(), Error> {
        let event: Event = EventBuilder::set_contact_list(list).to_event(&self.keys)?;
        self.send_event(event).await
    }

    /// Get contact list
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/02.md>
    ///
    /// # Example
    /// ```rust,no_run
    /// # use nostr_sdk::Client;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let my_keys = Client::generate_keys();
    /// #   let client = Client::new(&my_keys);
    /// let _list = client.get_contact_list().await.unwrap();
    /// # }
    /// ```
    pub async fn get_contact_list(&self) -> Result<Vec<Contact>, Error> {
        let mut contact_list: Vec<Contact> = Vec::new();

        let filter = SubscriptionFilter::new()
            .authors(vec![self.keys.public_key()])
            .kind(Kind::Base(KindBase::ContactList))
            .limit(1);
        let events: Vec<Event> = self.get_events_of(vec![filter]).await?;

        for event in events.into_iter() {
            for tag in event.tags.into_iter() {
                if let Tag::ContactList {
                    pk,
                    relay_url,
                    alias,
                } = tag
                {
                    contact_list.push(Contact::new(pk, relay_url, alias));
                }
            }
        }

        Ok(contact_list)
    }

    /// Send encrypted direct message
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/04.md>
    ///
    /// # Example
    /// ```rust,no_run
    /// use nostr::secp256k1::XOnlyPublicKey;
    /// use nostr::util::nips::nip19::FromBech32;
    /// use nostr_sdk::Client;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let my_keys = Client::generate_keys();
    /// #   let client = Client::new(&my_keys);
    /// let alice_pubkey = XOnlyPublicKey::from_bech32(
    ///     "npub14f8usejl26twx0dhuxjh9cas7keav9vr0v8nvtwtrjqx3vycc76qqh9nsy",
    /// )
    /// .unwrap();
    ///
    /// client
    ///     .send_direct_msg(alice_pubkey, "My first DM fro Nostr SDK!")
    ///     .await
    ///     .unwrap();
    /// # }
    /// ```
    #[cfg(feature = "nip04")]
    pub async fn send_direct_msg<S>(&self, receiver: XOnlyPublicKey, msg: S) -> Result<(), Error>
    where
        S: Into<String>,
    {
        let event: Event = EventBuilder::new_encrypted_direct_msg(&self.keys, receiver, msg)?
            .to_event(&self.keys)?;
        self.send_event(event).await
    }

    /// Boost event
    pub async fn boost_event(&self, event: &Event) -> Result<(), Error> {
        let event: Event = EventBuilder::boost(event).to_event(&self.keys)?;
        self.send_event(event).await
    }

    /// Delete event
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/09.md>
    pub async fn delete_event<S>(
        &self,
        event_id: Sha256Hash,
        reason: Option<S>,
    ) -> Result<(), Error>
    where
        S: Into<String>,
    {
        let event: Event = EventBuilder::delete(vec![event_id], reason).to_event(&self.keys)?;
        self.send_event(event).await
    }

    /// Like event
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/25.md>
    ///
    /// # Example
    /// ```rust,no_run
    /// # use nostr_sdk::Client;
    /// use nostr::Event;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let my_keys = Client::generate_keys();
    /// #   let client = Client::new(&my_keys);
    /// let event = Event::from_json(r#"{
    ///         "pubkey":"a8e76c3ace7829f9ee44cf9293309e21a1824bf1e57631d00685a1ed0b0bd8a2",
    ///         "content":"🔥 78,680 blocks to the next Halving 🔥",
    ///         "id":"3aded8d2194dc2fedb1d7b70480b43b6c4deb0a22dcdc9c471d1958485abcf21",
    ///         "created_at":1667337749,
    ///         "sig":"96e0a125e15ecc889757a1b517fdab0223a9ceae22d2591536b5f5186599b50cb1c5f20c2d0d06cdd5cd75368529e33bac4fcd3b321db9865d47785b95b72625",
    ///         "kind":1,
    ///         "tags":[]
    ///     }"#).unwrap();
    ///
    /// client.like(&event).await.unwrap();
    /// # }
    /// ```
    pub async fn like(&self, event: &Event) -> Result<(), Error> {
        let event: Event = EventBuilder::new_reaction(event, true).to_event(&self.keys)?;
        self.send_event(event).await
    }

    /// Disike event
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/25.md>
    ///
    /// # Example
    /// ```rust,no_run
    /// # use nostr_sdk::Client;
    /// use nostr::Event;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let my_keys = Client::generate_keys();
    /// #   let client = Client::new(&my_keys);
    /// let event = Event::from_json(r#"{
    ///     "pubkey":"a8e76c3ace7829f9ee44cf9293309e21a1824bf1e57631d00685a1ed0b0bd8a2",
    ///     "content":"🔥 78,680 blocks to the next Halving 🔥",
    ///     "id":"3aded8d2194dc2fedb1d7b70480b43b6c4deb0a22dcdc9c471d1958485abcf21",
    ///     "created_at":1667337749,
    ///     "sig":"96e0a125e15ecc889757a1b517fdab0223a9ceae22d2591536b5f5186599b50cb1c5f20c2d0d06cdd5cd75368529e33bac4fcd3b321db9865d47785b95b72625",
    ///     "kind":1,
    ///     "tags":[]
    /// }"#).unwrap();
    ///
    /// client.dislike(&event).await.unwrap();
    /// # }
    /// ```
    pub async fn dislike(&self, event: &Event) -> Result<(), Error> {
        let event: Event = EventBuilder::new_reaction(event, false).to_event(&self.keys)?;
        self.send_event(event).await
    }

    /// Create new channel
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/28.md>
    pub async fn new_channel(&self, metadata: Metadata) -> Result<(), Error> {
        let event: Event = EventBuilder::new_channel(metadata)?.to_event(&self.keys)?;
        self.send_event(event).await
    }

    /// Update channel metadata
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/28.md>
    pub async fn update_channel(
        &self,
        channel_id: Sha256Hash,
        relay_url: Url,
        metadata: Metadata,
    ) -> Result<(), Error> {
        let event: Event = EventBuilder::set_channel_metadata(channel_id, relay_url, metadata)?
            .to_event(&self.keys)?;
        self.send_event(event).await
    }

    /// Send message to channel
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/28.md>
    pub async fn send_channel_msg<S>(
        &self,
        channel_id: Sha256Hash,
        relay_url: Url,
        msg: S,
    ) -> Result<(), Error>
    where
        S: Into<String>,
    {
        let event: Event =
            EventBuilder::new_channel_msg(channel_id, relay_url, msg).to_event(&self.keys)?;
        self.send_event(event).await
    }

    /// Hide channel message
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/28.md>
    pub async fn hide_channel_msg<S>(
        &self,
        message_id: Sha256Hash,
        reason: Option<S>,
    ) -> Result<(), Error>
    where
        S: Into<String>,
    {
        let event: Event =
            EventBuilder::hide_channel_msg(message_id, reason).to_event(&self.keys)?;
        self.send_event(event).await
    }

    /// Mute channel user
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/28.md>
    pub async fn mute_channel_user<S>(
        &self,
        pubkey: XOnlyPublicKey,
        reason: Option<S>,
    ) -> Result<(), Error>
    where
        S: Into<String>,
    {
        let event: Event = EventBuilder::mute_channel_user(pubkey, reason).to_event(&self.keys)?;
        self.send_event(event).await
    }

    /// Get a list of channels
    pub async fn get_channels(&self) -> Result<Vec<Event>, Error> {
        self.get_events_of(vec![
            SubscriptionFilter::new().kind(Kind::Base(KindBase::ChannelCreation))
        ])
        .await
    }

    pub async fn get_entity_of<S>(&self, entity: S) -> Result<Entity, Error>
    where
        S: Into<String>,
    {
        let entity: String = entity.into();
        let events: Vec<Event> = self
            .get_events_of(vec![SubscriptionFilter::new()
                .id(&entity)
                .kind(Kind::Base(KindBase::ChannelCreation))
                .limit(1)])
            .await?;
        if events.is_empty() {
            let pubkey = XOnlyPublicKey::from_str(&entity)?;
            let events: Vec<Event> = self
                .get_events_of(vec![SubscriptionFilter::new().author(pubkey).limit(1)])
                .await?;
            if events.is_empty() {
                Ok(Entity::Unknown)
            } else {
                Ok(Entity::Account)
            }
        } else {
            Ok(Entity::Channel)
        }
    }

    #[cfg(feature = "sqlite")]
    pub async fn req_feed(&self, since: Option<u64>, until: Option<u64>) -> Result<(), Error> {
        let store = self.store()?;
        let mut filter = SubscriptionFilter::new()
            .kinds(vec![
                Kind::Base(KindBase::TextNote),
                Kind::Base(KindBase::Boost),
                Kind::Base(KindBase::Reaction),
            ])
            .authors(store.get_contacts_pubkeys()?);
        if let Some(since) = since {
            filter = filter.since(since);
        }
        if let Some(until) = until {
            filter = filter.until(until);
        }
        self.req_events_of(vec![filter]);
        Ok(())
    }

    #[cfg(feature = "sqlite")]
    pub async fn sync(&self) -> Result<(), Error> {
        use crate::thread;
        use nostr::util::time;

        let store: Store = self.store()?;
        let client = self.clone();
        let (update_subscription_thread, handle) = abortable(async move {
            let my_public_key: XOnlyPublicKey = client.keys.public_key();

            let contact_filters = SubscriptionFilter::new()
                .author(my_public_key)
                .kind(Kind::Base(KindBase::ContactList))
                .limit(1);

            /* let dm_filters = SubscriptionFilter::new()
            .pubkey(my_public_key)
            .kind(Kind::Base(KindBase::EncryptedDirectMessage)); */

            let mut contacts_metadata =
                SubscriptionFilter::new().kind(Kind::Base(KindBase::Metadata));

            let mut feed_filters = SubscriptionFilter::new().kinds(vec![
                Kind::Base(KindBase::TextNote),
                Kind::Base(KindBase::Boost),
                Kind::Base(KindBase::Reaction),
            ]);

            loop {
                if let Ok(pubkeys) = store.get_contacts_pubkeys() {
                    if contacts_metadata.authors.as_ref() != Some(&pubkeys) {
                        let now = time::timestamp();
                        let new_metadata_filter =
                            contacts_metadata.clone().authors(pubkeys.clone());
                        let new_feed_filters =
                        feed_filters.clone().authors(pubkeys).since(now - 43200);
                        match client
                            .subscribe(vec![
                                contact_filters.clone(),
                                //dm_filters.clone(),
                                new_metadata_filter.clone(),
                                new_feed_filters.clone(),
                            ])
                            .await
                        {
                            Ok(_) => {
                                contacts_metadata = new_metadata_filter;
                                feed_filters = new_feed_filters;
                                log::debug!("Subscription filters updated");
                            }
                            Err(e) => log::error!("Impossible to subscribe to new filters: {}", e),
                        }
                    }
                } else {
                    log::error!("Impossible to get contacts");
                }
                log::debug!("Wait for new subscription check...");
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });

        thread::spawn(update_subscription_thread);

        let store: Store = self.store()?;
        let client = self.clone();
        thread::spawn(async move {
            let mut notifications = client.notifications();
            while let Ok(notification) = notifications.recv().await {
                match notification {
                    RelayPoolNotification::Event(_url, event) => {
                        if let Err(e) = store.handle_event(&event) {
                            log::error!("Impossible to handle event: {}", e.to_string());
                        }
                    }
                    RelayPoolNotification::Shutdown => {
                        handle.abort();
                        store.close();
                        break;
                    }
                    _ => (),
                }
            }
            log::debug!("Exited from SQLite sync thread");
        });

        Ok(())
    }

    pub async fn handle_notifications<F>(&self, func: F) -> Result<(), Error>
    where
        F: Fn(RelayPoolNotification) -> Result<(), Error>,
    {
        loop {
            let mut notifications = self.notifications();

            while let Ok(notification) = notifications.recv().await {
                func(notification)?;
            }
        }
    }
}
