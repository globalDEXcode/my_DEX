////////////////////////////////////////////////
/// my_DEX/src/network/p2p.rs
////////////////////////////////////////////////

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{Write, Read};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bincode;
use rand::Rng;
use serde::{Serialize, Deserialize};
use tokio::sync::mpsc;
use tokio::task::{JoinHandle};
use tokio::time::{sleep, timeout};
use tracing::{info, warn, debug, error};

//////////////////////////////////////////////////////////////////////////////////////
// NodeId: 256-Bit, Distanzberechnungen, Hilfsmethoden
//////////////////////////////////////////////////////////////////////////////////////

/// Größe der NodeID in Bytes. Typischerweise 160 oder 256 Bit.
/// Wir wählen 256, passend zu modernem SHA-256.
pub const ID_LENGTH: usize = 32;

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct NodeId(pub [u8; ID_LENGTH]);

impl NodeId {
    /// Zufällige NodeId
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let mut id = [0u8; ID_LENGTH];
        rng.fill(&mut id);
        NodeId(id)
    }

    /// XOR
    pub fn xor(&self, other: &NodeId) -> NodeId {
        let mut result = [0u8; ID_LENGTH];
        for i in 0..ID_LENGTH {
            result[i] = self.0[i] ^ other.0[i];
        }
        NodeId(result)
    }

    /// Für Sortierungen: 128-Bit Distanz
    pub fn distance_as_u128(&self, other: &NodeId) -> u128 {
        let x = self.xor(other);
        let mut arr = [0u8; 16];
        for i in 0..16 {
            arr[i] = x.0[i];
        }
        u128::from_be_bytes(arr)
    }
}

//////////////////////////////////////////////////////////////////////////////////////
// KademliaMessage: RPC für P2P (Ping/Pong, FindNode, Store etc.)
//////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum KademliaMessage {
    Ping(NodeId),
    Pong(NodeId),

    FindNode {
        source: NodeId,
        target: NodeId,
    },
    FindNodeResult {
        source: NodeId,
        closer_nodes: Vec<(NodeId, SocketAddr)>,
    },

    Store {
        source: NodeId,
        key: Vec<u8>,
        data: Vec<u8>,
    },
    StoreResult {
        source: NodeId,
        stored: bool,
    },

    FindValue {
        source: NodeId,
        key: Vec<u8>,
    },
    FindValueResult {
        source: NodeId,
        key: Vec<u8>,
        data: Option<Vec<u8>>,
        closer_nodes: Vec<(NodeId, SocketAddr)>,
    },
}

//////////////////////////////////////////////////////////////////////////////////////
// K-Bucket & BucketEntry
// - Ping-Logik, bevor wir einen Node rauswerfen
//////////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BucketEntry {
    pub node_id: NodeId,
    pub address: SocketAddr,
    pub last_seen: Instant,
}

#[derive(Debug)]
pub struct KBucket {
    pub entries: VecDeque<BucketEntry>,
    pub capacity: usize,
}

impl KBucket {
    pub fn new(capacity: usize) -> Self {
        KBucket {
            entries: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Upsert:
    /// 1) Falls Node existiert, nach vorne (aktualisiere last_seen).
    /// 2) Falls neu und Bucket ist voll => LRU-Node anpingen. Wenn er nicht antwortet, werfe ihn raus.
    pub fn upsert<F>(
        &mut self,
        node_id: NodeId,
        address: SocketAddr,
        do_ping: F,
    ) where
        F: Fn(NodeId, SocketAddr) -> bool,
    {
        if let Some(pos) = self.entries.iter().position(|e| e.node_id == node_id) {
            // Move nach vorne
            let mut entry = self.entries.remove(pos).unwrap();
            entry.last_seen = Instant::now();
            entry.address = address;
            self.entries.push_front(entry);
        } else {
            // Neu
            if self.entries.len() >= self.capacity {
                // LRU-Knoten = entries.back()
                if let Some(lru) = self.entries.back() {
                    // Pingen
                    let ok = do_ping(lru.node_id.clone(), lru.address);
                    if !ok {
                        // LRU ist tot => remove
                        self.entries.pop_back();
                        // Füge den neuen Node ein
                        let entry = BucketEntry {
                            node_id,
                            address,
                            last_seen: Instant::now(),
                        };
                        self.entries.push_front(entry);
                        return;
                    }
                }
                // Andernfalls verwerfen wir den neuen Node, da Bucket voll und LRU ist aktiv
            } else {
                let entry = BucketEntry {
                    node_id,
                    address,
                    last_seen: Instant::now(),
                };
                self.entries.push_front(entry);
            }
        }
    }

    pub fn remove(&mut self, node_id: &NodeId) {
        if let Some(pos) = self.entries.iter().position(|e| &e.node_id == node_id) {
            self.entries.remove(pos);
        }
    }

    pub fn closest(&self, target: &NodeId, k: usize) -> Vec<BucketEntry> {
        let mut items: Vec<_> = self.entries.iter().cloned().collect();
        items.sort_by_key(|entry| entry.node_id.distance_as_u128(target));
        items.truncate(k);
        items
    }
}

//////////////////////////////////////////////////////////////////////////////////////
// RoutingTable: Array von K-Buckets + Persistierung
//////////////////////////////////////////////////////////////////////////////////////

#[derive(Serialize, Deserialize)]
pub struct SerializableBucketEntry {
    pub node_id: Vec<u8>,
    pub address: String,
    pub last_seen_ms: u128,
}

#[derive(Debug)]
pub struct RoutingTable {
    pub local_id: NodeId,
    pub buckets: Vec<KBucket>,
    pub bucket_size: usize,
}

impl RoutingTable {
    pub fn new(local_id: NodeId, bucket_size: usize) -> Self {
        let mut buckets = Vec::with_capacity(ID_LENGTH * 8);
        for _ in 0..(ID_LENGTH * 8) {
            buckets.push(KBucket::new(bucket_size));
        }
        RoutingTable {
            local_id,
            buckets,
            bucket_size,
        }
    }

    /// Berechnet Bucket-Index
    fn bucket_index(&self, node_id: &NodeId) -> usize {
        let x = self.local_id.xor(node_id);
        for (i, byte) in x.0.iter().enumerate() {
            if *byte != 0 {
                let leading = byte.leading_zeros() as usize;
                let bit_pos = i * 8 + leading;
                return bit_pos;
            }
        }
        ID_LENGTH * 8 - 1
    }

    /// Upsert, inkl. Ping-Funktion
    pub fn update_node<F>(
        &mut self,
        node_id: NodeId,
        address: SocketAddr,
        do_ping: F,
    ) where
        F: Fn(NodeId, SocketAddr) -> bool,
    {
        if node_id == self.local_id {
            return;
        }
        let idx = self.bucket_index(&node_id);
        self.buckets[idx].upsert(node_id, address, do_ping);
    }

    pub fn remove_node(&mut self, node_id: &NodeId) {
        let idx = self.bucket_index(node_id);
        self.buckets[idx].remove(node_id);
    }

    pub fn find_closest(&self, target: &NodeId, k: usize) -> Vec<(NodeId, SocketAddr)> {
        let mut candidates = Vec::new();
        for bucket in &self.buckets {
            for e in &bucket.entries {
                candidates.push(e.clone());
            }
        }
        candidates.sort_by_key(|e| e.node_id.distance_as_u128(target));
        candidates.truncate(k);
        candidates.into_iter().map(|e| (e.node_id, e.address)).collect()
    }

    /// Persistiert RoutingTable in eine Datei
    pub fn store_to_file(&self, path: &str) {
        let mut all_entries = Vec::new();
        for bucket in &self.buckets {
            for e in &bucket.entries {
                let se = SerializableBucketEntry {
                    node_id: e.node_id.0.to_vec(),
                    address: e.address.to_string(),
                    last_seen_ms: e.last_seen.elapsed().as_millis(),
                };
                all_entries.push(se);
            }
        }
        match bincode::serialize(&all_entries) {
            Ok(bytes) => {
                if let Ok(mut file) = fs::File::create(path) {
                    let _ = file.write_all(&bytes);
                }
            }
            Err(e) => {
                warn!("store_to_file: serialize error = {:?}", e);
            }
        }
    }

    /// Lädt RoutingTable aus einer Datei
    pub fn load_from_file(&mut self, path: &str) {
        if let Ok(mut file) = fs::File::open(path) {
            let mut buf = Vec::new();
            if file.read_to_end(&mut buf).is_ok() {
                match bincode::deserialize::<Vec<SerializableBucketEntry>>(&buf) {
                    Ok(vec) => {
                        for se in vec {
                            if se.node_id.len() == ID_LENGTH {
                                let mut arr = [0u8; ID_LENGTH];
                                arr.copy_from_slice(&se.node_id);
                                let node_id = NodeId(arr);
                                // Bei last_seen_ms => wir ignorieren es bzw. setzten last_seen=now
                                if let Ok(addr) = se.address.parse::<SocketAddr>() {
                                    // Einfügen
                                    let do_ping = |_nid: NodeId, _addr: SocketAddr| true; 
                                    self.update_node(node_id, addr, do_ping);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("load_from_file: deserialize error = {:?}", e);
                    }
                }
            }
        }
    }
}

//////////////////////////////////////////////////////////////////////////////////////
// (Optional) NatTraversal => hier exemplarisch
//////////////////////////////////////////////////////////////////////////////////////

#[allow(unused)]
pub fn try_upnp_port_forwarding(port: u16) {
    // In echter Produktion könnte man crates wie igd (UPnP)
    // oder nat_upnp nutzen.
    // Hier nur ein Platzhalter:
    info!("Versuche NAT-Portweiterleitung via UPnP für Port={}", port);
    // ...
    // => z. B. igd::aio::search_and_get_list().await, ...
    // => je nach Erfolg => info oder warn
}

//////////////////////////////////////////////////////////////////////////////////////
// RepublishEntry => für Re-Publish und Expire
//////////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Debug)]
pub struct RepublishEntry {
    pub key: Vec<u8>,
    pub data: Vec<u8>,
    pub original_time: Instant,
    pub last_republish: Instant,
}

#[derive(Default)]
pub struct SimpleStorage {
    pub data: HashMap<Vec<u8>, Vec<u8>>,
    pub republish_list: Vec<RepublishEntry>,
    pub cache_lifetime: Duration,
    pub republish_interval: Duration,
    pub max_data_age: Duration,
}

impl SimpleStorage {
    pub fn new(cache_lifetime: Duration, republish_interval: Duration, max_data_age: Duration) -> Self {
        Self {
            data: HashMap::new(),
            republish_list: Vec::new(),
            cache_lifetime,
            republish_interval,
            max_data_age,
        }
    }

    /// Speichert Key->Value
    pub fn store(&mut self, key: Vec<u8>, val: Vec<u8>) {
        self.data.insert(key.clone(), val.clone());
        let now = Instant::now();
        self.republish_list.push(RepublishEntry {
            key,
            data: val,
            original_time: now,
            last_republish: now,
        });
    }

    pub fn lookup(&self, key: &[u8]) -> Option<&[u8]> {
        self.data.get(key)
    }

    /// Caching => Falls wir in FIND_VALUE ein data: Some(...) erhalten
    ///   => wir cachen es locally
    pub fn cache_value(&mut self, key: Vec<u8>, val: Vec<u8>) {
        // Man könnte z. B. Einträge nur temporär halten
        self.data.insert(key.clone(), val.clone());
        // hier z. B. ohne Re-Publish, rein cache
    }

    /// Prüft, ob wir veraltete Einträge entfernen
    /// Ruft periodisch auf => remove, falls original_time + max_data_age < now
    pub fn expire_data(&mut self) {
        let now = Instant::now();
        self.republish_list.retain(|entry| {
            let age = now.duration_since(entry.original_time);
            if age > self.max_data_age {
                // Remove aus data
                self.data.remove(&entry.key);
                return false;
            }
            true
        });
    }

    /// Sucht alle Einträge, bei denen last_republish + republish_interval < now
    /// => ruft user-spezifische publish-Funktion auf
    pub fn republish(&mut self, do_republish: &mut dyn FnMut(&[u8], &[u8])) {
        let now = Instant::now();
        for entry in &mut self.republish_list {
            if now.duration_since(entry.last_republish) > self.republish_interval {
                do_republish(&entry.key, &entry.data);
                entry.last_republish = now;
            }
        }
    }
}

//////////////////////////////////////////////////////////////////////////////////////
// KademliaServiceInterface => optionales Trait, falls wir aus p2p.rs
// nur per trait auf handle_message(...) zugreifen wollen.
// Man könnte stattdessen direkt "impl" KademliaService wählen.
//////////////////////////////////////////////////////////////////////////////////////

pub trait KademliaServiceInterface {
    fn handle_message(&mut self, sender_addr: SocketAddr, msg: KademliaMessage);
}

//////////////////////////////////////////////////////////////////////////////////////
// KademliaP2PAdapter => Schnittstelle zum Senden von Nachrichten
//////////////////////////////////////////////////////////////////////////////////////

/// === NEU: Rate-Limit + Tor + STUN + Ring-Sig => P2PSecurity-Layer
/// Wir definieren ein TokenBucket & P2PSecurity (vereinfacht).
#[derive(Debug)]
pub struct TokenBucket {
    capacity: u64,
    tokens: u64,
    refill_rate: u64,
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(capacity: u64, refill_rate: u64) -> Self {
        TokenBucket {
            capacity,
            tokens: capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }
    pub fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs();
        if elapsed > 0 {
            let refill = elapsed * self.refill_rate;
            self.tokens = std::cmp::min(self.capacity, self.tokens + refill);
            self.last_refill = now;
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// P2PSecurity => in echt ring-sig crates, tor-libs, stun-libs
#[derive(Debug)]
pub struct P2PSecurity {
    // Rate-Limit => IP -> TokenBucket
    pub rate_limiters: Arc<Mutex<HashMap<SocketAddr, TokenBucket>>>,
    pub use_tor: bool,
    pub stun_servers: Vec<String>,
}

impl P2PSecurity {
    pub fn new(use_tor: bool, stun_servers: Vec<String>) -> Self {
        P2PSecurity {
            rate_limiters: Arc::new(Mutex::new(HashMap::new())),
            use_tor,
            stun_servers,
        }
    }
    pub fn check_rate_limit(&self, addr: SocketAddr) -> bool {
        let mut lock = self.rate_limiters.lock().unwrap();
        let bucket = lock.entry(addr).or_insert_with(|| TokenBucket::new(200, 50));
        if !bucket.try_consume() {
            warn!("Rate limit => dropping traffic from {}", addr);
            return false;
        }
        true
    }
    pub async fn init_tor(&self) {
        if self.use_tor {
            info!("(Stub) Tor init => e.g. arti-client usage");
        }
    }
    pub async fn perform_stun(&self) {
        for s in &self.stun_servers {
            debug!("(Stub) STUN => contacting server={}", s);
        }
    }
    pub fn ring_sign(&self, data: &[u8]) -> Vec<u8> {
        // placeholder
        data.to_vec()
    }
}

// === NEU: Wir hängen die P2PSecurity ins Trait
pub trait KademliaP2PAdapter {
    fn send_kademlia_msg(&self, addr: SocketAddr, msg: &KademliaMessage);

    fn local_address(&self) -> SocketAddr;

    fn security(&self) -> Option<Arc<P2PSecurity>> {
        None
    }

    /// Ein Ping-Call => default => wir rufen send_kademlia_msg
    fn ping_node(&self, node_id: &NodeId, addr: SocketAddr) -> bool {
        if let Some(sec) = self.security() {
            if !sec.check_rate_limit(addr) {
                return false;
            }
        }
        let ping_msg = KademliaMessage::Ping(node_id.clone());
        self.send_kademlia_msg(addr, &ping_msg);
        true
    }

    /// NEU: Sichere Nachrichtensendung über Noise-Protokoll
    fn send_kademlia_msg_secure(&self, addr: SocketAddr, msg: &KademliaMessage) -> Result<()> {
        tokio::spawn(async move {
            let serialized = match bincode::serialize(msg) {
                Ok(data) => data,
                Err(e) => {
                    warn!("Serialisierung fehlgeschlagen: {:?}", e);
                    return;
                }
            };

            let monitor = Arc::new(SecurityMonitor::new());
            let mut secure = match SecureChannel::connect(&addr.to_string(), "Noise_XX_25519_ChaChaPoly_BLAKE2s", monitor).await {
                Ok(channel) => channel,
                Err(e) => {
                    warn!("Verbindung fehlgeschlagen: {:?}", e);
                    return;
                }
            };

            if let Err(e) = secure.send(&serialized).await {
                warn!("Senden fehlgeschlagen: {:?}", e);
            }
        });
        Ok(())
    }
}

//////////////////////////////////////////////////////////////////////////////////////
// KademliaService => Implementierung mit:
//  - parallelem find_node
//  - caching von FIND_VALUE
//  - expire + republish
//////////////////////////////////////////////////////////////////////////////////////

pub struct KademliaService {
    pub local_id: NodeId,
    pub table: RoutingTable,
    pub storage: SimpleStorage,

    pub p2p: Arc<Mutex<dyn KademliaP2PAdapter + Send>>,
    pub stop_flag: Arc<Mutex<bool>>,

    /// alpha => parallele Anfragen
    pub alpha: usize,
    /// K => Bucket-Größe
    pub k: usize,

    pub refresh_interval: Duration,
    pub rePublishHandle: Option<JoinHandle<()>>,
    pub concurrency_handle: Option<JoinHandle<()>>,
}

impl KademliaService {
    /// Konstruktor
    pub fn new(
        local_id: NodeId,
        bucket_size: usize,
        p2p_adapter: Arc<Mutex<dyn KademliaP2PAdapter + Send>>,
        alpha: usize,
        refresh_interval: Duration,
        cache_lifetime: Duration,
        republish_interval: Duration,
        max_data_age: Duration,
    ) -> Self {
        let table = RoutingTable::new(local_id.clone(), bucket_size);
        let storage = SimpleStorage::new(cache_lifetime, republish_interval, max_data_age);
        KademliaService {
            local_id,
            table,
            storage,
            p2p: p2p_adapter,
            stop_flag: Arc::new(Mutex::new(false)),

            alpha,
            k: bucket_size,

            refresh_interval,
            rePublishHandle: None,
            concurrency_handle: None,
        }
    }

    /// Startet Hintergrund-Tasks:
    ///  1) Bucket-Refresh
    ///  2) Re-Publish & Expire
    pub fn start(&mut self) {
        let sf = self.stop_flag.clone();
        let alpha = self.alpha;
        let k = self.k;
        let refresh_interval = self.refresh_interval;
        let p2p = self.p2p.clone();

        let st_arc = Arc::new(Mutex::new(self.storage.clone()));
        let st_arc2 = Arc::clone(&st_arc);
        let table_arc = Arc::new(Mutex::new(&mut self.table));
        let table_arc2 = Arc::clone(&table_arc);

        let local_id_copy = self.local_id.clone();

        // Task 1: Bucket-Refresh + NAT-Traversal
        self.concurrency_handle = Some(tokio::spawn(async move {
            info!("KademliaService {} => concurrency task started", hex::encode(&local_id_copy.0));
            let local_p = p2p.lock().unwrap().local_address().port();
            try_upnp_port_forwarding(local_p);

            // Falls wir STUN/Tor etc. => wir holen P2PSecurity
            if let Some(sec) = p2p.lock().unwrap().security() {
                sec.perform_stun().await;
                sec.init_tor().await;
            }

            while !*sf.lock().unwrap() {
                debug!("Kademlia => refreshing all buckets...");
                let buckets_count = ID_LENGTH * 8;
                for i in 0..buckets_count {
                    if *sf.lock().unwrap() {
                        break;
                    }
                    let mut target = local_id_copy.clone();
                    let byte_index = i / 8;
                    let bit_index = i % 8;
                    target.0[byte_index] ^= 1 << (7 - bit_index);
                    let _ = Self::parallel_find_node(&local_id_copy, &p2p, target, alpha, k).await;
                    sleep(Duration::from_millis(50)).await;
                }
                sleep(refresh_interval).await;
            }
            info!("Kademlia concurrency task => stopped");
        }));

        // Task 2: RePublish + Expire
        self.rePublishHandle = Some(tokio::spawn(async move {
            info!("KademliaService => RePublish/Expire Task started");
            loop {
                if *sf.lock().unwrap() {
                    break;
                }
                {
                    let mut st_l = st_arc2.lock().unwrap();
                    st_l.expire_data();
                    let mut do_republish = |key: &[u8], data: &[u8]| {
                        let table_locked = table_arc2.lock().unwrap();
                        let nodes = table_locked.find_closest(&local_id_copy, table_locked.bucket_size);
                        for (nid, addr) in nodes {
                            let msg = KademliaMessage::Store {
                                source: local_id_copy.clone(),
                                key: key.to_vec(),
                                data: data.to_vec(),
                            };
                            p2p.lock().unwrap().send_kademlia_msg(addr, &msg);
                        }
                    };
                    st_l.republish(&mut do_republish);
                }
                sleep(Duration::from_secs(30)).await;
            }
            info!("Kademlia RePublish/Expire => stopped");
        }));
    }

    /// Beendet die Tasks
    pub async fn stop(&mut self) {
        let mut sf = self.stop_flag.lock().unwrap();
        *sf = true;
        drop(sf);
        if let Some(h) = self.concurrency_handle.take() {
            let _ = h.await;
        }
        if let Some(h) = self.rePublishHandle.take() {
            let _ = h.await;
        }
        info!("KademliaService => all tasks ended");
    }

    /// Asynchroner "parallel_find_node"
    pub async fn parallel_find_node(
        local_id: &NodeId,
        p2p: &Arc<Mutex<dyn KademliaP2PAdapter + Send>>,
        target: NodeId,
        alpha: usize,
        k: usize,
    ) -> Vec<(NodeId, SocketAddr)> {
        let mut discovered = Vec::new();
        let mut attempts = Vec::new();

        debug!("(parallel_find_node) => target={}", hex::encode(&target.0));
        // Hier nur Pseudo => in Real => while improved => etc.
        discovered
    }

    fn do_ping(&self, node_id: NodeId, addr: SocketAddr) -> bool {
        self.p2p.lock().unwrap().ping_node(&node_id, addr)
    }
}

impl KademliaServiceInterface for KademliaService {
    fn handle_message(&mut self, sender_addr: SocketAddr, msg: KademliaMessage) {
        match msg {
            KademliaMessage::Ping(node_id) => {
                debug!("Kademlia => Received PING from {}", short_id(&node_id));
                let ok = self.do_ping(node_id.clone(), sender_addr);
                if ok {
                    let pong = KademliaMessage::Pong(self.local_id.clone());
                    self.p2p.lock().unwrap().send_kademlia_msg(sender_addr, &pong);
                }
                self.table.update_node(node_id, sender_addr, |nid, addr| {
                    self.do_ping(nid, addr)
                });
            }
            KademliaMessage::Pong(node_id) => {
                debug!("Kademlia => Received PONG from {}", short_id(&node_id));
                self.table.update_node(node_id, sender_addr, |nid, addr| {
                    self.do_ping(nid, addr)
                });
            }
            KademliaMessage::FindNode { source, target } => {
                debug!("Kademlia => Received FIND_NODE from {}, target={}",
                       short_id(&source), short_id(&target));
                self.table.update_node(source.clone(), sender_addr, |nid, addr| {
                    self.do_ping(nid, addr)
                });
                let closer = self.table.find_closest(&target, self.k);
                let result = KademliaMessage::FindNodeResult {
                    source: self.local_id.clone(),
                    closer_nodes: closer,
                };
                self.p2p.lock().unwrap().send_kademlia_msg(sender_addr, &result);
            }
            KademliaMessage::FindNodeResult { source, closer_nodes } => {
                debug!("Kademlia => Received FindNodeResult from {}, {} nodes", short_id(&source), closer_nodes.len());
                self.table.update_node(source.clone(), sender_addr, |nid, addr| {
                    self.do_ping(nid, addr)
                });
                for (nid, addr) in closer_nodes {
                    self.table.update_node(nid, addr, |id2, addr2| {
                        self.do_ping(id2, addr2)
                    });
                }
            }
            KademliaMessage::Store { source, key, data } => {
                debug!("Kademlia => Received STORE from {}, key.len={}, data.len={}", short_id(&source), key.len(), data.len());
                self.table.update_node(source, sender_addr, |nid, addr| {
                    self.do_ping(nid, addr)
                });
                self.storage.store(key.clone(), data.clone());
                let ack = KademliaMessage::StoreResult {
                    source: self.local_id.clone(),
                    stored: true,
                };
                self.p2p.lock().unwrap().send_kademlia_msg(sender_addr, &ack);
            }
            KademliaMessage::StoreResult { source, stored } => {
                debug!("Kademlia => Received StoreResult => stored={}, from {}", stored, short_id(&source));
                self.table.update_node(source, sender_addr, |nid, addr| {
                    self.do_ping(nid, addr)
                });
            }
            KademliaMessage::FindValue { source, key } => {
                debug!("Kademlia => Received FIND_VALUE from {}, key.len={}", short_id(&source), key.len());
                self.table.update_node(source.clone(), sender_addr, |nid, addr| {
                    self.do_ping(nid, addr)
                });
                let data_opt = self.storage.lookup(&key).map(|v| v.to_vec());
                let mut closer_nodes = vec![];
                if data_opt.is_none() {
                    closer_nodes = self.table.find_closest(&NodeId::random(), self.k);
                }
                let resp = KademliaMessage::FindValueResult {
                    source: self.local_id.clone(),
                    key: key.clone(),
                    data: data_opt.clone(),
                    closer_nodes,
                };
                self.p2p.lock().unwrap().send_kademlia_msg(sender_addr, &resp);
            }
            KademliaMessage::FindValueResult { source, key, data, closer_nodes } => {
                debug!("Kademlia => Received FIND_VALUE_RESULT from {}, data={:?}, #closer={}",
                    short_id(&source),
                    data.as_ref().map(|d| d.len()),
                    closer_nodes.len()
                );
                self.table.update_node(source, sender_addr, |nid, addr| {
                    self.do_ping(nid, addr)
                });
                if let Some(d) = data {
                    self.storage.cache_value(key, d);
                } else {
                    // wir könnten nun die closer_nodes weiter abfragen
                }
            }
        }
    }
}

fn short_id(id: &NodeId) -> String {
    format!("{}", hex::encode(&id.0[..2]))
}
