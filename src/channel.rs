use crate::{log, LOG_ERROR, LOG_EXTREME};
use std::any::Any;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{atomic::{AtomicUsize, Ordering}, Arc, Mutex};

pub enum SystemMessageTypes {
    StreamData = 0xff00,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CEType {
    NoMsgType,
    InvalidMsgType,
    NotRegistered,
    LinkNotReady,
    AlreadySent,
    TooBig,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageState {
    New,
    Sent,
    Delivered,
    Failed,
}

#[derive(Debug)]
pub struct ChannelException {
    pub kind: CEType,
    pub message: String,
}

impl fmt::Display for ChannelException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for ChannelException {}

pub trait MessageBase: Send + Sync {
    fn msgtype(&self) -> u16;
    fn pack(&self) -> Vec<u8>;
    fn unpack(&mut self, data: &[u8]);
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

pub type MessageFactory = Arc<dyn Fn() -> Box<dyn MessageBase + Send + Sync> + Send + Sync>;
pub type MessageCallback = Arc<dyn Fn(&dyn MessageBase) -> bool + Send + Sync>;

pub trait ChannelOutletBase: Send + Sync {
    type Packet: Clone + Send + Sync;

    fn send(&self, data: &[u8]) -> Self::Packet;
    fn resend(&self, packet: &Self::Packet);
    fn set_packet_delivered_callback(
        &self,
        packet: &Self::Packet,
        callback: Option<Arc<dyn Fn(Self::Packet) + Send + Sync>>,
    );
    fn set_packet_timeout_callback(
        &self,
        packet: &Self::Packet,
        callback: Option<Arc<dyn Fn(Self::Packet) + Send + Sync>>,
        timeout: Option<f64>,
    );
    fn get_packet_state(&self, packet: &Self::Packet) -> MessageState;
    fn get_packet_id(&self, packet: &Self::Packet) -> Option<Vec<u8>>;
    fn rtt(&self) -> f64;
    fn mdu(&self) -> usize;
    fn is_usable(&self) -> bool;
    fn timed_out(&self);
}

pub struct Envelope<O: ChannelOutletBase> {
    pub ts: f64,
    pub id: usize,
    pub message: Option<Arc<Mutex<Box<dyn MessageBase + Send + Sync>>>>,
    pub raw: Vec<u8>,
    pub packet: Option<O::Packet>,
    pub sequence: u16,
    pub outlet: Arc<O>,
    pub tries: usize,
    pub unpacked: bool,
    pub packed: bool,
    pub tracked: bool,
}

impl<O: ChannelOutletBase> Envelope<O> {
    pub fn new(
        outlet: Arc<O>,
        message: Option<Box<dyn MessageBase + Send + Sync>>,
        raw: Option<Vec<u8>>,
        sequence: Option<u16>,
    ) -> Self {
        Envelope {
            ts: now_seconds(),
            id: rand_id(),
            message: message.map(|msg| Arc::new(Mutex::new(msg))),
            raw: raw.unwrap_or_default(),
            packet: None,
            sequence: sequence.unwrap_or(0),
            outlet,
            tries: 0,
            unpacked: false,
            packed: false,
            tracked: false,
        }
    }

    pub fn unpack(&mut self, factories: &HashMap<u16, MessageFactory>) -> Result<(), ChannelException> {
        if self.raw.len() < 6 {
            return Err(ChannelException {
                kind: CEType::InvalidMsgType,
                message: "Envelope raw too small".to_string(),
            });
        }
        let msgtype = u16::from_be_bytes([self.raw[0], self.raw[1]]);
        self.sequence = u16::from_be_bytes([self.raw[2], self.raw[3]]);
        let length = u16::from_be_bytes([self.raw[4], self.raw[5]]) as usize;
        let raw = &self.raw[6..];
        if raw.len() < length {
            return Err(ChannelException {
                kind: CEType::InvalidMsgType,
                message: "Envelope payload length mismatch".to_string(),
            });
        }
        let ctor = factories.get(&msgtype).ok_or_else(|| ChannelException {
            kind: CEType::NotRegistered,
            message: format!("Unable to find constructor for Channel MSGTYPE 0x{:04x}", msgtype),
        })?;
        let mut message = ctor();
        message.unpack(&raw[..length]);
        self.message = Some(Arc::new(Mutex::new(message)));
        self.unpacked = true;
        Ok(())
    }

    pub fn pack(&mut self) -> Result<&[u8], ChannelException> {
        let message = self.message.as_ref().ok_or_else(|| ChannelException {
            kind: CEType::NoMsgType,
            message: "Envelope has no message to pack".to_string(),
        })?;
        let guard = message.lock().unwrap();
        let msgtype = guard.msgtype();
        let data = guard.pack();
        if msgtype == 0 {
            return Err(ChannelException {
                kind: CEType::NoMsgType,
                message: "Message has invalid MSGTYPE".to_string(),
            });
        }
        let length = data.len() as u16;
        self.raw = Vec::with_capacity(6 + data.len());
        self.raw.extend_from_slice(&msgtype.to_be_bytes());
        self.raw.extend_from_slice(&self.sequence.to_be_bytes());
        self.raw.extend_from_slice(&length.to_be_bytes());
        self.raw.extend_from_slice(&data);
        self.packed = true;
        Ok(&self.raw)
    }
}

pub struct Channel<O: ChannelOutletBase> {
    outlet: Arc<O>,
    inner: Arc<Mutex<ChannelState<O>>>,
}

struct ChannelState<O: ChannelOutletBase> {
    tx_ring: VecDeque<Envelope<O>>,
    rx_ring: VecDeque<Envelope<O>>,
    message_callbacks: Vec<MessageCallback>,
    next_sequence: u16,
    next_rx_sequence: u16,
    message_factories: HashMap<u16, MessageFactory>,
    max_tries: usize,
    fast_rate_rounds: usize,
    medium_rate_rounds: usize,
    window: usize,
    window_max: usize,
    window_min: usize,
    window_flexibility: usize,
}

impl<O: ChannelOutletBase + 'static> Channel<O> {
    pub const WINDOW: usize = 2;
    pub const WINDOW_MIN: usize = 2;
    pub const WINDOW_MIN_LIMIT_SLOW: usize = 2;
    pub const WINDOW_MIN_LIMIT_MEDIUM: usize = 5;
    pub const WINDOW_MIN_LIMIT_FAST: usize = 16;
    pub const WINDOW_MAX_SLOW: usize = 5;
    pub const WINDOW_MAX_MEDIUM: usize = 12;
    pub const WINDOW_MAX_FAST: usize = 48;
    pub const WINDOW_MAX: usize = Self::WINDOW_MAX_FAST;
    pub const FAST_RATE_THRESHOLD: usize = 10;
    pub const RTT_FAST: f64 = 0.18;
    pub const RTT_MEDIUM: f64 = 0.75;
    pub const RTT_SLOW: f64 = 1.45;
    pub const WINDOW_FLEXIBILITY: usize = 4;
    pub const SEQ_MAX: u16 = 0xFFFF;
    pub const SEQ_MODULUS: u32 = Self::SEQ_MAX as u32 + 1;

    pub fn new(outlet: Arc<O>) -> Self {
        let (window, window_max, window_min, window_flexibility) = if outlet.rtt() > Self::RTT_SLOW {
            (1, 1, 1, 1)
        } else {
            (
                Self::WINDOW,
                Self::WINDOW_MAX_SLOW,
                Self::WINDOW_MIN,
                Self::WINDOW_FLEXIBILITY,
            )
        };
        Channel {
            outlet,
            inner: Arc::new(Mutex::new(ChannelState {
                tx_ring: VecDeque::new(),
                rx_ring: VecDeque::new(),
                message_callbacks: Vec::new(),
                next_sequence: 0,
                next_rx_sequence: 0,
                message_factories: HashMap::new(),
                max_tries: 5,
                fast_rate_rounds: 0,
                medium_rate_rounds: 0,
                window,
                window_max,
                window_min,
                window_flexibility,
            })),
        }
    }

    pub fn register_message_type<T>(&self) -> Result<(), ChannelException>
    where
        T: MessageBase + Default + Send + Sync + 'static,
    {
        self.register_message_type_internal::<T>(false)
    }

    pub fn register_message_type_system<T>(&self) -> Result<(), ChannelException>
    where
        T: MessageBase + Default + Send + Sync + 'static,
    {
        self.register_message_type_internal::<T>(true)
    }

    fn register_message_type_internal<T>(&self, is_system_type: bool) -> Result<(), ChannelException>
    where
        T: MessageBase + Default + Send + Sync + 'static,
    {
        let instance = T::default();
        let msgtype = instance.msgtype();
        if msgtype == 0 {
            return Err(ChannelException {
                kind: CEType::InvalidMsgType,
                message: "Message has invalid MSGTYPE class attribute".to_string(),
            });
        }
        if msgtype >= 0xF000 && !is_system_type {
            return Err(ChannelException {
                kind: CEType::InvalidMsgType,
                message: "Message has system-reserved message type".to_string(),
            });
        }

        let mut inner = self.inner.lock().unwrap();
        inner
            .message_factories
            .insert(msgtype, Arc::new(|| Box::new(T::default())));
        Ok(())
    }

    pub fn add_message_handler(&self, callback: MessageCallback) {
        let mut inner = self.inner.lock().unwrap();
        if !inner.message_callbacks.iter().any(|cb| Arc::ptr_eq(cb, &callback)) {
            inner.message_callbacks.push(callback);
        }
    }

    pub fn remove_message_handler(&self, callback: &MessageCallback) {
        let mut inner = self.inner.lock().unwrap();
        inner.message_callbacks.retain(|cb| !Arc::ptr_eq(cb, callback));
    }

    pub fn shutdown(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.message_callbacks.clear();
        for envelope in inner.tx_ring.iter() {
            if let Some(packet) = &envelope.packet {
                self.outlet.set_packet_timeout_callback(packet, None, None);
                self.outlet.set_packet_delivered_callback(packet, None);
            }
        }
        inner.tx_ring.clear();
        inner.rx_ring.clear();
    }

    pub fn is_ready_to_send(&self) -> bool {
        if !self.outlet.is_usable() {
            return false;
        }
        let inner = self.inner.lock().unwrap();
        let mut outstanding = 0usize;
        for envelope in inner.tx_ring.iter() {
            if envelope.packet.is_none()
                || self.outlet.get_packet_state(envelope.packet.as_ref().unwrap())
                    != MessageState::Delivered
            {
                outstanding += 1;
            }
        }
        outstanding < inner.window
    }

    pub fn send(&self, message: Box<dyn MessageBase + Send + Sync>) -> Result<Envelope<O>, ChannelException> {
        if !self.is_ready_to_send() {
            return Err(ChannelException {
                kind: CEType::LinkNotReady,
                message: "Link is not ready".to_string(),
            });
        }

        let mut envelope = Envelope::new(self.outlet.clone(), Some(message), None, None);
        let sequence = {
            let mut inner = self.inner.lock().unwrap();
            let sequence = inner.next_sequence;
            inner.next_sequence = ((inner.next_sequence as u32 + 1) % Self::SEQ_MODULUS) as u16;
            sequence
        };
        envelope.sequence = sequence;

        envelope.pack()?;
        if envelope.raw.len() > self.outlet.mdu() {
            return Err(ChannelException {
                kind: CEType::TooBig,
                message: format!(
                    "Packed message too big for packet: {} > {}",
                    envelope.raw.len(),
                    self.outlet.mdu()
                ),
            });
        }

        let packet = self.outlet.send(&envelope.raw);
        envelope.packet = Some(packet.clone());
        envelope.tries += 1;

        {
            let mut inner = self.inner.lock().unwrap();
            let next_rx_sequence = inner.next_rx_sequence;
            self.emplace_envelope(&mut envelope, &mut inner.tx_ring, next_rx_sequence)?;
        }

        let delivered_cb = {
            let channel = self.clone();
            Arc::new(move |pkt: O::Packet| {
                channel.packet_delivered(pkt);
            })
        };
        let timeout_cb = {
            let channel = self.clone();
            Arc::new(move |pkt: O::Packet| {
                channel.packet_timeout(pkt);
            })
        };
        self.outlet
            .set_packet_delivered_callback(envelope.packet.as_ref().unwrap(), Some(delivered_cb));
        self.outlet.set_packet_timeout_callback(
            envelope.packet.as_ref().unwrap(),
            Some(timeout_cb),
            Some(self.get_packet_timeout_time(envelope.tries)),
        );
        self.update_packet_timeouts();

        Ok(envelope)
    }

    pub fn receive(&self, raw: &[u8]) {
        let mut envelope = Envelope::new(self.outlet.clone(), None, Some(raw.to_vec()), None);
        let contig = {
            let mut inner = self.inner.lock().unwrap();
            let factories = inner.message_factories.clone();
            if envelope.unpack(&factories).is_err() {
                log(
                    "Channel message could not be unpacked".to_string(),
                    LOG_ERROR,
                    false,
                    false,
                );
                return;
            }

            if envelope.sequence < inner.next_rx_sequence {
                let window_overflow = (inner.next_rx_sequence as u32 + Self::WINDOW_MAX as u32)
                    % Self::SEQ_MODULUS;
                if window_overflow < inner.next_rx_sequence as u32 {
                    if envelope.sequence as u32 > window_overflow {
                        log(
                            format!(
                                "Invalid packet sequence ({}) received on channel",
                                envelope.sequence
                            ),
                            LOG_EXTREME,
                            false,
                            false,
                        );
                        return;
                    }
                } else {
                    log(
                        format!(
                            "Invalid packet sequence ({}) received on channel",
                            envelope.sequence
                        ),
                        LOG_EXTREME,
                        false,
                        false,
                    );
                    return;
                }
            }

            let next_rx_sequence = inner.next_rx_sequence;
            let is_new = self
                .emplace_envelope(&mut envelope, &mut inner.rx_ring, next_rx_sequence)
                .unwrap_or(false);
            if !is_new {
                log("Duplicate message received on channel", LOG_EXTREME, false, false);
                return;
            }

            let mut contiguous = Vec::new();
            loop {
                let mut found = None;
                for (idx, env) in inner.rx_ring.iter().enumerate() {
                    if env.sequence == inner.next_rx_sequence {
                        found = Some(idx);
                        break;
                    }
                }
                if let Some(idx) = found {
                    let mut env = inner.rx_ring.remove(idx).unwrap();
                    if !env.unpacked {
                        let _ = env.unpack(&factories);
                    }
                    contiguous.push(env);
                    inner.next_rx_sequence =
                        ((inner.next_rx_sequence as u32 + 1) % Self::SEQ_MODULUS) as u16;
                    if inner.next_rx_sequence == 0 {
                        continue;
                    }
                } else {
                    break;
                }
            }

            contiguous
        };

        let callbacks = { self.inner.lock().unwrap().message_callbacks.clone() };
        for env in contig {
            if let Some(msg) = env.message.as_ref() {
                let guard = msg.lock().unwrap();
                for cb in callbacks.iter() {
                    if cb(guard.as_ref()) {
                        break;
                    }
                }
            }
        }
    }

    pub fn mdu(&self) -> usize {
        let mut mdu = self.outlet.mdu().saturating_sub(6);
        if mdu > 0xFFFF {
            mdu = 0xFFFF;
        }
        mdu
    }

    fn emplace_envelope(
        &self,
        envelope: &mut Envelope<O>,
        ring: &mut VecDeque<Envelope<O>>,
        next_rx_sequence: u16,
    ) -> Result<bool, ChannelException> {
        let mut i = 0usize;
        for existing in ring.iter() {
            if envelope.sequence == existing.sequence {
                log(
                    format!("Envelope: Emplacement of duplicate envelope with sequence {}", envelope.sequence),
                    LOG_EXTREME,
                    false,
                    false,
                );
                return Ok(false);
            }

            if envelope.sequence < existing.sequence
                && !(self.seq_distance(next_rx_sequence, envelope.sequence) > (Self::SEQ_MAX as u32 / 2))
            {
                ring.insert(i, envelope_shallow_clone(envelope));
                envelope.tracked = true;
                return Ok(true);
            }

            i += 1;
        }

        envelope.tracked = true;
        ring.push_back(envelope_shallow_clone(envelope));
        Ok(true)
    }

    fn seq_distance(&self, from: u16, to: u16) -> u32 {
        if from >= to {
            (from - to) as u32
        } else {
            (from as u32 + Self::SEQ_MODULUS - to as u32) as u32
        }
    }

    fn packet_delivered(&self, packet: O::Packet) {
        self.packet_tx_op(&packet, |_| true);
    }

    fn packet_timeout(&self, packet: O::Packet) {
        let max_tries = { self.inner.lock().unwrap().max_tries };
        let outlet = self.outlet.clone();
        self.packet_tx_op(&packet, |envelope| {
            if envelope.tries >= max_tries {
                log("Retry count exceeded on channel, tearing down Link.", LOG_ERROR, false, false);
                self.shutdown();
                outlet.timed_out();
                return true;
            }

            envelope.tries += 1;
            outlet.resend(envelope.packet.as_ref().unwrap());

            let delivered_cb = {
                let channel = self.clone();
                Arc::new(move |pkt: O::Packet| {
                    channel.packet_delivered(pkt);
                })
            };
            let timeout_cb = {
                let channel = self.clone();
                Arc::new(move |pkt: O::Packet| {
                    channel.packet_timeout(pkt);
                })
            };
            outlet.set_packet_delivered_callback(envelope.packet.as_ref().unwrap(), Some(delivered_cb));
            outlet.set_packet_timeout_callback(
                envelope.packet.as_ref().unwrap(),
                Some(timeout_cb),
                Some(self.get_packet_timeout_time(envelope.tries)),
            );
            self.update_packet_timeouts();

            let mut inner = self.inner.lock().unwrap();
            if inner.window > inner.window_min {
                inner.window -= 1;
                if inner.window_max > (inner.window_min + inner.window_flexibility) {
                    inner.window_max -= 1;
                }
            }

            false
        });
    }

    fn packet_tx_op<F>(&self, packet: &O::Packet, mut op: F)
    where
        F: FnMut(&mut Envelope<O>) -> bool,
    {
        let mut inner = self.inner.lock().unwrap();
        let packet_id = self.outlet.get_packet_id(packet);
        let mut found_idx = None;
        for (idx, env) in inner.tx_ring.iter().enumerate() {
            if let (Some(env_id), Some(pkt_id)) = (env.packet.as_ref().and_then(|p| self.outlet.get_packet_id(p)), packet_id.clone()) {
                if env_id == pkt_id {
                    found_idx = Some(idx);
                    break;
                }
            }
        }

        if let Some(idx) = found_idx {
            let mut env = inner.tx_ring.remove(idx).unwrap();
            let remove = op(&mut env);
            if remove {
                if inner.window < inner.window_max {
                    inner.window += 1;
                    if self.outlet.rtt() != 0.0 {
                        if self.outlet.rtt() > Self::RTT_FAST {
                            inner.fast_rate_rounds = 0;
                            if self.outlet.rtt() > Self::RTT_MEDIUM {
                                inner.medium_rate_rounds = 0;
                            } else {
                                inner.medium_rate_rounds += 1;
                                if inner.window_max < Self::WINDOW_MAX_MEDIUM
                                    && inner.medium_rate_rounds == Self::FAST_RATE_THRESHOLD
                                {
                                    inner.window_max = Self::WINDOW_MAX_MEDIUM;
                                    inner.window_min = Self::WINDOW_MIN_LIMIT_MEDIUM;
                                }
                            }
                        } else {
                            inner.fast_rate_rounds += 1;
                            if inner.window_max < Self::WINDOW_MAX_FAST
                                && inner.fast_rate_rounds == Self::FAST_RATE_THRESHOLD
                            {
                                inner.window_max = Self::WINDOW_MAX_FAST;
                                inner.window_min = Self::WINDOW_MIN_LIMIT_FAST;
                            }
                        }
                    }
                }
            } else {
                inner.tx_ring.push_back(env);
            }
        } else {
            log("Spurious message received on channel", LOG_EXTREME, false, false);
        }
    }

    fn update_packet_timeouts(&self) {
        let inner = self.inner.lock().unwrap();
        for envelope in inner.tx_ring.iter() {
            let updated_timeout = self.get_packet_timeout_time(envelope.tries);
            if let Some(packet) = &envelope.packet {
                self.outlet
                    .set_packet_timeout_callback(packet, None, Some(updated_timeout));
            }
        }
    }

    fn get_packet_timeout_time(&self, tries: usize) -> f64 {
        let tries = tries.max(1) as i32;
        let base = self.outlet.rtt().max(0.0) * 2.5;
        let to = 1.5_f64.powi(tries - 1) * base.max(0.025) * (self.inner.lock().unwrap().tx_ring.len() as f64 + 1.5);
        to
    }
}

impl<O: ChannelOutletBase> Clone for Channel<O> {
    fn clone(&self) -> Self {
        Channel {
            outlet: self.outlet.clone(),
            inner: self.inner.clone(),
        }
    }
}

fn now_seconds() -> f64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    now.as_secs() as f64 + (now.subsec_nanos() as f64 / 1_000_000_000.0)
}

static ENVELOPE_ID: AtomicUsize = AtomicUsize::new(1);

fn rand_id() -> usize {
    ENVELOPE_ID.fetch_add(1, Ordering::Relaxed)
}

fn envelope_shallow_clone<O: ChannelOutletBase>(env: &Envelope<O>) -> Envelope<O> {
    Envelope {
        ts: env.ts,
        id: env.id,
        message: env.message.clone(),
        raw: env.raw.clone(),
        packet: env.packet.clone(),
        sequence: env.sequence,
        outlet: env.outlet.clone(),
        tries: env.tries,
        unpacked: env.unpacked,
        packed: env.packed,
        tracked: env.tracked,
    }
}
