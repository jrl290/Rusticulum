use crate::channel::{Channel, MessageBase, SystemMessageTypes};
use crate::{log, LOG_ERROR};
use bzip2::read::BzDecoder;
use bzip2::write::BzEncoder;
use bzip2::Compression;
use std::any::Any;
use std::io::{Read, Result as IoResult, Write};
use std::sync::{Arc, Mutex};
use std::thread;

pub struct StreamDataMessage {
	pub stream_id: u16,
	pub data: Vec<u8>,
	pub eof: bool,
	pub compressed: bool,
}

impl Default for StreamDataMessage {
	fn default() -> Self {
		StreamDataMessage {
			stream_id: 0,
			data: Vec::new(),
			eof: false,
			compressed: false,
		}
	}
}

impl StreamDataMessage {
	pub const STREAM_ID_MAX: u16 = 0x3fff;
	pub const OVERHEAD: usize = 2 + 6;
}

impl MessageBase for StreamDataMessage {
	fn msgtype(&self) -> u16 {
		SystemMessageTypes::StreamData as u16
	}

	fn pack(&self) -> Vec<u8> {
		let mut header_val = self.stream_id & Self::STREAM_ID_MAX;
		if self.eof {
			header_val |= 0x8000;
		}
		if self.compressed {
			header_val |= 0x4000;
		}
		let mut out = Vec::with_capacity(2 + self.data.len());
		out.extend_from_slice(&header_val.to_be_bytes());
		out.extend_from_slice(&self.data);
		out
	}

	fn unpack(&mut self, raw: &[u8]) {
		if raw.len() < 2 {
			return;
		}
		let header = u16::from_be_bytes([raw[0], raw[1]]);
		self.eof = (header & 0x8000) != 0;
		self.compressed = (header & 0x4000) != 0;
		self.stream_id = header & 0x3fff;
		self.data = raw[2..].to_vec();
		if self.compressed {
			if let Ok(decompressed) = decompress_bytes(&self.data) {
				self.data = decompressed;
			}
		}
	}

	fn as_any(&self) -> &dyn Any {
		self
	}

	fn as_any_mut(&mut self) -> &mut dyn Any {
		self
	}
}

#[allow(dead_code)]
pub struct RawChannelReader<O: crate::channel::ChannelOutletBase + 'static> {
	stream_id: u16,
	channel: Arc<Channel<O>>,
	buffer: Arc<Mutex<Vec<u8>>>,
	eof: Arc<Mutex<bool>>,
	listeners: Arc<Mutex<Vec<Arc<dyn Fn(usize) + Send + Sync>>>>,
}

impl<O: crate::channel::ChannelOutletBase + 'static> RawChannelReader<O> {
	pub fn new(stream_id: u16, channel: Arc<Channel<O>>) -> Self {
		let reader = RawChannelReader {
			stream_id,
			channel: channel.clone(),
			buffer: Arc::new(Mutex::new(Vec::new())),
			eof: Arc::new(Mutex::new(false)),
			listeners: Arc::new(Mutex::new(Vec::new())),
		};

		let _ = channel.register_message_type_system::<StreamDataMessage>();
		let buffer = reader.buffer.clone();
		let eof = reader.eof.clone();
		let listeners = reader.listeners.clone();
		channel.add_message_handler(Arc::new(move |message| {
			if let Some(stream_msg) = message.as_any().downcast_ref::<StreamDataMessage>() {
				if stream_msg.stream_id == stream_id {
					if !stream_msg.data.is_empty() {
						let mut buf = buffer.lock().unwrap();
						buf.extend_from_slice(&stream_msg.data);
					}
					if stream_msg.eof {
						let mut eof_flag = eof.lock().unwrap();
						*eof_flag = true;
					}
					let ready = buffer.lock().unwrap().len();
					for listener in listeners.lock().unwrap().iter() {
						let listener = listener.clone();
						thread::spawn(move || {
							listener(ready);
						});
					}
					return true;
				}
			}
			false
		}));

		reader
	}

	pub fn add_ready_callback(&self, cb: Arc<dyn Fn(usize) + Send + Sync>) {
		self.listeners.lock().unwrap().push(cb);
	}

	pub fn remove_ready_callback(&self, cb: &Arc<dyn Fn(usize) + Send + Sync>) {
		self.listeners
			.lock()
			.unwrap()
			.retain(|listener| !Arc::ptr_eq(listener, cb));
	}

	pub fn close(&self) {
		self.listeners.lock().unwrap().clear();
	}
}

impl<O: crate::channel::ChannelOutletBase + 'static> Read for RawChannelReader<O> {
	fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
		let mut buffer = self.buffer.lock().unwrap();
		if buffer.is_empty() {
			if *self.eof.lock().unwrap() {
				return Ok(0);
			}
			return Ok(0);
		}
		let to_read = buf.len().min(buffer.len());
		buf[..to_read].copy_from_slice(&buffer[..to_read]);
		buffer.drain(..to_read);
		Ok(to_read)
	}
}

pub struct RawChannelWriter<O: crate::channel::ChannelOutletBase + 'static> {
	stream_id: u16,
	channel: Arc<Channel<O>>,
	eof: bool,
	mdu: usize,
}

impl<O: crate::channel::ChannelOutletBase + 'static> RawChannelWriter<O> {
	pub const MAX_CHUNK_LEN: usize = 1024 * 16;
	pub const COMPRESSION_TRIES: usize = 4;

	pub fn new(stream_id: u16, channel: Arc<Channel<O>>) -> Self {
		let mdu = channel.mdu().saturating_sub(StreamDataMessage::OVERHEAD);
		RawChannelWriter {
			stream_id,
			channel,
			eof: false,
			mdu,
		}
	}

	pub fn close(&mut self) {
		self.eof = true;
		let _ = self.write(&[]);
	}
}

impl<O: crate::channel::ChannelOutletBase + 'static> Write for RawChannelWriter<O> {
	fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
		let chunk_len = buf.len().min(Self::MAX_CHUNK_LEN);
		let mut comp_try = 1usize;
		let mut comp_success = false;
		let mut processed_length = 0usize;
		let mut payload = Vec::new();

		while chunk_len > 32 && comp_try < Self::COMPRESSION_TRIES {
			let segment_len = chunk_len / comp_try;
			if let Ok(compressed) = compress_bytes(&buf[..segment_len]) {
				if compressed.len() < self.mdu && compressed.len() < segment_len {
					payload = compressed;
					processed_length = segment_len;
					comp_success = true;
					break;
				}
			}
			comp_try += 1;
		}

		if !comp_success {
			let capped = buf.len().min(self.mdu);
			payload = buf[..capped].to_vec();
			processed_length = capped;
		}

		let message = StreamDataMessage {
			stream_id: self.stream_id,
			data: payload,
			eof: self.eof,
			compressed: comp_success,
		};

		if let Err(err) = self.channel.send(Box::new(message)) {
			log(
				format!("RawChannelWriter send failed: {}", err),
				LOG_ERROR,
				false,
				false,
			);
			return Ok(0);
		}

		Ok(processed_length)
	}

	fn flush(&mut self) -> IoResult<()> {
		Ok(())
	}
}

pub struct Buffer;

impl Buffer {
	pub fn create_reader<O: crate::channel::ChannelOutletBase + 'static>(
		stream_id: u16,
		channel: Arc<Channel<O>>,
		ready_callback: Option<Arc<dyn Fn(usize) + Send + Sync>>,
	) -> RawChannelReader<O> {
		let reader = RawChannelReader::new(stream_id, channel);
		if let Some(cb) = ready_callback {
			reader.add_ready_callback(cb);
		}
		reader
	}

	pub fn create_writer<O: crate::channel::ChannelOutletBase + 'static>(
		stream_id: u16,
		channel: Arc<Channel<O>>,
	) -> RawChannelWriter<O> {
		RawChannelWriter::new(stream_id, channel)
	}

	/// Create a bidirectional buffer pair (reader + writer)
	/// 
	/// This returns a tuple of (reader, writer) for bidirectional communication
	pub fn create_bidirectional_buffer<O: crate::channel::ChannelOutletBase + 'static>(
		receive_stream_id: u16,
		send_stream_id: u16,
		channel: Arc<Channel<O>>,
		ready_callback: Option<Arc<dyn Fn(usize) + Send + Sync>>,
	) -> (RawChannelReader<O>, RawChannelWriter<O>) {
		let reader = RawChannelReader::new(receive_stream_id, channel.clone());
		if let Some(cb) = ready_callback {
			reader.add_ready_callback(cb);
		}
		let writer = RawChannelWriter::new(send_stream_id, channel);
		(reader, writer)
	}
}

fn compress_bytes(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
	let mut encoder = BzEncoder::new(Vec::new(), Compression::best());
	encoder.write_all(data)?;
	encoder.finish()
}

fn decompress_bytes(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
	let mut decoder = BzDecoder::new(data);
	let mut out = Vec::new();
	decoder.read_to_end(&mut out)?;
	Ok(out)
}
