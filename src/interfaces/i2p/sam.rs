use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DEFAULT_SAM_ADDRESS: &str = "127.0.0.1:7656";
const READ_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
pub struct Destination {
    pub base64: String,
    pub base32: Option<String>,
    has_private_key: bool,
}

impl Destination {
    pub fn new(data: &str, has_private_key: bool) -> Self {
        Destination {
            base64: data.to_string(),
            base32: None,
            has_private_key,
        }
    }

    pub fn from_base64(base64: &str) -> Self {
        Self::new(base64, false)
    }

    pub fn from_private_key(private_key: &str) -> Self {
        Self::new(private_key, true)
    }
}

#[derive(Debug)]
pub struct SamMessage {
    pub parts: HashMap<String, String>,
}

impl SamMessage {
    pub fn parse(line: &str) -> Result<Self, String> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let mut map = HashMap::new();

        for part in parts {
            if let Some(pos) = part.find('=') {
                let key = part[..pos].to_string();
                let value = part[pos + 1..].to_string();
                map.insert(key, value);
            } else {
                map.insert(part.to_string(), "".to_string());
            }
        }

        Ok(SamMessage { parts: map })
    }

    pub fn is_ok(&self) -> bool {
        self.parts.get("RESULT").map(|s| s.as_str()) == Some("OK")
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.parts.get(key)
    }
}

pub struct SamConnection {
    stream: Arc<Mutex<Option<TcpStream>>>,
    sam_address: String,
}

impl SamConnection {
    pub fn new(sam_address: Option<&str>) -> Self {
        SamConnection {
            stream: Arc::new(Mutex::new(None)),
            sam_address: sam_address.unwrap_or(DEFAULT_SAM_ADDRESS).to_string(),
        }
    }

    fn connect(&self) -> io::Result<()> {
        let stream = TcpStream::connect(&self.sam_address)?;
        stream.set_read_timeout(Some(READ_TIMEOUT))?;
        stream.set_write_timeout(Some(READ_TIMEOUT))?;

        let mut guard = self.stream.lock().unwrap();
        *guard = Some(stream);
        Ok(())
    }

    fn send_command(&self, command: &str) -> io::Result<()> {
        let mut guard = self.stream.lock().unwrap();
        if let Some(ref mut stream) = *guard {
            stream.write_all(command.as_bytes())?;
            stream.flush()?;
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::NotConnected, "Not connected to SAM"))
        }
    }

    fn read_reply(&self) -> io::Result<SamMessage> {
        let guard = self.stream.lock().unwrap();
        if let Some(ref stream) = *guard {
            let mut reader = BufReader::new(stream.try_clone()?);
            let mut line = String::new();
            reader.read_line(&mut line)?;
            
            SamMessage::parse(&line.trim())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        } else {
            Err(io::Error::new(io::ErrorKind::NotConnected, "Not connected to SAM"))
        }
    }

    pub fn hello(&self) -> io::Result<bool> {
        self.connect()?;
        self.send_command("HELLO VERSION MIN=3.0 MAX=3.2\n")?;
        let reply = self.read_reply()?;
        Ok(reply.is_ok())
    }

    pub fn naming_lookup(&self, name: &str) -> io::Result<Destination> {
        if self.stream.lock().unwrap().is_none() {
            self.connect()?;
            self.hello()?;
        }

        let command = format!("NAMING LOOKUP NAME={}\n", name);
        self.send_command(&command)?;
        let reply = self.read_reply()?;

        if reply.is_ok() {
            if let Some(value) = reply.get("VALUE") {
                Ok(Destination::from_base64(value))
            } else {
                Err(io::Error::new(io::ErrorKind::InvalidData, "No VALUE in NAMING LOOKUP reply"))
            }
        } else {
            Err(io::Error::new(io::ErrorKind::Other, 
                format!("NAMING LOOKUP failed: {:?}", reply.get("RESULT"))))
        }
    }

    pub fn dest_generate(&self, sig_type: &str) -> io::Result<Destination> {
        if self.stream.lock().unwrap().is_none() {
            self.connect()?;
            self.hello()?;
        }

        let command = format!("DEST GENERATE SIGNATURE_TYPE={}\n", sig_type);
        self.send_command(&command)?;
        let reply = self.read_reply()?;

        if reply.is_ok() {
            if let Some(priv_key) = reply.get("PRIV") {
                Ok(Destination::from_private_key(priv_key))
            } else {
                Err(io::Error::new(io::ErrorKind::InvalidData, "No PRIV in DEST GENERATE reply"))
            }
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "DEST GENERATE failed"))
        }
    }

    pub fn session_create(
        &self,
        style: &str,
        session_id: &str,
        destination: Option<&Destination>,
        options: &HashMap<String, String>,
    ) -> io::Result<Destination> {
        if self.stream.lock().unwrap().is_none() {
            self.connect()?;
            self.hello()?;
        }

        let dest_string = if let Some(dest) = destination {
            if dest.has_private_key {
                &dest.base64
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Destination must have private key for session creation"
                ));
            }
        } else {
            "TRANSIENT"
        };

        let options_str: Vec<String> = options
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        let options_part = if options_str.is_empty() {
            String::new()
        } else {
            format!(" {}", options_str.join(" "))
        };

        let command = format!(
            "SESSION CREATE STYLE={} ID={} DESTINATION={}{}\n",
            style, session_id, dest_string, options_part
        );
        self.send_command(&command)?;
        let reply = self.read_reply()?;

        if reply.is_ok() {
            if let Some(dest_value) = reply.get("DESTINATION") {
                Ok(Destination::from_private_key(dest_value))
            } else if destination.is_some() {
                Ok(destination.unwrap().clone())
            } else {
                Err(io::Error::new(io::ErrorKind::InvalidData, "No DESTINATION in SESSION CREATE reply"))
            }
        } else {
            Err(io::Error::new(io::ErrorKind::Other, 
                format!("SESSION CREATE failed: {:?}", reply.get("RESULT"))))
        }
    }

    pub fn stream_connect(&self, session_id: &str, destination: &str) -> io::Result<TcpStream> {
        if self.stream.lock().unwrap().is_none() {
            self.connect()?;
            self.hello()?;
        }

        let command = format!(
            "STREAM CONNECT ID={} DESTINATION={} SILENT=false\n",
            session_id, destination
        );
        self.send_command(&command)?;
        let reply = self.read_reply()?;

        if reply.is_ok() {
            // Return the underlying TCP stream for data transfer
            let mut guard = self.stream.lock().unwrap();
            if let Some(stream) = guard.take() {
                Ok(stream)
            } else {
                Err(io::Error::new(io::ErrorKind::Other, "Stream was taken"))
            }
        } else {
            Err(io::Error::new(io::ErrorKind::Other, 
                format!("STREAM CONNECT failed: {:?}", reply.get("RESULT"))))
        }
    }

    pub fn stream_accept(&self, session_id: &str) -> io::Result<TcpStream> {
        if self.stream.lock().unwrap().is_none() {
            self.connect()?;
            self.hello()?;
        }

        let command = format!("STREAM ACCEPT ID={} SILENT=false\n", session_id);
        self.send_command(&command)?;
        let reply = self.read_reply()?;

        if reply.is_ok() {
            // Return the underlying TCP stream for data transfer
            let mut guard = self.stream.lock().unwrap();
            if let Some(stream) = guard.take() {
                Ok(stream)
            } else {
                Err(io::Error::new(io::ErrorKind::Other, "Stream was taken"))
            }
        } else {
            Err(io::Error::new(io::ErrorKind::Other, 
                format!("STREAM ACCEPT failed: {:?}", reply.get("RESULT"))))
        }
    }

    pub fn close(&self) {
        let mut guard = self.stream.lock().unwrap();
        if let Some(stream) = guard.take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

impl Drop for SamConnection {
    fn drop(&mut self) {
        self.close();
    }
}
