use crate::browser::{DeviceDiscoveryMetadata, DeviceMetadataResolution};
use crate::prelude::BuilderDelegate;
use plist::{Dictionary, Value};
use std::fmt;
use std::io::{Cursor, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Instant;

const MAX_PLIST_SIZE: usize = 1024 * 1024;
const MAX_VALUE_SIZE: usize = 4096;
const LOCKDOWND_PORT: u16 = 62078;

pub(crate) fn resolve_metadata(
    service_type: &crate::ServiceType,
    addresses: impl IntoIterator<Item = SocketAddr>,
    resolution: DeviceMetadataResolution,
) -> Option<DeviceDiscoveryMetadata> {
    let DeviceMetadataResolution::AppleMobile { timeout } = resolution else {
        return None;
    };
    if service_type.name() != "apple-mobdev2"
        || service_type.protocol() != "tcp"
        || timeout.is_zero()
    {
        return None;
    }

    let deadline = Instant::now() + timeout;
    let mut addresses = addresses.into_iter().collect::<Vec<_>>();
    addresses.sort_by_key(|address| !address.is_ipv4());

    for address in addresses {
        let address = lockdown_address(address);
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match TcpStream::connect_timeout(&address, remaining) {
            Ok(mut stream) => {
                if let Some(metadata) = resolve_from_stream(&mut stream, deadline) {
                    return Some(metadata);
                }
            }
            Err(error) => debug!(
                "lockdownd metadata connection to {} failed: {}",
                address, error
            ),
        }
    }
    None
}

fn lockdown_address(mut address: SocketAddr) -> SocketAddr {
    address.set_port(LOCKDOWND_PORT);
    address
}

fn resolve_from_stream(
    stream: &mut TcpStream,
    deadline: Instant,
) -> Option<DeviceDiscoveryMetadata> {
    let mut builder = DeviceDiscoveryMetadata::builder();

    read_value(stream, deadline, "DeviceName", |value| {
        builder.device_name(Some(value));
    });
    read_value(stream, deadline, "ProductType", |value| {
        builder.product_type(Some(value));
    });
    read_value(stream, deadline, "ProductVersion", |value| {
        builder.product_version(Some(value));
    });
    read_value(stream, deadline, "BuildVersion", |value| {
        builder.build_version(Some(value));
    });
    read_value(stream, deadline, "WiFiAddress", |value| {
        builder.wifi_address(Some(value));
    });

    let metadata = builder.build().ok()?;
    (!metadata.is_empty()).then_some(metadata)
}

fn read_value(
    stream: &mut TcpStream,
    deadline: Instant,
    key: &str,
    mut set_value: impl FnMut(String),
) {
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        return;
    };
    if remaining.is_zero() {
        return;
    }
    if let Err(error) = stream.set_read_timeout(Some(remaining)) {
        debug!("could not set lockdownd read timeout: {}", error);
        return;
    }
    if let Err(error) = stream.set_write_timeout(Some(remaining)) {
        debug!("could not set lockdownd write timeout: {}", error);
        return;
    }

    match get_lockdown_value(stream, key) {
        Ok(value) => set_value(value),
        Err(error) => debug!("lockdownd GetValue for {} failed: {}", key, error),
    }
}

fn get_lockdown_value(stream: &mut TcpStream, key: &str) -> LockdownResult<String> {
    let mut request = Dictionary::new();
    request.insert("Label".to_string(), Value::String("zeroconf".to_string()));
    request.insert("Request".to_string(), Value::String("GetValue".to_string()));
    request.insert("Key".to_string(), Value::String(key.to_string()));
    write_plist_frame(stream, &Value::Dictionary(request))?;

    let response = read_plist_frame(stream)?;
    let dictionary = response
        .as_dictionary()
        .ok_or(LockdownError::Protocol("response is not a dictionary"))?;
    if let Some(error) = dictionary.get("Error").and_then(Value::as_string) {
        return Err(LockdownError::Device(error.to_string()));
    }
    let value = dictionary
        .get("Value")
        .and_then(Value::as_string)
        .ok_or(LockdownError::Protocol("response has no string Value"))?;
    if value.len() > MAX_VALUE_SIZE {
        return Err(LockdownError::Protocol("response value is too large"));
    }
    Ok(value.to_string())
}

fn write_plist_frame(stream: &mut TcpStream, value: &Value) -> LockdownResult<()> {
    let mut payload = Vec::new();
    plist::to_writer_xml(&mut payload, value).map_err(LockdownError::Plist)?;
    if payload.len() > MAX_PLIST_SIZE {
        return Err(LockdownError::Protocol("request plist is too large"));
    }
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .map_err(LockdownError::Io)?;
    stream.write_all(&payload).map_err(LockdownError::Io)
}

fn read_plist_frame(stream: &mut TcpStream) -> LockdownResult<Value> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).map_err(LockdownError::Io)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_PLIST_SIZE {
        return Err(LockdownError::Protocol("invalid response plist length"));
    }
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload).map_err(LockdownError::Io)?;
    Value::from_reader(Cursor::new(payload)).map_err(LockdownError::Plist)
}

type LockdownResult<T> = std::result::Result<T, LockdownError>;

#[derive(Debug)]
enum LockdownError {
    Io(std::io::Error),
    Plist(plist::Error),
    Device(String),
    Protocol(&'static str),
}

impl fmt::Display for LockdownError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {}", error),
            Self::Plist(error) => write!(formatter, "plist error: {}", error),
            Self::Device(error) => write!(formatter, "device error: {}", error),
            Self::Protocol(error) => write!(formatter, "protocol error: {}", error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddrV6, TcpListener};
    use std::thread;

    #[test]
    fn get_value_uses_lockdown_framing() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_plist_frame(&mut stream).unwrap();
            let request = request.as_dictionary().unwrap();
            assert_eq!(
                request.get("Request").and_then(Value::as_string),
                Some("GetValue")
            );
            assert_eq!(
                request.get("Key").and_then(Value::as_string),
                Some("DeviceName")
            );

            let mut response = Dictionary::new();
            response.insert(
                "Value".to_string(),
                Value::String("Test iPhone".to_string()),
            );
            write_plist_frame(&mut stream, &Value::Dictionary(response)).unwrap();
        });

        let mut stream = TcpStream::connect(address).unwrap();
        assert_eq!(
            get_lockdown_value(&mut stream, "DeviceName").unwrap(),
            "Test iPhone"
        );
        server.join().unwrap();
    }

    #[test]
    fn rejects_oversized_frame_before_allocation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .write_all(&((MAX_PLIST_SIZE + 1) as u32).to_be_bytes())
                .unwrap();
        });

        let mut stream = TcpStream::connect(address).unwrap();
        assert!(matches!(
            read_plist_frame(&mut stream),
            Err(LockdownError::Protocol(_))
        ));
        server.join().unwrap();
    }

    #[test]
    fn metadata_connections_use_lockdownd_port() {
        let ipv4: SocketAddr = "192.0.2.1:32498".parse().unwrap();
        assert_eq!(lockdown_address(ipv4).port(), LOCKDOWND_PORT);

        let ipv6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 32498, 0, 7));
        let SocketAddr::V6(normalized) = lockdown_address(ipv6) else {
            unreachable!();
        };
        assert_eq!(normalized.port(), LOCKDOWND_PORT);
        assert_eq!(normalized.scope_id(), 7);
    }
}
