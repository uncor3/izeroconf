use crate::browser::{DeviceDiscoveryMetadata, DeviceMetadataResolution};
use crate::prelude::BuilderDelegate;
use plist::{Dictionary, Value};
use std::fmt;
use std::io::{Cursor, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Instant;

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
    let values = match get_lockdown_values(stream, deadline) {
        Ok(values) => values,
        Err(error) => {
            debug!("lockdownd GetValue failed: {}", error);
            return None;
        }
    };

    let value = |key: &str| {
        values
            .get(key)
            .and_then(Value::as_string)
            .map(ToOwned::to_owned)
    };

    let mut builder = DeviceDiscoveryMetadata::builder();
    builder
        .device_name(value("DeviceName"))
        .product_type(value("ProductType"))
        .product_version(value("ProductVersion"))
        .build_version(value("BuildVersion"))
        .wifi_address(value("WiFiAddress"));

    let metadata = builder.build().ok()?;
    (!metadata.is_empty()).then_some(metadata)
}

fn get_lockdown_values(stream: &mut TcpStream, deadline: Instant) -> LockdownResult<Dictionary> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(LockdownError::Protocol("metadata resolution timed out"))?;
    if remaining.is_zero() {
        return Err(LockdownError::Protocol("metadata resolution timed out"));
    }
    stream
        .set_read_timeout(Some(remaining))
        .map_err(LockdownError::Io)?;
    stream
        .set_write_timeout(Some(remaining))
        .map_err(LockdownError::Io)?;

    let mut request = Dictionary::new();
    request.insert("Label".to_string(), Value::String("izeroconf".to_string()));
    request.insert("Request".to_string(), Value::String("GetValue".to_string()));
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
        .and_then(Value::as_dictionary)
        .ok_or(LockdownError::Protocol(
            "response Value is not a dictionary",
        ))?;
    Ok(value.clone())
}

fn write_plist_frame(stream: &mut TcpStream, value: &Value) -> LockdownResult<()> {
    let mut payload = Vec::new();
    plist::to_writer_xml(&mut payload, value).map_err(LockdownError::Plist)?;
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .map_err(LockdownError::Io)?;
    stream.write_all(&payload).map_err(LockdownError::Io)
}

fn read_plist_frame(stream: &mut TcpStream) -> LockdownResult<Value> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).map_err(LockdownError::Io)?;
    let length = u32::from_be_bytes(length) as usize;
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
    fn get_values_uses_keyless_lockdown_request() {
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
            assert!(!request.contains_key("Key"));
            assert!(!request.contains_key("Domain"));

            let mut values = Dictionary::new();
            values.insert(
                "DeviceName".to_string(),
                Value::String("Test iPhone".to_string()),
            );
            let mut response = Dictionary::new();
            response.insert("Value".to_string(), Value::Dictionary(values));
            write_plist_frame(&mut stream, &Value::Dictionary(response)).unwrap();
        });

        let mut stream = TcpStream::connect(address).unwrap();
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        let values = get_lockdown_values(&mut stream, deadline).unwrap();
        assert_eq!(
            values.get("DeviceName").and_then(Value::as_string),
            Some("Test iPhone")
        );
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
