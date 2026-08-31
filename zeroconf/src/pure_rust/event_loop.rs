use super::{instance_name, parse_service_type};
use crate::browser::{
    BrowserEvent, DeviceMetadataResolution, ServiceBrowserCallback, ServiceDiscovery,
    ServiceRemoval,
};
use crate::event_loop::TEventLoop;
use crate::prelude::BuilderDelegate;
use crate::{DiscoveryTxtRecord, Result};
#[cfg(feature = "apple-mobile-device-metadata")]
use mdns_sd::ScopedIp;
use mdns_sd::{Receiver, ResolvedService, ServiceDaemon, ServiceEvent};
use std::any::Any;
use std::collections::HashMap;
#[cfg(feature = "apple-mobile-device-metadata")]
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

enum EventLoopMode {
    Browser {
        receiver: Receiver<ServiceEvent>,
        callback: Box<ServiceBrowserCallback>,
        context: Option<Arc<dyn Any + Send + Sync>>,
        metadata_resolution: DeviceMetadataResolution,
    },
    Service,
}

pub struct PureRustEventLoop {
    daemon: ServiceDaemon,
    mode: EventLoopMode,
}

impl PureRustEventLoop {
    pub(crate) fn for_browser(
        daemon: ServiceDaemon,
        receiver: Receiver<ServiceEvent>,
        callback: Box<ServiceBrowserCallback>,
        context: Option<Arc<dyn Any + Send + Sync>>,
        metadata_resolution: DeviceMetadataResolution,
    ) -> Self {
        Self {
            daemon,
            mode: EventLoopMode::Browser {
                receiver,
                callback,
                context,
                metadata_resolution,
            },
        }
    }

    pub(crate) fn for_service(daemon: ServiceDaemon) -> Self {
        Self {
            daemon,
            mode: EventLoopMode::Service,
        }
    }
}

impl TEventLoop for PureRustEventLoop {
    fn poll(&self, timeout: Duration) -> Result<()> {
        let EventLoopMode::Browser {
            receiver,
            callback,
            context,
            metadata_resolution,
        } = &self.mode
        else {
            if !timeout.is_zero() {
                std::thread::sleep(timeout);
            }
            return Ok(());
        };

        let event = match receiver.recv_timeout(timeout) {
            Ok(event) => event,
            Err(mdns_sd::RecvTimeoutError::Timeout) => return Ok(()),
            Err(mdns_sd::RecvTimeoutError::Disconnected) => {
                return Err("mDNS event channel disconnected".into());
            }
        };

        let translated = match event {
            ServiceEvent::ServiceResolved(service) => {
                Some(resolve_service(&service, *metadata_resolution).map(BrowserEvent::Add))
            }
            ServiceEvent::ServiceRemoved(ty_domain, fullname) => {
                Some(remove_service(&ty_domain, &fullname).map(BrowserEvent::Remove))
            }
            _ => None,
        };

        if let Some(result) = translated {
            callback(result, context.clone());
        }
        Ok(())
    }
}

impl Drop for PureRustEventLoop {
    fn drop(&mut self) {
        if let Err(error) = self.daemon.shutdown() {
            debug!("failed to shut down pure-Rust mDNS daemon: {}", error);
        }
    }
}

fn resolve_service(
    service: &ResolvedService,
    metadata_resolution: DeviceMetadataResolution,
) -> Result<ServiceDiscovery> {
    let mut addresses = service.addresses.iter().collect::<Vec<_>>();
    addresses.sort_by_key(|address| (!address.is_ipv4(), address.to_ip_addr().to_string()));
    let address = addresses
        .first()
        .ok_or_else(|| crate::error::Error::from("resolved service has no address"))?
        .to_ip_addr()
        .to_string();

    let txt_map = service
        .txt_properties
        .iter()
        .map(|property| (property.key().to_string(), property.val_str().to_string()))
        .collect::<HashMap<_, _>>();
    let txt = if txt_map.is_empty() {
        None
    } else {
        Some(DiscoveryTxtRecord::from(txt_map))
    };

    #[cfg(feature = "apple-mobile-device-metadata")]
    let device_metadata = crate::apple_mobile::resolve_metadata(
        &parse_service_type(&service.ty_domain)?,
        service
            .addresses
            .iter()
            .filter_map(|address| to_socket_address(address, service.port)),
        metadata_resolution,
    );
    #[cfg(not(feature = "apple-mobile-device-metadata"))]
    let device_metadata = {
        let _ = metadata_resolution;
        None
    };

    ServiceDiscovery::builder()
        .name(instance_name(&service.fullname, &service.ty_domain))
        .service_type(parse_service_type(&service.ty_domain)?)
        .domain("local".to_string())
        .host_name(service.host.trim_end_matches('.').to_string())
        .address(address)
        .port(service.port)
        .txt(txt)
        .device_metadata(device_metadata)
        .build()
        .map_err(|error| error.to_string().into())
}

#[cfg(feature = "apple-mobile-device-metadata")]
fn to_socket_address(address: &ScopedIp, port: u16) -> Option<SocketAddr> {
    match address {
        ScopedIp::V4(ip) => Some(SocketAddr::new(IpAddr::V4(*ip.addr()), port)),
        ScopedIp::V6(ip) => Some(SocketAddr::V6(SocketAddrV6::new(
            *ip.addr(),
            port,
            0,
            ip.scope_id().index,
        ))),
        _ => None,
    }
}

fn remove_service(ty_domain: &str, fullname: &str) -> Result<ServiceRemoval> {
    let service_type = parse_service_type(ty_domain)?;
    ServiceRemoval::builder()
        .name(instance_name(fullname, ty_domain))
        .kind(format!(
            "_{}._{}",
            service_type.name(),
            service_type.protocol()
        ))
        .domain("local".to_string())
        .build()
        .map_err(|error| error.to_string().into())
}
