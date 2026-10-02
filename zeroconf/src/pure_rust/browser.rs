use super::{event_loop::PureRustEventLoop, format_service_type};
use crate::browser::{
    DeviceMetadataResolution, DiscoveryBackend, ServiceBrowserCallback, TMdnsBrowser,
};
use crate::{NetworkInterface, Result, ServiceType};
use mdns_sd::{IfKind, ServiceDaemon};
use std::any::Any;
use std::fmt;
use std::sync::Arc;
use std::ffi::c_char;


pub struct PureRustMdnsBrowser {
    service_type: ServiceType,
    interface: NetworkInterface,
    service_callback: Option<Box<ServiceBrowserCallback>>,
    context: Option<Arc<dyn Any + Send + Sync>>,
    metadata_resolution: DeviceMetadataResolution,
}

impl fmt::Debug for PureRustMdnsBrowser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PureRustMdnsBrowser")
            .field("service_type", &self.service_type)
            .field("interface", &self.interface)
            .field("metadata_resolution", &self.metadata_resolution)
            .finish_non_exhaustive()
    }
}

impl PureRustMdnsBrowser {
    pub fn set_device_metadata_resolution(&mut self, resolution: DeviceMetadataResolution) {
        self.metadata_resolution = resolution;
    }

    pub fn device_metadata_resolution(&self) -> DeviceMetadataResolution {
        self.metadata_resolution
    }
}

impl TMdnsBrowser for PureRustMdnsBrowser {
    type EventLoop = PureRustEventLoop;

    fn backend() -> DiscoveryBackend {
        DiscoveryBackend::PureRust
    }

    fn new(service_type: ServiceType) -> Self {
        Self {
            service_type,
            interface: NetworkInterface::Unspec,
            service_callback: None,
            context: None,
            metadata_resolution: DeviceMetadataResolution::Disabled,
        }
    }

    fn set_network_interface(&mut self, interface: NetworkInterface) {
        self.interface = interface;
    }

    fn network_interface(&self) -> NetworkInterface {
        self.interface
    }

    fn set_service_callback(&mut self, service_callback: Box<ServiceBrowserCallback>) {
        self.service_callback = Some(service_callback);
    }

    fn set_context(&mut self, context: Box<dyn Any + Send + Sync>) {
        self.context = Some(Arc::from(context));
    }

    fn context(&self) -> Option<&(dyn Any + Send + Sync)> {
        self.context.as_deref()
    }

    fn browse_services(&mut self) -> Result<Self::EventLoop> {
        info!("Using pure-Rust backend for mDNS service browsing");
        let daemon = ServiceDaemon::new().map_err(|error| error.to_string())?;
        if let NetworkInterface::AtIndex(index) = self.interface {
            daemon
                .disable_interface(IfKind::All)
                .map_err(|error| error.to_string())?;
            daemon
                .enable_interface(IfKind::IndexV4(index))
                .map_err(|error| error.to_string())?;
            daemon
                .enable_interface(IfKind::IndexV6(index))
                .map_err(|error| error.to_string())?;
        }

        let receiver = daemon
            .browse(&format_service_type(&self.service_type))
            .map_err(|error| error.to_string())?;
        let callback = self
            .service_callback
            .take()
            .ok_or_else(|| crate::error::Error::from("service callback is required"))?;

        Ok(PureRustEventLoop::for_browser(
            daemon,
            receiver,
            callback,
            self.context.clone(),
            self.metadata_resolution,
        ))
    }
}
