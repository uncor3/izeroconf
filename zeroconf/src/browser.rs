//! Trait definition for cross-platform browser

use crate::event_loop::TEventLoop;
use crate::txt_record::TTxtRecord;
use crate::{NetworkInterface, Result, ServiceType};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Event from [`MdnsBrowser`] received by the `ServiceBrowserCallback`.
///
/// [`MdnsBrowser`]: type.MdnsBrowser.html
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserEvent {
    Add(ServiceDiscovery),
    Remove(ServiceRemoval),
}

/// Concrete discovery implementation used by an mDNS browser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryBackend {
    #[cfg(feature = "pure-rust")]
    PureRust,
    #[cfg(all(feature = "native-backend", target_os = "linux"))]
    Avahi,
    #[cfg(all(
        feature = "native-backend",
        any(target_vendor = "apple", target_vendor = "pc", target_os = "freebsd")
    ))]
    Bonjour,
}

/// Backend-neutral TXT data returned by service discovery.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiscoveryTxtRecord {
    entries: HashMap<String, String>,
}

impl From<HashMap<String, String>> for DiscoveryTxtRecord {
    fn from(entries: HashMap<String, String>) -> Self {
        Self { entries }
    }
}

impl TTxtRecord for DiscoveryTxtRecord {
    fn new() -> Self {
        Self::default()
    }
    fn insert(&mut self, key: &str, value: &str) -> Result<()> {
        self.entries.insert(key.to_string(), value.to_string());
        Ok(())
    }
    fn get(&self, key: &str) -> Option<String> {
        self.entries.get(key).cloned()
    }
    fn remove(&mut self, key: &str) -> Option<String> {
        self.entries.remove(key)
    }
    fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }
    fn len(&self) -> usize {
        self.entries.len()
    }
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = (String, String)> + 'a> {
        Box::new(
            self.entries
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        )
    }
    fn keys<'a>(&'a self) -> Box<dyn Iterator<Item = String> + 'a> {
        Box::new(self.entries.keys().cloned())
    }
    fn values<'a>(&'a self) -> Box<dyn Iterator<Item = String> + 'a> {
        Box::new(self.entries.values().cloned())
    }
}

/// Interface for interacting with underlying mDNS implementation service browsing capabilities.
pub trait TMdnsBrowser {
    type EventLoop: TEventLoop;

    fn backend() -> DiscoveryBackend
    where
        Self: Sized;

    /// Creates a new `MdnsBrowser` that browses for the specified `kind` (e.g. `_http._tcp`)
    fn new(service_type: ServiceType) -> Self;

    /// Sets the network interface on which to browse for services on.
    ///
    /// Most applications will want to use the default value `NetworkInterface::Unspec` to browse
    /// on all available interfaces.
    fn set_network_interface(&mut self, interface: NetworkInterface);

    /// Returns the network interface on which to browse for services on.
    fn network_interface(&self) -> NetworkInterface;

    /// Sets the [`ServiceBrowserCallback`] that is invoked when the browser has discovered and
    /// resolved or removed a service.
    ///
    /// [`ServiceBrowserCallback`]: ../type.ServiceBrowserCallback.html
    fn set_service_callback(&mut self, service_callback: Box<ServiceBrowserCallback>);

    /// Sets the optional user context to pass through to the callback. This is useful if you need
    /// to share state between pre and post-callback. The context type must implement `Any`.
    fn set_context(&mut self, context: Box<dyn Any + Send + Sync>);

    /// Returns the optional user context to pass through to the callback.
    fn context(&self) -> Option<&(dyn Any + Send + Sync)>;

    /// Starts the browser. Returns an `EventLoop` which can be called to keep the browser alive.
    fn browse_services(&mut self) -> Result<Self::EventLoop>;
}

/// Callback invoked from [`MdnsBrowser`] once a service has been discovered and resolved or
/// removed.
///
/// # Arguments
/// * `browser_event` - The event received from Zeroconf
/// * `context` - The optional user context passed through
///
/// [`MdnsBrowser`]: type.MdnsBrowser.html
pub type ServiceBrowserCallback =
    dyn Fn(Result<BrowserEvent>, Option<Arc<dyn Any + Send + Sync>>) + Send + Sync;

/// Optional metadata obtained from an Apple mobile device after DNS-SD resolution.
///
/// These values are read with unauthenticated lockdownd GetValue requests. They are
/// best-effort, untrusted local-network data and may be absent on any device.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Getters, Builder, BuilderDelegate, Clone, Default, PartialEq, Eq)]
pub struct DeviceDiscoveryMetadata {
    #[builder(default)]
    device_name: Option<String>,
    #[builder(default)]
    wifi_address: Option<String>,
    #[builder(default)]
    product_type: Option<String>,
    #[builder(default)]
    product_version: Option<String>,
    #[builder(default)]
    build_version: Option<String>,
}

#[cfg(feature = "apple-mobile-device-metadata")]
impl DeviceDiscoveryMetadata {
    pub(crate) fn is_empty(&self) -> bool {
        self.device_name.is_none()
            && self.wifi_address.is_none()
            && self.product_type.is_none()
            && self.product_version.is_none()
            && self.build_version.is_none()
    }
}

/// Controls optional post-DNS-SD metadata resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceMetadataResolution {
    /// Return DNS-SD data without opening any additional connections.
    Disabled,
    /// Resolve metadata for _apple-mobdev2._tcp services using sessionless lockdownd.
    AppleMobile { timeout: Duration },
}

impl Default for DeviceMetadataResolution {
    fn default() -> Self {
        Self::Disabled
    }
}

/// Represents a service that has been discovered by a [`MdnsBrowser`].
///
/// [`MdnsBrowser`]: type.MdnsBrowser.html
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Getters, Builder, BuilderDelegate, Clone, PartialEq, Eq)]
pub struct ServiceDiscovery {
    name: String,
    service_type: ServiceType,
    domain: String,
    host_name: String,
    address: String,
    port: u16,
    txt: Option<DiscoveryTxtRecord>,
    #[builder(default)]
    device_metadata: Option<DeviceDiscoveryMetadata>,
}

/// Represents a service that has been removed by a [`MdnsBrowser`].
///
/// [`MdnsBrowser`]: type.MdnsBrowser.html
#[derive(Debug, Getters, Builder, BuilderDelegate, Clone, PartialEq, Eq)]
pub struct ServiceRemoval {
    /// The "abc" part in "abc._http._udp.local"
    name: String,
    /// The "_http._udp" part in "abc._http._udp.local"
    kind: String,
    /// The "local" part in "abc._http._udp.local"
    domain: String,
}
