//! Bonjour implementation for cross-platform browser

use super::event_loop::BonjourEventLoop;
use super::service_ref::{
    BrowseServicesParams, GetAddressInfoParams, ManagedDNSServiceRef, ServiceResolveParams,
};
use super::txt_record::BonjourTxtRecord;
use super::txt_record_ref::ManagedTXTRecordRef;
use super::{bonjour_util, constants};
use crate::ffi::{AsRaw, FromRaw, c_str};
use crate::prelude::*;
use crate::{
    BrowserEvent, DeviceMetadataResolution, DiscoveryBackend, DiscoveryTxtRecord,
    ServiceBrowserCallback, ServiceDiscovery, ServiceRemoval,
};
use std::ffi::{c_char, c_uchar, c_void};
use crate::{NetworkInterface, Result, ServiceType};
#[cfg(target_vendor = "pc")]
use bonjour_sys::sockaddr_in;
use bonjour_sys::{DNSServiceErrorType, DNSServiceFlags, DNSServiceRef};

#[cfg(any(target_vendor = "apple", target_os = "freebsd"))]
use libc::{sockaddr_in, sockaddr_in6};
use std::any::Any;
use std::ffi::CString;
use std::fmt::{self, Formatter};
use std::net::IpAddr;
#[cfg(feature = "apple-mobile-device-metadata")]
use std::net::SocketAddr;
use std::ptr;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct BonjourMdnsBrowser {
    service: Arc<Mutex<ManagedDNSServiceRef>>,
    kind: CString,
    interface_index: u32,
    context: Box<BonjourBrowserContext>,
}

unsafe impl Send for BonjourMdnsBrowser {}
unsafe impl Sync for BonjourMdnsBrowser {}

impl BonjourMdnsBrowser {
    pub fn set_device_metadata_resolution(&mut self, resolution: DeviceMetadataResolution) {
        self.context.metadata_resolution = resolution;
    }

    pub fn device_metadata_resolution(&self) -> DeviceMetadataResolution {
        self.context.metadata_resolution
    }
}

impl TMdnsBrowser for BonjourMdnsBrowser {
    type EventLoop = BonjourEventLoop;

    fn backend() -> DiscoveryBackend {
        DiscoveryBackend::Bonjour
    }

    fn new(service_type: ServiceType) -> Self {
        Self {
            service: Arc::default(),
            kind: bonjour_util::format_regtype(&service_type),
            interface_index: constants::BONJOUR_IF_UNSPEC,
            context: Box::default(),
        }
    }

    fn set_network_interface(&mut self, interface: NetworkInterface) {
        self.interface_index = bonjour_util::interface_index(interface);
    }

    fn network_interface(&self) -> NetworkInterface {
        bonjour_util::interface_from_index(self.interface_index)
    }

    fn set_service_callback(&mut self, service_discovered_callback: Box<ServiceBrowserCallback>) {
        self.context.service_discovered_callback = Some(service_discovered_callback);
    }

    fn set_context(&mut self, context: Box<dyn Any + Send + Sync>) {
        self.context.user_context = Some(Arc::from(context));
    }

    fn context(&self) -> Option<&(dyn Any + Send + Sync)> {
        self.context.user_context.as_ref().map(|c| c.as_ref())
    }

    fn browse_services(&mut self) -> Result<Self::EventLoop> {
        info!("Using Bonjour backend for mDNS service browsing");
        debug!("Browsing services: {:?}", self);

        let mut service_lock = self
            .service
            .lock()
            .expect("should have been able to obtain lock on service ref");

        let browse_params = BrowseServicesParams::builder()
            .flags(0)
            .interface_index(self.interface_index)
            .regtype(self.kind.as_ptr())
            .domain(ptr::null_mut())
            .callback(Some(browse_callback))
            .context(self.context.as_raw())
            .build()?;

        unsafe { service_lock.browse_services(browse_params)? };

        Ok(BonjourEventLoop::new(self.service.clone()))
    }
}

#[derive(Default, FromRaw, AsRaw)]
struct BonjourBrowserContext {
    service_discovered_callback: Option<Box<ServiceBrowserCallback>>,
    resolved_name: Option<String>,
    resolved_kind: Option<String>,
    resolved_domain: Option<String>,
    resolved_port: u16,
    resolved_txt: Option<DiscoveryTxtRecord>,
    metadata_resolution: DeviceMetadataResolution,
    user_context: Option<Arc<dyn Any + Send + Sync>>,
}

impl BonjourBrowserContext {
    fn invoke_callback(&self, result: Result<BrowserEvent>) {
        if let Some(f) = &self.service_discovered_callback {
            f(result, self.user_context.clone());
        } else {
            warn!("attempted to invoke callback but none was set");
        }
    }
}

impl fmt::Debug for BonjourBrowserContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("BonjourResolverContext")
            .field("resolved_name", &self.resolved_name)
            .field("resolved_kind", &self.resolved_kind)
            .field("resolved_domain", &self.resolved_domain)
            .field("resolved_port", &self.resolved_port)
            .finish()
    }
}

unsafe impl Send for BonjourBrowserContext {}
unsafe impl Sync for BonjourBrowserContext {}

unsafe extern "system" fn browse_callback(
    _sd_ref: DNSServiceRef,
    flags: DNSServiceFlags,
    interface_index: u32,
    error: DNSServiceErrorType,
    name: *const c_char,
    regtype: *const c_char,
    domain: *const c_char,
    context: *mut c_void,
) {
    let ctx = unsafe { BonjourBrowserContext::from_raw(context) };

    if error != 0 {
        ctx.invoke_callback(Err(format!(
            "browse_callback() reported error (code: {})",
            error
        )
        .into()));
        return;
    }

    if flags & bonjour_sys::kDNSServiceFlagsAdd != 0 {
        if let Err(e) = unsafe { handle_browse_add(ctx, name, regtype, domain, interface_index) } {
            ctx.invoke_callback(Err(e));
        }
    } else {
        unsafe { handle_browse_remove(ctx, name, regtype, domain) };
    }
}

unsafe fn handle_browse_add(
    ctx: &mut BonjourBrowserContext,
    name: *const c_char,
    regtype: *const c_char,
    domain: *const c_char,
    interface_index: u32,
) -> Result<()> {
    ctx.resolved_name = Some(unsafe { c_str::copy_raw(name) });
    ctx.resolved_kind = Some(unsafe { c_str::copy_raw(regtype) });
    ctx.resolved_domain = Some(unsafe { c_str::copy_raw(domain) });

    unsafe {
        ManagedDNSServiceRef::default().resolve_service(
            ServiceResolveParams::builder()
                .flags(bonjour_sys::kDNSServiceFlagsForceMulticast)
                .interface_index(interface_index)
                .name(name)
                .regtype(regtype)
                .domain(domain)
                .callback(Some(resolve_callback))
                .context(ctx.as_raw())
                .build()?,
        )
    }
}

unsafe fn handle_browse_remove(
    ctx: &mut BonjourBrowserContext,
    name: *const c_char,
    regtype: *const c_char,
    domain: *const c_char,
) {
    let name = unsafe { c_str::raw_to_str(name) };
    let regtype = unsafe { c_str::raw_to_str(regtype) };
    let domain = unsafe { c_str::raw_to_str(domain) };

    // Remove the "." suffix to be consistent with the Avahi implementation.
    let regtype = regtype.strip_suffix(".").unwrap_or(domain);
    let domain = domain.strip_suffix(".").unwrap_or(domain);

    ctx.invoke_callback(Ok(BrowserEvent::Remove(
        ServiceRemoval::builder()
            .name(name.to_string())
            .kind(regtype.to_string())
            .domain(domain.to_string())
            .build()
            .expect("could not build ServiceRemoval"),
    )));
}

unsafe extern "system" fn resolve_callback(
    _sd_ref: DNSServiceRef,
    _flags: DNSServiceFlags,
    interface_index: u32,
    error: DNSServiceErrorType,
    _fullname: *const c_char,
    host_target: *const c_char,
    port: u16,
    txt_len: u16,
    txt_record: *const c_uchar,
    context: *mut c_void,
) {
    let ctx = unsafe { BonjourBrowserContext::from_raw(context) };

    let result = unsafe {
        handle_resolve(
            ctx,
            error,
            port,
            interface_index,
            host_target,
            txt_len,
            txt_record,
        )
    };

    if let Err(e) = result {
        ctx.invoke_callback(Err(e));
    }
}

unsafe fn handle_resolve(
    ctx: &mut BonjourBrowserContext,
    error: DNSServiceErrorType,
    port: u16,
    interface_index: u32,
    host_target: *const c_char,
    txt_len: u16,
    txt_record: *const c_uchar,
) -> Result<()> {
    if error != 0 {
        return Err(format!("error reported by resolve_callback: (code: {})", error).into());
    }

    ctx.resolved_port = port;

    ctx.resolved_txt = if txt_len > 1 {
        Some(DiscoveryTxtRecord::from(
            BonjourTxtRecord::from(unsafe { ManagedTXTRecordRef::clone_raw(txt_record, txt_len)? })
                .to_map(),
        ))
    } else {
        None
    };

    unsafe {
        ManagedDNSServiceRef::default().get_address_info(
            GetAddressInfoParams::builder()
                .flags(bonjour_sys::kDNSServiceFlagsForceMulticast)
                .interface_index(interface_index)
                .protocol(0)
                .hostname(host_target)
                .callback(Some(get_address_info_callback))
                .context(ctx.as_raw())
                .build()?,
        )
    }
}

unsafe extern "system" fn get_address_info_callback(
    _sd_ref: DNSServiceRef,
    _flags: DNSServiceFlags,
    interface_index: u32,
    error: DNSServiceErrorType,
    hostname: *const c_char,
    address: *const bonjour_sys::sockaddr,
    _ttl: u32,
    context: *mut c_void,
) {
    let ctx = unsafe { BonjourBrowserContext::from_raw(context) };
    if let Err(e) =
        unsafe { handle_get_address_info(ctx, error, interface_index, address, hostname) }
    {
        ctx.invoke_callback(Err(e));
    }
}

unsafe fn handle_get_address_info(
    ctx: &mut BonjourBrowserContext,
    error: DNSServiceErrorType,
    _interface_index: u32,
    address: *const bonjour_sys::sockaddr,
    hostname: *const c_char,
) -> Result<()> {
    // this callback runs multiple times for some reason
    if ctx.resolved_name.is_none() {
        return Ok(());
    }

    if error != 0 {
        return Err(format!(
            "get_address_info_callback() reported error (code: {})",
            error
        )
        .into());
    }

    // on macOS the bytes are swapped for the port
    let port: u16 = ctx.resolved_port.to_be();

    #[cfg(any(target_vendor = "apple", target_os = "freebsd"))]
    let ip = unsafe { ip_addr_from_sockaddr(address)? }.to_string();

    #[cfg(target_vendor = "pc")]
    let ip = {
        let address = address as *const sockaddr_in;
        assert_not_null!(address);
        let s_un = unsafe { (*address).sin_addr.S_un.S_un_b };
        let s_addr = [s_un.s_b1, s_un.s_b2, s_un.s_b3, s_un.s_b4];
        IpAddr::from(s_addr).to_string()
    };

    let hostname = unsafe { c_str::copy_raw(hostname) };

    let domain = bonjour_util::normalize_domain(
        &ctx.resolved_domain
            .take()
            .ok_or("could not get domain from BonjourBrowserContext")?,
    );

    let kind = bonjour_util::normalize_domain(
        &ctx.resolved_kind
            .take()
            .ok_or("could not get kind from BonjourBrowserContext")?,
    );

    let name = ctx
        .resolved_name
        .take()
        .ok_or("could not get name from BonjourBrowserContext")?;

    let service_type = bonjour_util::parse_regtype(&kind)?;
    #[cfg(feature = "apple-mobile-device-metadata")]
    let device_metadata = ip.parse::<IpAddr>().ok().and_then(|address| {
        let socket_address = match address {
            IpAddr::V4(address) => SocketAddr::new(IpAddr::V4(address), port),
            IpAddr::V6(address) => {
                std::net::SocketAddrV6::new(address, port, 0, _interface_index).into()
            }
        };
        crate::apple_mobile::resolve_metadata(
            &service_type,
            [socket_address],
            ctx.metadata_resolution,
        )
    });

    let mut builder = ServiceDiscovery::builder();
    builder
        .name(name)
        .service_type(service_type)
        .domain(domain)
        .host_name(hostname)
        .address(ip)
        .port(port)
        .txt(ctx.resolved_txt.take());
    #[cfg(feature = "apple-mobile-device-metadata")]
    builder.device_metadata(device_metadata);
    let result = builder.build().expect("could not build ServiceResolution");

    ctx.invoke_callback(Ok(BrowserEvent::Add(result)));

    Ok(())
}

#[cfg(any(target_vendor = "apple", target_os = "freebsd"))]
unsafe fn ip_addr_from_sockaddr(address: *const bonjour_sys::sockaddr) -> Result<IpAddr> {
    // DNSServiceGetAddrInfo can return either family. Reading an IPv6 sockaddr as
    // sockaddr_in produces an invalid IPv4 address (often 0.0.0.0 on macOS).
    let sockaddr = unsafe { (address as *const libc::sockaddr).as_ref() }
        .ok_or("DNSServiceGetAddrInfo returned a null address")?;
    match i32::from(sockaddr.sa_family) {
        libc::AF_INET => {
            let ipv4 = unsafe { &*(address as *const sockaddr_in) };
            Ok(IpAddr::from(ipv4.sin_addr.s_addr.to_ne_bytes()))
        }
        libc::AF_INET6 => {
            let ipv6 = unsafe { &*(address as *const sockaddr_in6) };
            Ok(IpAddr::from(ipv6.sin6_addr.s6_addr))
        }
        family => Err(format!("unsupported Bonjour address family: {family}").into()),
    }
}

#[cfg(all(test, target_vendor = "apple"))]
mod tests {
    use super::*;

    #[test]
    fn decodes_ipv4_sockaddr() {
        let mut address: sockaddr_in = unsafe { std::mem::zeroed() };
        address.sin_len = std::mem::size_of::<sockaddr_in>() as u8;
        address.sin_family = libc::AF_INET as u8;
        address.sin_addr.s_addr = u32::from_ne_bytes([192, 0, 2, 42]);

        let ip =
            unsafe { ip_addr_from_sockaddr(&address as *const _ as *const bonjour_sys::sockaddr) };
        assert_eq!(ip.unwrap().to_string(), "192.0.2.42");
    }

    #[test]
    fn decodes_ipv6_sockaddr_without_interpreting_it_as_ipv4() {
        let mut address: sockaddr_in6 = unsafe { std::mem::zeroed() };
        address.sin6_len = std::mem::size_of::<sockaddr_in6>() as u8;
        address.sin6_family = libc::AF_INET6 as u8;
        address.sin6_addr.s6_addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        let ip =
            unsafe { ip_addr_from_sockaddr(&address as *const _ as *const bonjour_sys::sockaddr) };
        assert_eq!(ip.unwrap().to_string(), "fe80::1");
    }

    #[test]
    fn rejects_null_and_unknown_address_families() {
        assert!(unsafe { ip_addr_from_sockaddr(std::ptr::null()) }.is_err());

        let mut address: sockaddr_in = unsafe { std::mem::zeroed() };
        address.sin_family = libc::AF_UNSPEC as u8;
        assert!(
            unsafe { ip_addr_from_sockaddr(&address as *const _ as *const bonjour_sys::sockaddr) }
                .is_err()
        );
    }
}
