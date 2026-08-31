use super::txt_record::PureRustTxtRecord;
use super::{event_loop::PureRustEventLoop, format_service_type};
use crate::prelude::BuilderDelegate;
use crate::service::{ServiceRegisteredCallback, ServiceRegistration, TMdnsService};
use crate::txt_record::TTxtRecord;
use crate::{NetworkInterface, Result, ServiceType};
use mdns_sd::{IfKind, ServiceDaemon, ServiceInfo};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

pub struct PureRustMdnsService {
    service_type: ServiceType,
    port: u16,
    name: Option<String>,
    interface: NetworkInterface,
    domain: Option<String>,
    host: Option<String>,
    txt_record: Option<PureRustTxtRecord>,
    registered_callback: Option<Box<ServiceRegisteredCallback>>,
    context: Option<Arc<dyn Any + Send + Sync>>,
}

impl TMdnsService for PureRustMdnsService {
    type EventLoop = PureRustEventLoop;
    type TxtRecord = PureRustTxtRecord;

    fn new(service_type: ServiceType, port: u16) -> Self {
        Self {
            service_type,
            port,
            name: None,
            interface: NetworkInterface::Unspec,
            domain: None,
            host: None,
            txt_record: None,
            registered_callback: None,
            context: None,
        }
    }

    fn set_name(&mut self, name: &str) {
        self.name = Some(name.to_string());
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn set_network_interface(&mut self, interface: NetworkInterface) {
        self.interface = interface;
    }

    fn network_interface(&self) -> NetworkInterface {
        self.interface
    }

    fn set_domain(&mut self, domain: &str) {
        self.domain = Some(domain.to_string());
    }

    fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    fn set_host(&mut self, host: &str) {
        self.host = Some(host.to_string());
    }

    fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    fn set_txt_record(&mut self, txt_record: Self::TxtRecord) {
        self.txt_record = Some(txt_record);
    }

    fn txt_record(&self) -> Option<&Self::TxtRecord> {
        self.txt_record.as_ref()
    }

    fn set_registered_callback(&mut self, registered_callback: Box<ServiceRegisteredCallback>) {
        self.registered_callback = Some(registered_callback);
    }

    fn set_context(&mut self, context: Box<dyn Any + Send + Sync>) {
        self.context = Some(Arc::from(context));
    }

    fn context(&self) -> Option<&(dyn Any + Send + Sync)> {
        self.context.as_deref()
    }

    fn register(&mut self) -> Result<Self::EventLoop> {
        let domain = self.domain.as_deref().unwrap_or("local").trim_matches('.');
        if !domain.eq_ignore_ascii_case("local") {
            return Err("the pure-Rust backend currently supports only the local domain".into());
        }

        let default_host = default_host();
        let host = normalize_host(self.host.as_deref().unwrap_or(&default_host));
        let name = self
            .name
            .clone()
            .unwrap_or_else(|| host.trim_end_matches(".local.").to_string());
        let properties = self
            .txt_record
            .as_ref()
            .map(TTxtRecord::to_map)
            .unwrap_or_else(HashMap::new);

        let mut info = ServiceInfo::new(
            &format_service_type(&self.service_type),
            &name,
            &host,
            "",
            self.port,
            properties,
        )
        .map_err(|error| error.to_string())?
        .enable_addr_auto();
        if let NetworkInterface::AtIndex(index) = self.interface {
            info.set_interfaces(vec![IfKind::IndexV4(index), IfKind::IndexV6(index)]);
        }

        let daemon = ServiceDaemon::new().map_err(|error| error.to_string())?;
        daemon.register(info).map_err(|error| error.to_string())?;

        if let Some(callback) = self.registered_callback.as_ref() {
            let registration = ServiceRegistration::builder()
                .name(name.clone())
                .service_type(self.service_type.clone())
                .domain("local".to_string())
                .build()
                .map_err(|error| error.to_string())?;
            callback(Ok(registration), self.context.clone());
        }
        self.name = Some(name);

        Ok(PureRustEventLoop::for_service(daemon))
    }
}

fn default_host() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "zeroconf".to_string())
}

fn normalize_host(host: &str) -> String {
    let host = host.trim_end_matches('.');
    if host.ends_with(".local") {
        format!("{}.", host)
    } else {
        format!("{}.local.", host)
    }
}
