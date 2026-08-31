pub mod browser;
pub mod event_loop;
pub mod service;
pub mod txt_record;

use crate::{Result, ServiceType};
use std::str::FromStr;

pub(crate) fn format_service_type(service_type: &ServiceType) -> String {
    format!(
        "_{}._{}.local.",
        service_type.name(),
        service_type.protocol()
    )
}

pub(crate) fn parse_service_type(ty_domain: &str) -> Result<ServiceType> {
    let without_dot = ty_domain.trim_end_matches('.');
    let without_local = without_dot.strip_suffix(".local").unwrap_or(without_dot);
    ServiceType::from_str(without_local)
}

pub(crate) fn instance_name(fullname: &str, ty_domain: &str) -> String {
    fullname
        .strip_suffix(ty_domain)
        .unwrap_or(fullname)
        .trim_end_matches('.')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_type_round_trip() {
        let service_type = ServiceType::new("http", "tcp").unwrap();
        assert_eq!(format_service_type(&service_type), "_http._tcp.local.");
        assert_eq!(
            parse_service_type("_http._tcp.local.").unwrap(),
            service_type
        );
    }

    #[test]
    fn extracts_instance_name() {
        assert_eq!(
            instance_name(
                "My Phone._apple-mobdev2._tcp.local.",
                "_apple-mobdev2._tcp.local."
            ),
            "My Phone"
        );
    }
}
