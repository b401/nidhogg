use chrono::NaiveTime;
use pnet::util::MacAddr;
use serde::Deserialize;
use snafu::ResultExt;
use std::net::Ipv4Addr;
use std::path::Path;

pub fn deserialize_naivetime<'de, D>(d: D) -> Result<NaiveTime, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    struct V;

    impl<'de2> serde::de::Visitor<'de2> for V {
        type Value = NaiveTime;

        fn expecting(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
            fmt.write_str("a naive time")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            NaiveTime::parse_from_str(v, "%H:%M")
                .map_err(|_| E::invalid_value(serde::de::Unexpected::Str(v), &self))
        }
    }

    d.deserialize_str(V)
}

#[derive(Debug, Deserialize)]
pub struct Period {
    #[serde(deserialize_with = "deserialize_naivetime")]
    start: NaiveTime,
    #[serde(deserialize_with = "deserialize_naivetime")]
    end: NaiveTime,
}

#[derive(Debug, Deserialize)]
struct ConfigDevice<'a> {
    hostname: Option<&'a str>,
    mac: MacAddr,
}

#[derive(Debug, Deserialize)]
struct ConfigData {
    interface: String,
    mac: Vec<MacAddr>,
    db: String,
}

#[derive(Debug)]
pub struct Interface {
    pub name: String,
    pub index: u32,
    pub addresses: NetworkAddresses,
}

#[derive(Debug)]
pub struct NetworkAddresses {
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
}

#[derive(Debug)]
pub struct Config {
    pub interface: Interface,
    pub mac: Vec<MacAddr>,
    pub db: String,
}

impl NetworkAddresses {
    pub fn new(mac: MacAddr, ip: Ipv4Addr) -> NetworkAddresses {
        NetworkAddresses { mac, ip }
    }
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> crate::Result<Config> {
        let path = path.as_ref();
        let config_content =
            std::fs::File::open(path).with_context(|| crate::error::ConfigNotFound {
                path: path.to_path_buf(),
            })?;
        let config_data: ConfigData = serde_yaml::from_reader(config_content)?;

        let interface = Interface::from_name(&config_data.interface)?;
        let mac = config_data.mac;
        let db = config_data.db;

        Ok(Config { interface, mac, db })
    }
}

impl Interface {
    fn from_name(name: &str) -> crate::Result<Interface> {
        let interface = match pnet::datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == name)
        {
            Some(interface) => interface,
            None => {
                return Err(crate::error::Error::UnknownInterface {
                    interface: name.into(),
                })
            }
        };
        let mac = match interface.mac {
            Some(mac) => mac,
            None => {
                return Err(crate::error::Error::BadInterface {
                    interface: interface.name,
                })
            }
        };
        let ip = match interface
            .ips
            .into_iter()
            .find(|ip| ip.is_ipv4())
            .map(|ip| ip.ip())
        {
            Some(std::net::IpAddr::V4(ip)) => ip,
            _ => {
                return Err(crate::error::Error::BadInterface {
                    interface: interface.name,
                })
            }
        };
        Ok(Interface {
            name: interface.name,
            index: interface.index,
            addresses: NetworkAddresses::new(mac, ip),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_naivetime(s: &str) -> NaiveTime {
        NaiveTime::parse_from_str(s, "%H:%M").unwrap()
    }

    #[test]
    fn test_period() {
        let now = to_naivetime("23:30");
        let period1 = Period {
            start: to_naivetime("23:00"),
            end: to_naivetime("06:00"),
        };
        let period2 = Period {
            start: to_naivetime("00:00"),
            end: to_naivetime("06:00"),
        };
        assert_eq!(period1.is_between(now), true);
        assert_eq!(period2.is_between(now), false);
    }
}
