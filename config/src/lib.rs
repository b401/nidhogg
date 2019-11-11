use chrono::NaiveTime;
use pnet::util::MacAddr;
use serde::Deserialize;
use snafu::ResultExt;
use std::net::Ipv4Addr;
use std::path::Path;

mod error;


#[derive(Debug, Deserialize)]
struct ConfigDevice<'a> {
    hostname: Option<&'a str>,
    mac: MacAddr,
}

#[derive(Debug, Deserialize)]
struct ConfigData {
    mail: Mail,
    splunk: Splunk,
    snmp: Snmp,
    portscan: Portscan,
    arpscan: Arpscan,
    webserver: Webserver,
}

#[derive(Deserialize, Debug)]
pub struct Splunk {
    pub enable: bool,
    pub server: String,
    pub username: String,
    pub password: String,
    pub interval: u64,
}

#[derive(Deserialize, Debug)]
pub struct Snmp {
    pub enable: bool,
    pub server: String,
    pub community: String,
    pub oid: String,
}

#[derive(Deserialize, Debug)]
pub struct Mail {
    pub enable: bool,
    pub server: String,
    pub username: String,
    pub password: String,
    pub email: String,
    pub from: String,
}

#[derive(Deserialize, Debug)]
pub struct Portscan {
    pub enable: bool,
    pub portspec: std::path::PathBuf,
    pub mappings: std::path::PathBuf,
    pub timeout: u64,
}

#[derive(Deserialize, Debug)]
pub struct Arpscan {
    pub enable: bool,
    pub interface: String,
    pub db: String,
    pub mac: Vec<MacAddr>,
    pub timeout: u64,
}

#[derive(Debug, Deserialize)]
pub struct Interface {
    pub name: String,
    pub index: u32,
    pub addresses: NetworkAddresses,
}

#[derive(Debug, Deserialize)]
pub struct NetworkAddresses {
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
}

#[derive(Debug, Deserialize)]
pub struct Webserver {
    pub enable: bool,
    pub address: Ipv4Addr,
    pub port: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug)]
pub struct Config {
    pub mail: Mail,
    pub splunk: Splunk,
    pub snmp: Snmp,
    pub portscan: Portscan,
    pub arpscan: Arpscan,
    pub interface: Interface,
    pub webserver: Webserver,
}

impl NetworkAddresses {
    pub fn new(mac: MacAddr, ip: Ipv4Addr) -> NetworkAddresses {
        NetworkAddresses { mac, ip }
    }
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> error::Result<Config> {
        let path = path.as_ref();
        let config_content = std::fs::File::open(path).with_context(|| error::ConfigNotFound {
            path: path.to_path_buf(),
        })?;
        let config_data: ConfigData = serde_yaml::from_reader(config_content)?;

        let mail = config_data.mail;
        let splunk = config_data.splunk;
        let snmp = config_data.snmp;
        let portscan = config_data.portscan;
        let interface = Interface::from_name(&config_data.arpscan.interface)?;
        let arpscan = config_data.arpscan;
        let webserver = config_data.webserver;

        Ok(Config {
            mail,
            splunk,
            snmp,
            portscan,
            arpscan,
            interface,
            webserver,
        })
    }
}

impl Interface {
    fn from_name(name: &str) -> error::Result<Interface> {
        let interface = match pnet::datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == name)
        {
            Some(interface) => interface,
            None => {
                return Err(error::Error::UnknownInterface {
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
