use serde::{Deserialize, Serialize};
#[macro_use]
extern crate enum_derive;
#[macro_use]
extern crate custom_derive;
use chrono;
use config;
use lettre::smtp::{authentication, SmtpClient};
use lettre::Transport;
use lettre_email::EmailBuilder;
use log::{error, warn};
use scanner;
use splunk;
use std::thread;

custom_derive! {
    #[derive(EnumFromStr, Debug)]
    enum State {
        Up,
        Down,
        Critical,
        Unknown,
    }
}

custom_derive! {
    #[derive(EnumFromStr, Debug)]
    enum Sensor {
        Network,
        Ping,
        HTTP,
        Port,
        Load,
        Memory,
        Disk,
        Unknown,
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Prtg {
    pub host: String,
    pub sensor: String,
    pub state: String,
}

pub fn scan_once(config: std::sync::Arc<config::Portscan>) -> Vec<scanner::ScanResult> {
    use nmap_analyze::Mapping;
    use nmap_analyze::*;

    let mut rs = Vec::new();
    let mappings = Mapping::from_file(&config.mappings).expect("Failed to load mapping file");
    for i in &mappings.mappings {
        for x in &i.ips {
            match scanner::run(Some(&x.to_string()), &config) {
                Ok(scan) => {
                    if scan.is_some() {
                        rs.push(scan.unwrap())
                    }
                }
                Err(e) => eprintln!("{}", e),
            };
        }
    }
    rs
}

pub fn sensor_changed(
    info: &Prtg,
    splunk: Option<std::sync::Arc<config::Splunk>>,
    mail: std::sync::Arc<config::Mail>,
    scan: std::sync::Arc<config::Portscan>,
) {
    let sensor: Sensor = info.sensor.parse().unwrap_or(Sensor::Unknown);
    match sensor {
        // network
        Sensor::Network | Sensor::Ping | Sensor::HTTP Sensor::Port => {
            let mut msg = format!(
                "Host: {} changed sensor: {} to state: {}\nPlease investigate!\n\n",
                info.host, info.sensor, info.state
            );

            warn!("{}", msg);

            match scanner::run(Some(&info.host), &scan) {
                Ok(res) => {
                    msg = match res {
                        Some(scan_result) => format!("{}\n{}", msg, scan_result),
                        None => format!("{}", msg),
                    };
                    send_mail(mail, &msg, &format!("{}: {}", info.host, info.sensor)).unwrap();
                }
                Err(e) => println!("Error: {}", e),
            };
        }
        // Host
        Sensor::Disk | Sensor::Load | Sensor::Memory => {
            let msg = match splunk {
                Some(spl) => {
                    let mut rest = splunk::Rest::new(&spl.server, &spl.username, &spl.password);
                    match rest.check_sudo(&info.host) {
                        Some(splunk_result) => {
                            format!("\n\nLast Splunk messages:\n{}", splunk_result)
                        }
                        None => format!("\n\nLast Splunk messages:\n Host not found or no logs"),
                    }
                }
                None => String::new(),
            };

            warn!(
                "Host: {} , Sensor: {}, State: {}",
                info.host, info.state, info.sensor
            );
            send_mail(
                mail,
                &format!(
                    "Host: {} changed sensor: {} to state: {}\nPlease investigate!{}",
                    info.host, info.sensor, info.state, msg
                ),
                &format!("{}: {}", info.host, info.sensor),
            )
            .unwrap();
        }
        // Unknown
        Sensor::Unknown => {
            error!(
                "[Unknown] Host: {} , Sensor: {}, State: {}",
                info.host, info.state, info.sensor
            );
        }
    };
}

pub fn send_mail(
    mail: std::sync::Arc<config::Mail>,
    msg: &String,
    subject: &String,
) -> Result<(), lettre::smtp::error::Error> {
    // to remove
    let mail = mail.clone();
    let authentication =
        authentication::Credentials::new(mail.username.clone(), mail.password.clone());
    let email = EmailBuilder::new()
        .to(mail.email.clone())
        .from(mail.from.clone())
        .subject(&format!("[Nidhogg] {}", subject))
        .text(msg)
        .build()
        .unwrap();
    let mut client = SmtpClient::new_simple(&mail.server)?
        .credentials(authentication)
        .authentication_mechanism(authentication::Mechanism::Plain)
        .transport();
    client.send(email.into()).unwrap();
    Ok(())
}

pub fn current_time() -> String {
    use chrono::{DateTime, Utc};
    let now: DateTime<Utc> = Utc::now();
    format!("[{}]", now.format("%b %e %T"))
}

pub fn splunk_check(config: std::sync::Arc<config::Splunk>, mail: std::sync::Arc<config::Mail>) {
    let mut rest = splunk::Rest::new(&config.server, &config.username, &config.password);
    thread::spawn(move || loop {
        thread::sleep(std::time::Duration::from_secs(config.interval));
        match rest.check_sudo(&"*".to_owned()) {
            Some(msg) => {
                send_mail(
                    mail.clone(),
                    &format!("Splunk Messages:\n,{}", msg),
                    &format!("Automated Splunker"),
                )
                .unwrap();
            }
            None => (),
        };
    });
}

pub fn scan(config: std::sync::Arc<config::Portscan>, mail: std::sync::Arc<config::Mail>) {
    use nmap_analyze::Mapping;
    use nmap_analyze::*;

    let mappings = Mapping::from_file(&config.mappings).expect("Failed to load mapping file");
    thread::spawn(move || loop {
        let mut hosts: Vec<String> = Vec::new();
        for i in &mappings.mappings {
            for x in &i.ips {
                hosts.push(x.to_string())
            }
        }
        for host in hosts {
            match scanner::run(Some(&host), &config) {
                Ok(res) => {
                    match res {
                        Some(scan_result) => {
                            if mail.enable {
                                send_mail(
                                    mail.clone(),
                                    &format!("Time: {} {}", current_time(), scan_result),
                                    &format!(
                                        "[Nidhogg] Automated Scanner found anomaly in host {}",
                                        host
                                    ),
                                )
                                .unwrap();
                            }
                        }
                        None => (),
                    };
                }
                Err(e) => println!("Error: {}", e),
            };
        }
        thread::sleep(std::time::Duration::from_secs(config.timeout));
    });
}
