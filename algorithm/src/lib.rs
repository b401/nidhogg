use serde::{Deserialize, Serialize};
#[macro_use]
extern crate enum_derive;
#[macro_use]
extern crate custom_derive;
use log::{error, info, warn};
#[macro_use]
extern crate systemd;
use chrono;
use config;
use lettre::smtp::{authentication, ClientSecurity, SmtpClient};
use lettre::{SmtpTransport, Transport};
use lettre_email::EmailBuilder;
use scanner;
use splunk;
use std::{thread, time};
use systemd::journal;

// testing
use std::env;

custom_derive! {
    #[derive(EnumFromStr, Debug)]
    enum State {
        up,
        down,
        critical,
        unknown,
    }
}

custom_derive! {
    #[derive(EnumFromStr, Debug)]
    enum Sensor {
        network,
        ping,
        load,
        memory,
        disk,
        unknown,
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Prtg {
    pub host: String,
    pub sensor: String,
    pub state: String,
}

struct Config {
    email: String,
}

impl Config {
    fn new() -> Self {
        Config {
            email: "sec@i-401.xyz".to_owned(),
        }
    }
}

pub fn sensor_down(
    info: &Prtg,
    splunk: std::sync::Arc<config::Splunk>,
    mail: std::sync::Arc<config::Mail>,
) {
    let mut rest = splunk::Rest::new(&splunk.server, &splunk.username, &splunk.password);
    let sensor: Sensor = info.sensor.parse().unwrap_or(Sensor::unknown);
    match sensor {
        // network
        Sensor::network | Sensor::ping => {
            let mut msg = format!(
                "Host: {} changed sensor: {} to state: {}\nPlease investigate!\n\n",
                info.host, info.sensor, info.state
            );

            warn!("{}", msg);

            match scanner::run(Some(&info.host)) {
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
        Sensor::disk | Sensor::load | Sensor::memory => {
            let msg = match rest.check_sudo(&info.host) {
                Some(splunk_result) => format!("{}", splunk_result),
                None => format!("Host not found or no logs"),
            };
            warn!(
                "Host: {} , Sensor: {}, State: {}",
                info.host, info.state, info.sensor
            );
            send_mail(mail,&format!("Host: {} changed sensor: {} to state: {}\nPlease investigate!\n\nLast Splunk messages:\n{}",info.host,info.sensor,info.state,msg), &format!("{}: {}", info.host, info.sensor)).unwrap();
        }
        // Unknown
        Sensor::unknown => {
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
    client.send(email.into());
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

pub fn scan(config: config::Portscan, mail: std::sync::Arc<config::Mail>) {
    use nmap_analyze::Mapping;
    use nmap_analyze::*;

    thread::spawn(move || loop {
        thread::sleep(std::time::Duration::from_secs(config.timeout));
        let mappings = Mapping::from_file(&config.mappings).expect("Failed to load mapping file");

        let mut hosts: Vec<String> = Vec::new();
        for i in &mappings.mappings {
            for x in &i.ips {
                hosts.push(x.to_string())
            }
        }
        for host in hosts {
            match scanner::run(Some(&host)) {
                Ok(res) => {
                    match res {
                        Some(scan_result) => {
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
                        None => (),
                    };
                }
                Err(e) => println!("Error: {}", e),
            };
        }
    });
}
