use serde::{Deserialize, Serialize};
#[macro_use]
extern crate enum_derive;
#[macro_use]
extern crate custom_derive;
use log::{error, warn};
use chrono;
use config;
use lettre::smtp::{authentication, SmtpClient};
use lettre::Transport;
use lettre_email::EmailBuilder;
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

pub fn sensor_down(
    info: &Prtg,
    splunk: Option<std::sync::Arc<config::Splunk>>,
    mail: Option<std::sync::Arc<config::Mail>>,
) {
    let sensor: Sensor = info.sensor.parse().unwrap_or(Sensor::Unknown);
    match sensor {
        // network
        Sensor::Network | Sensor::Ping => {
            let mut msg = format!(
                "Host: {} changed sensor: {} to state: {}\nPlease investigate!\n\n",
                info.host, info.sensor, info.state
            );

            warn!("{}", msg);

            match scanner::run(Some(&info.host)) {
                Ok(res) => {
                    msg = match res {
                        Some(scan_result) => format!("{}\n{}", msg, scan_result),
                        None => msg.to_string(),
                    };
                    if let Some(new_mail) = mail {
                        send_mail(new_mail, &msg, &format!("{}: {}", info.host, info.sensor)).unwrap();
                    };
                }
                Err(e) => println!("Error: {}", e),
            };
        }
        // Host
        Sensor::Disk | Sensor::Load | Sensor::Memory => {
            let msg = match splunk{
                Some(spl) => {
                    let mut rest = splunk::Rest::new(&spl.server, &spl.username, &spl.password);
                    match rest.check_sudo(&info.host) {
                        Some(splunk_result) => format!("\n\nLast Splunk messages:\n{}", splunk_result),
                        None => "\n\nLast Splunk messages:\n Host not found or no logs".to_string(),
                    }
                },
                None => String::new()
            };

            warn!(
                "Host: {} , Sensor: {}, State: {}",
                info.host, info.state, info.sensor
            );
            if let Some(new_mail) = mail {
                send_mail(new_mail,&format!("Host: {} changed sensor: {} to state: {}\nPlease investigate!{}",info.host,info.sensor,info.state,msg), &format!("{}: {}", info.host, info.sensor)).unwrap();
            };
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
    msg: &str,
    subject: &str,
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
    match client.send(email.into()) {
        Ok(_) => eprintln!("Sent mail"),
        Err(_) => println!("Could not send mail to endpoint")
    }
    Ok(())
}

pub fn current_time() -> String {
    use chrono::{DateTime, Utc};
    let now: DateTime<Utc> = Utc::now();
    format!("[{}]", now.format("%b %e %T"))
}

pub fn splunk_check(config: std::sync::Arc<config::Splunk>, mail: Option<std::sync::Arc<config::Mail>>) {
    let mut rest = splunk::Rest::new(&config.server, &config.username, &config.password);
    thread::spawn(move || loop {
        thread::sleep(std::time::Duration::from_secs(config.interval));
        let ret = rest.check_sudo(&"*".to_owned());
        if let Some(ret) = ret {
                if let Some(new_mail) = &mail {
                    send_mail(
                        new_mail.clone(),
                        &format!("Splunk Messages:\n,{}", ret),
                        &"Automated Splunker".to_string(),
                    )
                    .unwrap();
                };
        };
    });
}

pub fn scan(config: config::Portscan, mail: Option<std::sync::Arc<config::Mail>>) {
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
                    if let Some(scan_result) = res {
                        if let Some(new_mail) = &mail {
                                send_mail(
                                    new_mail.clone(),
                                    &format!("Time: {} {}", current_time(), scan_result),
                                    &format!(
                                        "[Nidhogg] Automated Scanner found anomaly in host {}",
                                        host
                                    ),
                                )
                                .unwrap();
                            };
                        };
                },
                Err(e) => println!("Error: {}", e),
            };
        }
    });
}
