use algorithm;
use arp_det;
use config;
use std::sync::Arc;
use std::thread;
use std::process::exit;
use web;

fn main() {
    let settings = match config::Config::from_file("/etc/nidhogg/config.yml") {
        Ok(setting) => setting,
        Err(_) => {
            eprintln!("config.yml not found");
            exit(1);
        }
    };
    let mail = if settings.mail.enable {
        Some(Arc::new(settings.mail))
    } else {
        None
    };

    if settings.arpscan.enable {
    // Start arp scanner
        {
            let arpscan = settings.arpscan;
            let interface = settings.interface;
            let new_mail = mail.clone();
            thread::spawn(move || {
                match arp_det::run((&arpscan, &interface), new_mail) {
                    Ok(_) => (),
                    Err(e) => eprintln!("{}", e),
                };
            });
        }
    }

    let splunk_enable = settings.splunk.enable;
    let splunki = if splunk_enable {
        Some(Arc::new(settings.splunk))
    } else {
        None
    };

    if splunk_enable {
        // start splunk checker
        {
            let new_splunk = splunki.clone();
            let new_mail = mail.clone();
            thread::spawn(move || {
                algorithm::splunk_check(new_splunk.unwrap(), new_mail);
            });
        }
    }

    if settings.portscan.enable {
        // start 5min scanner
        algorithm::scan(settings.portscan, mail.clone());
    }

    if settings.webserver.enable {
        // Start webserver
        let splk = if splunk_enable {
            splunki
        } else{
            None
        };

        web::run(settings.webserver, splk, mail).expect("Could not start webserver");
    }

}
