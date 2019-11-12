use algorithm;
use arp_det;
use config;
use std::process::exit;
use std::sync::Arc;
use std::thread;
use web;

fn main() {
    let yaml_settings = "/etc/nidhogg/config.yml".to_string();

    let settings = match config::Config::from_file(yaml_settings) {
        Ok(setting) => setting,
        Err(e) => {
            println!("{}", e);
            exit(1);
        }
    };

    let mail = Arc::new(settings.mail);
    let arp_enable = settings.arpscan.enable.clone();
    let arpscan = Arc::new(settings.arpscan);
    if arp_enable {
        {
            // Start arp scanner
            let new_arpscan = arpscan.clone();
            let interface = settings.interface;
            let new_mail = mail.clone();

            println!("[*] Starting arp scanner in new thread");
            thread::spawn(move || {
                match arp_det::run((&new_arpscan, &interface), new_mail) {
                    Ok(_) => (),
                    Err(e) => eprintln!("{}", e),
                };
            });
        }
    }

    let spl_enable = settings.splunk.enable.clone();
    let splunki = Arc::new(settings.splunk);
    let portscan = Arc::new(settings.portscan);
    let webserv = Arc::new(settings.webserver);

    if spl_enable {
        // start splunk checker
        let new_splunki = splunki.clone();
        let new_mail = mail.clone();
        println!("[*] Starting Splunk scanner in new thread");
        thread::spawn(move || {
            algorithm::splunk_check(new_splunki, new_mail);
        });
    }

    let portscan: Option<std::sync::Arc<config::Portscan>> = if portscan.enable {
        // start 5min scanner
        println!("[*] Starting portscanner");
        algorithm::scan(portscan.clone(), mail.clone());
        Some(portscan)
    } else {
        None
    };

    if webserv.enable {
        let spl_web = if spl_enable {
            Some(splunki.clone())
        } else {
            None
        };

        let arp_web = if arp_enable {
            Some(arpscan.clone())
        } else {
            None
        };

        println!("[*] Starting webserver");
        web::run(webserv.clone(), spl_web, mail, portscan, arp_web)
            .expect("Could not start webserver");
    }
}
