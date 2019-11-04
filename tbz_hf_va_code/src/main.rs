use algorithm;
use arp_det;
use config;
use std::process::exit;
use std::sync::Arc;
use std::thread;
use web;

fn main() {
    let settings = match config::Config::from_file("/etc/nidhogg/config.yml") {
        Ok(setting) => setting,
        Err(e) => {
            println!("{}", e);
            exit(1);
        }
    };

    let mail = Arc::new(settings.mail);
    if settings.arpscan.enable {
        // Start arp scanner
        {
            let arpscan = settings.arpscan;
            let interface = settings.interface;
            let new_mail = mail.clone();
            thread::spawn(move || {
                println!("[*] Starting arp scanner");
                match arp_det::run((&arpscan, &interface), new_mail) {
                    Ok(_) => (),
                    Err(e) => eprintln!("{}", e),
                };
            });
        }
    }

    let spl_enable = settings.splunk.enable.clone();
    let splunki = Arc::new(settings.splunk);

    if spl_enable {
        // start splunk checker
        let new_splunk = splunki.clone();
        let new_mail = mail.clone();
        thread::spawn(move || {
            println!("[*] Starting Splunk scanner");
            algorithm::splunk_check(new_splunk, new_mail);
        });
    }

    if settings.portscan.enable {
        // start 5min scanner
        println!("[*] Starting portscanner");
        algorithm::scan(settings.portscan, mail.clone());
    }

    if settings.webserver.enable {
        let spl_web = if spl_enable {
            Some(splunki.clone())
        } else {
            None
        };
        println!("[*] Starting webserver");
        web::run(settings.webserver, spl_web, mail).expect("Could not start webserver");
    }
}
