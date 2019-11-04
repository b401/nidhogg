use algorithm;
use arp_det;
use config;
use std::sync::Arc;
use std::thread;
use web;

fn main() -> Result<(),std::boxed::Box<dyn std::error::Error>> {
    let settings = config::Config::from_file("/etc/nidhogg/config.yml")?;
    let mail = Arc::new(settings.mail);
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


    if settings.splunk.enable {
        let splunki = Arc::new(settings.splunk);
        // start splunk checker
        {
            let new_splunk = splunki.clone();
            let new_mail = mail.clone();
            thread::spawn(move || {
                algorithm::splunk_check(new_splunk, new_mail);
            });
        }
    }

    if settings.portscan.enable {
        // start 5min scanner
        algorithm::scan(settings.portscan, mail.clone());
    }

    if settings.webserver.enable {
        // Start webserver
        web::run(settings.webserver, Some(splunki), mail).expect("Could not start webserver");
    }

    Ok(())
}
