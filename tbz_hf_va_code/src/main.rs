use arp_det;
use nidhogg::rest::Rest;
use nidhogg::snmp;
use std::thread;
use web;

fn main() {
    /*
    match arp_det::run() {
        Ok(_) => (),
        Err(_) => eprintln!("Can't detect arp changes"),
    };
    */

    thread::spawn(|| {
        arp_det::run().expect("Couldn't start arp detection, skipping..");
    });

    web::run().expect("Could not start webserver");

    /*
    let mut sysinfo = snmp::SnmpObject::new("127.0.0.1", "my_comm");
    match sysinfo.get("1.0.2.3.5.1.2.3") {
        Ok(o) => println!("{}", o),
        Err(e) => eprintln!("{:?}", e),
    };

    let mut rest = Rest::new("http://127.0.0.1:8000/blah", "test123token");
    rest.get();

    match scanner::run() {
        Some(output) => println!("{}", output),
        None => (),
    };
    */
}
