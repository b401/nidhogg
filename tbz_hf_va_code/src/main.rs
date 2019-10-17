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

    //    thread::spawn(|| {
    //        arp_det::run().expect("Couldn't start arp detection, skipping..");
    //    });

    //    web::run().expect("Could not start webserver");

    /*
    let mut sysinfo = snmp::SnmpObject::new("127.0.0.1", "my_comm");
    match sysinfo.get("1.0.2.3.5.1.2.3") {
        Ok(o) => println!("{}", o),
        Err(e) => eprintln!("{:?}", e),
    };

    match scanner::run() {
        Some(output) => println!("{}", output),
        None => (),
    };
    */

    // splunk
    // curl -k -H "Authorization: Bearer eyJfd3e46a31246da7ea7f109e7f95fd" . . .

    let mut rest = Rest::new("10.0.0.36:8089", "buuky", "duHurWfu21");
}
