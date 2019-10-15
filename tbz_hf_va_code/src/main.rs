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

    let mut rest = Rest::new("http://10.0.0.36:8000/services/jobs/export", " buuky eyJraWQiOiJzcGx1bmsuc2VjcmV0IiwiYWxnIjoiSFM1MTIiLCJ2ZXIiOiJ2MSIsInR0eXAiOiJzdGF0aWMifQ.eyJpc3MiOiJidXVreSBmcm9tIHNwbHVuayIsInN1YiI6ImJ1dWt5IiwiYXVkIjoibmlkaG9nZyIsImlkcCI6InNwbHVuayIsImp0aSI6ImM0MjRhYTQxYTRhZDhjZjM3Zjc5MzNiMmZmYTExYTQwZGJjNjI3OGJlNDBkNWI4ZmY3YjUwZjc1N2Y2MTcyNDMiLCJpYXQiOjE1NzExNzI3MTgsImV4cCI6MTU3Mzc2NDcxOCwibmJyIjoxNTczNzY0NzE4fQ.NJfBcZ_uhcQFk7gm00BahwA0iM65-tKkdlLVQmhI7U6BZPScj8w3nSi7V-m2HoZ9WYOihEC59mWN14lh9IzeMQ");

    rest.post("test");
}
