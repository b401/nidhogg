//use c_ares_resolver::Resolver;
use config::NetworkAddresses;
use crossbeam_channel::{never, select};
use db;
use network::Event;
use pnet::util::MacAddr;
use std::collections::{hash_map, HashMap};
use std::path::PathBuf;
use structopt::StructOpt;

mod config;
mod error;
mod network;

const TICK_SECS: u32 = 20;

#[derive(Debug, structopt::StructOpt)]
#[structopt(about)]
struct Opt {
    #[structopt(long, default_value = "config.yaml")]
    config_file: PathBuf,
}

type Result<T, E = error::Error> = std::result::Result<T, E>;

#[derive(Debug)]
enum Status {
    Arrived,
    Left,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Arrived => write!(f, "arrived"),
            Self::Left => write!(f, "left"),
        }
    }
}

#[derive(Debug)]
struct Tracking {
    ip: std::net::Ipv4Addr,
    outstanding: u32,
}

pub struct Queue {
    mac: Vec<MacAddr>,
}

impl Queue {
    fn new() -> Queue {
        Queue { mac: Vec::new() }
    }

    fn set(&mut self, mac: MacAddr) {
        self.mac.push(mac);
    }

    pub fn get(&self) -> Option<Vec<String>> {
        match self.mac.len() {
            0 => None,
            _ => Some(self.mac.iter().map(|x| x.to_string()).collect()),
        }
    }

    pub fn clear(&mut self) {
        self.mac.clear();
    }
}

pub struct Inddex {
    interface_name: String,
    mac: Vec<MacAddr>,
    network_addresses: NetworkAddresses,
    socket: network::Socket,
    online: HashMap<MacAddr, Tracking>,
    pub queue: db::DBC,
}

impl Inddex {
    fn new(config: config::Config) -> Result<Self> {
        Ok(Self {
            interface_name: config.interface.name,
            mac: config.mac,
            network_addresses: config.interface.addresses,
            socket: network::Socket::new(config.interface.index)?,
            online: HashMap::new(),
            queue: db::DBC::new(&config.db),
        })
    }

    fn start_pcap(&mut self) -> Result<crossbeam_channel::Receiver<Event>> {
        let mut capture = pcap::Capture::from_device(self.interface_name.as_str())?
            .promisc(true)
            .open()?;
        capture.direction(pcap::Direction::In)?;
        capture.filter("arp or (udp and port bootpc)")?;

        let (s, r) = crossbeam_channel::unbounded();
        std::thread::spawn(move || loop {
            match capture.next() {
                Ok(packet) => {
                    if let Err(e) = s.send(network::parse_packet(packet.data)) {
                        println!("Failed to send event, exiting: {}", e);
                        return;
                    }
                }
                Err(e) => {
                    println!("Failed to read packet, exiting: {}", e);
                    return;
                }
            };
        });

        Ok(r)
    }

    fn run(&mut self) -> Result<()> {
        let cap_r = self.start_pcap()?;

        let (resolve_s, resolve_r) = crossbeam_channel::unbounded();
        drop(resolve_s);
        let mut resolve_r = Some(&resolve_r);

        let mut t;
        let mut clock = None;

        #[allow(clippy::drop_copy, clippy::zero_ptr)]
        loop {
            select! {
                recv(cap_r) -> event => self.handle_event(event?),
                recv(resolve_r.unwrap_or(&never())) -> device => match device {
                    Ok((mac, ip)) => self.handle_resolve(mac, ip),
                    Err(_) => {
                        resolve_r = None;
                    }
                },
            }
            match (self.online.is_empty(), clock) {
                (true, Some(_)) => {
                    println!("No devices online, disabling clock");
                    clock = None;
                }
                (false, None) => {
                    t = crossbeam_channel::tick(std::time::Duration::from_secs(TICK_SECS.into()));
                    clock = Some(&t);
                }
                _ => (),
            }
        }
    }

    fn handle_resolve(&self, mac: MacAddr, ip: std::net::Ipv4Addr) {
        println!("Resolved: {}", ip);
        if let Err(e) = self
            .socket
            .send_arp_request(&self.network_addresses, &NetworkAddresses::new(mac, ip))
        {
            println!("Failed to send ARP request to {}: {}", ip, e);
        }
    }

    fn handle_event(&mut self, event: Event) {
        match event {
            Event::Connected(mac) => {
                if !self.mac.contains(&mac) {
                    self.notify(mac);
                }
            }
            Event::Ignored => (),
            _ => (),
        }
    }

    /*
    fn handle_event(&mut self, event: Event) {
        match event {
            Event::Connected(mac) => {
                if !self.mac.contains(&mac) {
                    self.notify(mac);
                }
            }
            Event::Alive { mac, ip } => {
                if !self.mac.contains(&mac) {
                    println!("Unknown Mac: {}", mac);
                    match self.online.entry(mac) {
                        hash_map::Entry::Occupied(mut occupied) => {
                            occupied.get_mut().outstanding = 0
                        }
                        hash_map::Entry::Vacant(vacant) => {
                            vacant.insert(Tracking { ip, outstanding: 0 });
                        }
                    }
                }
            }
            Event::Ignored => (),
        }
    }
            */

    // WICHTIG!!!
    fn notify(&mut self, mac: MacAddr) {
        match self.queue.insert_entry(&mac.to_string()) {
            Ok(_) => println!("Found new device: {}", mac),
            Err(e) => println!("Error: {}", e),
        }
    }
}

pub fn run() -> Result<()> {
    println!("Starting arp detection");
    let opt = Opt::from_args();
    let config = config::Config::from_file(opt.config_file)?;
    let mut inddex = Inddex::new(config)?;
    inddex.run()
}
