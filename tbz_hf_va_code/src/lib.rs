pub mod snmp {
    use snmp::SyncSession;

    pub struct SnmpObject {
        session: SyncSession,
    }

    impl<'a, 'o> SnmpObject {
        pub fn new(ip: &'a str, community: &'o str) -> SnmpObject {
            SnmpObject {
                session: {
                    match SyncSession::new(
                        format!("{}:161", ip),
                        community.as_bytes(),
                        Some(std::time::Duration::from_secs(2)),
                        0,
                    ) {
                        Ok(s) => s,
                        Err(e) => panic!("ERROR: {}", e),
                    }
                },
            }
        }

        pub fn get<'i>(&mut self, oid: &'i str) -> Result<String, snmp::SnmpError> {
            let oid: Box<[u32]> = oid
                .split_terminator('.')
                .map(|x| x.parse::<u32>().unwrap())
                .collect::<Vec<u32>>()
                .into_boxed_slice();

            match self.session.get(&*oid) {
                Ok(mut response) => {
                    if let Some((_oid, snmp::Value::OctetString(sys_descr))) =
                        response.varbinds.next()
                    {
                        Ok(String::from_utf8_lossy(sys_descr).to_string())
                    } else {
                        Err(snmp::SnmpError::ReceiveError)
                    }
                }
                Err(e) => Err(e),
            }
        }
    }
}

pub mod rest {
    use curl::easy::{Easy, List};

    pub struct Rest {
        token: String,
        client: Easy,
        pub response: Vec<u8>,
        url: String,
    }

    impl<'a> Rest {
        pub fn new<'l>(token: &'a str, url: &'l str) -> Rest {
            Rest {
                token: token.to_owned(),
                client: Easy::new(),
                response: Default::default(),
                url: url.to_owned(),
            }
        }

        pub fn get(&mut self) {
            self.client.get(true).unwrap();
            match self.client.url(&self.url) {
                Ok(_) => {
                    match self.run() {
                        Ok(_) => (),
                        Err(e) => eprintln!("Error: {}", e),
                    };
                }
                Err(e) => eprintln!("{}", e),
            };
        }

        fn set_oauth(&mut self) {
            let mut list = List::new();
            let header = format!("Authorization: {}", self.token);
            list.append(&header).unwrap();

            self.client.http_headers(list).unwrap();
        }

        fn run(&mut self) -> Result<(), curl::Error> {
            self.set_oauth();
            let mut response = Vec::new();
            let mut transfer = self.client.transfer();

            transfer
                .write_function(|new_data| {
                    response.extend_from_slice(new_data);
                    Ok(new_data.len())
                })
                .unwrap();

            transfer.perform()
        }
    }
}

#[allow(dead_code)]
fn run() {
    loop {}
}
