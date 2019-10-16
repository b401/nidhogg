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
    use curl::easy::{Easy2, Handler, List, WriteError};
    use serde::{Deserialize, Serialize};

    pub struct Rest {
        token: String,
        client: Easy2<Collector>,
        pub response: Vec<u8>,
        url: String,
    }

    #[derive(Serialize, Deserialize)]
    struct Message {
        result: SearchResult,
    }

    #[derive(Serialize, Deserialize)]
    struct SearchResult {
        _raw: String,
        _sourcetype: String,
        _time: String,
        _host: String,
        source: String,
    }

    enum METHOD {
        SEARCH(String),
    }

    struct Collector(Vec<u8>);

    impl Handler for Collector {
        fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
            self.0.extend_from_slice(data);
            Ok(data.len())
        }
    }

    impl<'a> Rest {
        pub fn new<'l>(token: &'a str, url: &'l str) -> Rest {
            Rest {
                token: token.to_owned(),
                client: Easy2::new(Collector(Vec::new())),
                response: Default::default(),
                url: url.to_owned(),
            }
        }

        fn post(&mut self, method: METHOD, content: String) {
            self.client.post(true).unwrap();
            let query = content.as_ref();
            self.client.post_fields_copy(query);
            match self.client.url(&self.url) {
                Ok(_) => self.run(),
                Err(_) => eprintln!("Errorr"),
            };
        }

        pub fn check_sudo(&mut self) {
            let method = METHOD::SEARCH("/services/search/jobs/export".to_owned());
            let mut query: String =
                "search='search source=/var/log/auth.log process=sudo | head 3".to_owned();
            self.post(method, query);
        }

        fn set_oauth(&mut self) {
            let mut list = List::new();
            let header = format!("Authorization: Bearer {}", self.token);
            list.append(&header).unwrap();

            self.client.http_headers(list).unwrap();
        }

        fn run(&mut self) {
            self.set_oauth();
            self.client.perform().unwrap();
            let response = self.client.get_ref();
            println!("{}", String::from_utf8_lossy(&response.0));
        }
    }
}

#[allow(dead_code)]
fn run() {
    loop {}
}
