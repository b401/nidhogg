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
    use curl::easy::{Auth, Easy2, Handler, List, WriteError};
    use serde::{Deserialize, Serialize};
    use serde_xml_rs::from_str;

    #[derive(Debug)]
    pub struct Rest {
        user: String,
        password: String,
        token: String,
        client: Easy2<Collector>,
        pub response: Vec<u8>,
        url: String,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct Message {
        result: SearchResult,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct SearchResult {
        _raw: String,
        _sourcetype: String,
        _time: String,
        _host: String,
        source: String,
    }

    enum OUTPUT {
        SEARCH,
        AUTH,
    }

    enum METHOD {
        SEARCH(String),
        AUTH(String),
    }

    #[derive(Serialize, Deserialize)]
    struct response {
        sessionKey: String,
    }

    #[derive(Debug)]
    struct Collector(Vec<u8>);

    impl Handler for Collector {
        fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
            self.0.extend_from_slice(data);
            Ok(data.len())
        }
    }

    impl<'user, 'pass> Rest {
        pub fn new<'l>(url: &'l str, user: &'user str, password: &'pass str) -> Rest {
            let mut Rest = Rest {
                user: user.to_owned(),
                password: password.to_owned(),
                client: Easy2::new(Collector(Vec::new())),
                response: Default::default(),
                token: Default::default(),
                url: format!("https://{}", url),
            };
            Rest.get_token();
            Rest
        }

        fn post(&mut self, method: METHOD, content: Vec<String>) {
            self.client.post(true).unwrap();
            let coll: String = content
                .iter()
                .map(|x| {
                    if content.len() > 1 {
                        "&".to_owned() + x.as_str()
                    } else {
                        x.to_owned()
                    }
                })
                .collect::<String>();
            self.client.post_fields_copy(coll.as_bytes()).unwrap();
            match self.client.url(&self.url) {
                Ok(_) => self.run(method),
                Err(_) => eprintln!("Error"),
            };
        }

        fn get(&mut self, url: String) {
            let method = METHOD::SEARCH("".to_owned());
            self.client.get(true).unwrap();
            let new_url = format!("{}{}", self.url, url);
            match self.client.url(new_url.as_ref()) {
                Ok(()) => self.run(method),
                Err(_) => eprintln!("Error"),
            };
        }

        pub fn check_sudo(&mut self) {
            let method = METHOD::SEARCH("/services/search/jobs/export".to_owned());
            let query =
                vec!["search='search source=/var/log/auth.log process=sudo | head 3".to_owned()];
            self.post(method, query);
        }

        fn get_token(&mut self) {
            let method: METHOD = METHOD::AUTH("/services/auth/login".to_owned());
            let mut query = vec![];
            query.push(format!("username={}&", self.user));
            query.push(format!("password={}", self.password));
            self.post(method, query);
        }

        fn run(&mut self, method: METHOD) {
            // Can later be changed
            let output: OUTPUT = match method {
                METHOD::SEARCH(search_url) => {
                    self.client
                        .url(&format!("{}{}", self.url, search_url))
                        .unwrap();
                    OUTPUT::SEARCH
                }
                METHOD::AUTH(auth_url) => {
                    self.client
                        .url(&format!("{}{}", self.url, auth_url))
                        .unwrap();
                    OUTPUT::AUTH
                }
            };
            // only on self signed
            self.client.ssl_verify_peer(false).unwrap();
            self.client.ssl_verify_host(false).unwrap();
            self.client.perform().unwrap();

            let response = self.client.get_ref();
            let new_rsp = String::from_utf8_lossy(&response.0).to_string();
            self.read_xml(new_rsp, output);
        }

        fn read_xml(&mut self, response: String, output: OUTPUT) {
            match output {
                OUTPUT::AUTH => {
                    let reader: response = serde_xml_rs::from_str(&response).unwrap();
                    self.token = reader.sessionKey;
                }
                OUTPUT::SEARCH => (),
            };
        }
    }
}

#[allow(dead_code)]
fn run() {
    loop {}
}
