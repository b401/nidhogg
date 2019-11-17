use curl::easy::{Easy2, Handler, List, WriteError};
use serde::{Deserialize, Serialize};
use std::fmt;

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
pub struct SearchResult {
    pub result: result,
}

impl fmt::Display for SearchResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[{}] {}", self.result.time, self.result.raw)?;
        Ok(())
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct result {
    #[serde(rename = "_indextime")]
    pub indextime: String,
    #[serde(rename = "_raw")]
    pub raw: String,
    #[serde(rename = "_sourcetype")]
    pub sourcetype: String,
    #[serde(rename = "_time")]
    pub time: String,
    pub host: String,
    pub source: String,
}

#[derive(Debug)]
enum OUTPUT {
    SEARCH,
    AUTH,
}

enum METHOD {
    SEARCH(String),
    AUTH(String),
}

#[derive(Serialize, Deserialize, Debug)]
struct Response {
    #[serde(rename = "sessionKey")]
    session_key: String,
}

#[derive(Debug)]
struct Collector(Vec<u8>);

impl Handler for Collector {
    fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
        self.0.clear();
        self.0.extend_from_slice(data);
        Ok(data.len())
    }
}

impl<'user, 'pass> Rest {
    pub fn new<'l>(url: &'l str, user: &'user str, password: &'pass str) -> Rest {
        let mut rest = Rest {
            user: user.to_owned(),
            password: password.to_owned(),
            client: Easy2::new(Collector(Vec::new())),
            response: Default::default(),
            token: Default::default(),
            url: format!("https://{}", url),
        };
        rest.get_token();
        rest
    }

    fn post(&mut self, method: METHOD, content: Vec<String>) -> Option<SearchResult> {
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
        self.run(method)
    }

    pub fn check_sudo(&mut self, host: &String) -> Option<SearchResult> {
        let method = METHOD::SEARCH("/services/search/jobs/export".to_owned());
        let mut query = vec![format!(
            r#"search=search process="sudo" host="{}" sourcetype="linux_secure" | head 1"#,
            host
        )];
        query.push("output_mode=json".to_owned());
        self.post(method, query)
    }

    pub fn check_logins(&mut self) -> Option<SearchResult> {
        let method = METHOD::SEARCH("/services/search/jobs/export".to_owned());
        let mut query = vec![r#"search=search source="/var/log/faillog" | head 1"#.to_owned()];
        query.push("output_mode=json".to_owned());
        self.post(method, query)
    }

    fn set_auth_header(&mut self) {
        let mut list = List::new();
        let header = format!("Authorization: Bearer {}", self.token);
        list.append(&header).unwrap();
        self.client.http_headers(list).unwrap();
    }

    fn get_token(&mut self) {
        let method: METHOD = METHOD::AUTH("/services/auth/login".to_owned());
        let mut query = vec![];
        query.push(format!("username={}&", self.user));
        query.push(format!("password={}", self.password));
        self.post(method, query);
    }

    fn run(&mut self, method: METHOD) -> Option<SearchResult> {
        if !self.token.is_empty() {
            println!("Token is not empty");
            self.set_auth_header();
        }
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
        let response = self.client.get_mut();
        let new_rsp = String::from_utf8_lossy(&response.0).to_string();
        &self.client.reset();
        self.read_response(new_rsp, output)
    }

    fn read_response(&mut self, response: String, output: OUTPUT) -> Option<SearchResult> {
        match output {
            OUTPUT::AUTH => {
                let reader: Result<Response, ()> = match serde_xml_rs::from_str(&response) {
                    Ok(rsp) => Ok(rsp),
                    Err(_) => Err(()),
                };
                if reader.is_ok() {
                    self.token = reader.unwrap().session_key;
                };
                None
            }
            OUTPUT::SEARCH => {
                let reader: Option<SearchResult> = match serde_json::from_str(&response) {
                    Ok(rsp) => Some(rsp),
                    Err(_) => return None,
                };
                reader
            }
        }
    }
}
