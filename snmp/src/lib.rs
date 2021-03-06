use snmp_real::SyncSession;

pub struct SnmpObject {
    session: SyncSession,
}

impl SnmpObject {
    pub fn new(ip: String, community: String) -> SnmpObject {
        dbg!(&ip);
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

    pub fn get(&mut self, oid: String) -> Result<String, snmp_real::SnmpError> {
        let oid: Box<[u32]> = oid
            .split_terminator('.')
            .map(|x| x.parse::<u32>().unwrap())
            .collect::<Vec<u32>>()
            .into_boxed_slice();

        match self.session.get(&oid) {
            Ok(mut response) => {
                if let Some((_oid, snmp_real::Value::OctetString(sys_descr))) = response.varbinds.next()
                {
                    Ok(String::from_utf8_lossy(sys_descr).to_string())
                } else {
                    Err(snmp_real::SnmpError::ReceiveError)
                }
            }
            Err(e) => Err(e),
        }
    }
}

