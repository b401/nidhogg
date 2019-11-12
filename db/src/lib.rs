#[allow(unused_imports)]
use rusqlite::types::ToSql;
use rusqlite::{params, Connection, Result, NO_PARAMS};
use std::path::Path;

pub struct DBC {
    connection: Connection,
}

impl DBC {
    #[rustfmt::skip]
    pub fn new(path: &str) -> DBC {
        let db_path = Path::new(path);
        let connection = DBC::connect(db_path);
        connection.execute("CREATE TABLE if not exists arp (
            id INTEGER PRIMARY KEY,
            mac TEXT UNIQUE NOT NULL ON CONFLICT IGNORE,
            time_created TEXT NOT NULL)",NO_PARAMS).unwrap();


        DBC { connection }
    }

    fn connect(path: &Path) -> Connection {
        match Connection::open(path) {
            Ok(connection) => connection,
            Err(e) => panic!("Error: {}", e),
        }
    }

    #[rustfmt::skip]
    pub fn insert_entry(&self, param: &str) -> Result<()> {
        let mut prepared_statement = self.connection.prepare(
            "INSERT INTO arp (mac, time_created) VALUES (?, ?)",
        )?;
        match prepared_statement.execute(params![param, time::get_time()]) {
            Ok(_) => Ok(()),
            Err(_) => Ok(()), //ignore constraint errors
        }
    }

    pub fn get_entry(&self) -> Option<Vec<String>> {
        let mut prepared_statement = self
            .connection
            .prepare(r#"SELECT time_created || ',' || mac from arp"#)
            .unwrap();
        let rows = prepared_statement
            .query_map(NO_PARAMS, |row| row.get(0))
            .unwrap();

        let mut addresses = Vec::new();
        for mac in rows {
            addresses.push(mac.unwrap());
        }

        if addresses.len() != 0 {
            Some(addresses)
        } else {
            None
        }
    }

    pub fn remove_entry(&self) -> Result<()> {
        let mut prepared_statement = self.connection.prepare("DELETE FROM arp")?;
        prepared_statement.execute(params![])?;
        Ok(())
    }
}
