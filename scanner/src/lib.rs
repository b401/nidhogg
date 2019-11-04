use nmap_analyze::output::JsonOutput;
use nmap_analyze::output::{OutputConfig, OutputDetail, OutputFormat};
use nmap_analyze::*;
use serde;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fmt;
use std::process::Command;
use std::str;
use std::str::FromStr;

#[derive(Debug, Deserialize, Serialize)]
pub struct ScanResult {
    pub pass: u8,
    pub fail: u8,
    pub error: u8,
    pub host_analysis_results: Root,
}

impl fmt::Display for ScanResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "\n\n[Scan]\nPass: {}\nFail: {}\nAnalysis:\n{}",
            self.pass, self.fail, self.host_analysis_results
        )
    }
}

impl fmt::Display for Root {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IP: {}\nResult:\n", self.ip.ip)?;
        for v in &self.ip.port_results {
            if v.fail.as_ref().is_some() {
                write!(
                    f,
                    "\n[ALERT] Port: {} - State: {}",
                    v.fail.as_ref().unwrap_or(&(0, Default::default())).0,
                    v.fail.as_ref().unwrap_or(&(0, Default::default())).1
                )?;
            }
        }
        Ok(())
    }
}

#[derive(Default, Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Root {
    pub ip: Address,
}

#[derive(Default, Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Address {
    ip: String,
    pub port_results: Vec<PortResult>,
    #[serde(skip)]
    portspec_name: String,
    pub summary: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortResult {
    #[serde(rename = "Pass")]
    #[serde(skip)]
    pass: Option<(i64, String)>,
    #[serde(rename = "Fail")]
    pub fail: Option<(i64, String)>,
}

pub fn run(host: Option<&String>) -> Result<Option<ScanResult>> {
    use sedregex::find_and_replace;
    let portspecs = PortSpecs::from_file("portspecs.yml").expect("Failed to load portspec file");
    let mappings = Mapping::from_file("mappings.xml").expect("Failed to load mapping file");

    let dst_host: String = match host {
        Some(dns) => dns.to_owned(),
        None => "*".to_owned(),
    };

    // ugly sed hack
    // TODO create pull request
    let nmap_output = Command::new("nmap")
        .arg("-dd")
        .arg("-n")
        .arg("-sS")
        .arg("-oX")
        .arg("-")
        .arg(dst_host)
        .output()
        .unwrap();

    let output = str::from_utf8(&nmap_output.stdout).unwrap();

    let content: String = String::from(find_and_replace(output, &["/.*mac.*/d"]).unwrap());

    let nmap_output = match Run::from_str(&content) {
        Ok(sane) => sane,
        Err(e) => {
            let error = nmap_analyze::Error::from_kind(nmap_analyze::ErrorKind::Msg(format!(
                "Did you run as root or is the host in the mapping/speclist?? {}",
                e
            )));
            return Err(error);
        }
    };

    let analyzer_result = default_analysis(&nmap_output, &mappings, &portspecs);

    let output_config = OutputConfig {
        detail: OutputDetail::Fail,
        format: OutputFormat::Json,
        color: false,
    };

    let mut buffer = Vec::new();

    analyzer_result
        .output(&output_config, &mut buffer)
        .expect("output failure");

    let x = String::from_utf8_lossy(&buffer);
    let utfbuffer: ScanResult = serde_json::from_str(&x).unwrap();
    if utfbuffer.fail == 1 {
        Ok(Some(utfbuffer))
    } else if utfbuffer.error > 0 {
        Err(nmap_analyze::Error::from_kind(
            nmap_analyze::ErrorKind::Msg("Scan failed".to_owned()),
        ))
    } else if utfbuffer.pass == 1 {
        Ok(None)
    } else {
        Ok(Some(utfbuffer))
    }
}
