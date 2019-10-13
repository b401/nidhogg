pub mod scanner {
    use nmap_analyze::output::JsonOutput;
    use nmap_analyze::output::{OutputConfig, OutputDetail, OutputFormat};
    use nmap_analyze::*;
    use serde::{Deserialize, Serialize};
    use serde_json;
    use std::process::{exit, Command};
    use std::str;
    use std::str::FromStr;

    #[derive(Debug, Deserialize, Serialize)]
    pub struct ScanResult {
        pub pass: u8,
        pub fail: u8,
        pub error: u8,
        pub host_analysis_results: serde_json::Value,
    }

    pub fn run() -> Result<ScanResult> {
        let portspecs =
            PortSpecs::from_file("portspecs.yml").expect("Failed to load portspec file");
        let mappings = Mapping::from_file("mappings.xml").expect("Failed to load mapping file");

        let nmap_output = Command::new("nmap")
            .arg("-dd")
            .arg("-n")
            .arg("-sS")
            .arg("-oX")
            .arg("-")
            .arg("10.0.0.20")
            .output()
            .unwrap();

        let output = str::from_utf8(&nmap_output.stdout).unwrap();
        let nmap_output = match Run::from_str(output) {
            Ok(sane) => sane,
            Err(_) => {
                eprintln!("Did you run as root?");
                exit(1);
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

        Ok(utfbuffer)
    }
}
