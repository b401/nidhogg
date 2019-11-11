#[macro_use]
extern crate tera;

use actix_web::{get, web, App, Error, HttpResponse, HttpServer, Result};
use algorithm;
use config;
use db;

/// #Sensor
/// Report down sensors
/// Url: ${hostname}/network
#[get("/sensor/{host}/{sensor}/{state}")]
fn sensor(path: web::Path<algorithm::Prtg>, data: web::Data<Data>) -> Result<String> {
    println!("Got somethin new!");
    algorithm::sensor_changed(
        &*path,
        data.splunk.clone(),
        data.mail.clone(),
        data.portscan.clone().unwrap(),
    );
    Ok(format!(""))
}

/// #Index
/// Path to get current index
/// Url: ${hostname}
#[get("/")]
fn index(tmpl: web::Data<Data>) -> Result<HttpResponse> {
    let ctx = tmpl
        .tera
        .render("index.html", &tera::Context::new())
        .unwrap();
    Ok(HttpResponse::Ok().content_type("text/html").body(ctx))
}

/// #Port
/// Portoverview
/// Url: /port
#[get("/port")]
fn port(tmpl: web::Data<Data>) -> Result<HttpResponse> {
    let mut context = tera::Context::new();
    if let Some(config) = tmpl.portscan.clone() {
        let res = algorithm::scan_once(config);
        let mut trst: Vec<scanner::DisplayScan> = Default::default();

        for i in res {
            let ip = i.host_analysis_results.ip.ip;
            let mut scan: scanner::DisplayScan = scanner::DisplayScan::from(ip);
            for x in i.host_analysis_results.ip.port_results {
                if x.fail.is_some() {
                    scan.port.push(x.fail.unwrap());
                }
            }
            trst.push(scan);
        }

        context.insert("anomalie", &trst);
        let ctx = tmpl.tera.render("port.html", &context).unwrap();
        Ok(HttpResponse::Ok().content_type("text/html").body(ctx))
    } else {
        //TODO
        let ctx = tmpl.tera.render("port.html", &context).unwrap();
        Ok(HttpResponse::Ok().content_type("text/html").body(ctx))
    }
}

/// #Arpwatch
/// Path to get current arp results
/// Url: ${hostname}/arpwatch
#[get("/arp")]
fn arpoverview(data: web::Data<Data>) -> HttpResponse {
    let mut context = tera::Context::new();

    match data.db.get_entry() {
        Some(arp) => {
            //data.db.remove_entry().unwrap();
            context.insert("macs", &arp);
            let ctx = data.tera.render("arp.html", &context).unwrap();
            HttpResponse::Ok().content_type("text/html").body(ctx)
        }
        None => {
            let ctx = data.tera.render("arp.html", &tera::Context::new()).unwrap();
            HttpResponse::Ok().content_type("text/html").body(ctx)
        }
    }
}

/// #/test
/// Path to check if tera templates are working
/// Url: ${hostname}/test
#[get("test")]
fn test(tmpl: web::Data<Data>) -> Result<HttpResponse, Error> {
    let ctx = tmpl
        .tera
        .render("user.html", &tera::Context::new())
        .unwrap();
    Ok(HttpResponse::Ok().content_type("text/html").body(ctx))
}

struct Data {
    tera: tera::Tera,
    db: db::DBC,
    splunk: Option<std::sync::Arc<config::Splunk>>,
    mail: std::sync::Arc<config::Mail>,
    portscan: Option<std::sync::Arc<config::Portscan>>,
}

impl Data {
    fn new(
        tera: tera::Tera,
        splunk: Option<std::sync::Arc<config::Splunk>>,
        mail: std::sync::Arc<config::Mail>,
        portscan: Option<std::sync::Arc<config::Portscan>>,
    ) -> Data {
        Data {
            tera,
            db: db::DBC::new("/tmp/arp.db"),
            splunk,
            mail,
            portscan,
        }
    }
}

pub fn run(
    config: config::Webserver,
    splunk: Option<std::sync::Arc<config::Splunk>>,
    mail: std::sync::Arc<config::Mail>,
    portscan: Option<std::sync::Arc<config::Portscan>>,
) -> std::io::Result<()> {
    println!("Starting webserver on {}:{}", config.address, config.port);
    HttpServer::new(move || {
        let tera = compile_templates!(concat!("/etc/nidhogg/templates/**/*"));
        let data = Data::new(tera, splunk.clone(), mail.clone(), portscan.clone());
        App::new()
            .data(data)
            .service(actix_files::Files::new("/static", "/etc/nidhogg/static").show_files_listing())
            .service(sensor)
            .service(index)
            .service(test)
            .service(port)
            .service(arpoverview)
    })
    .bind(&format!("{}:{}", config.address, config.port))?
    .run()
}
