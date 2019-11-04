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
    algorithm::sensor_down(&*path, data.splunk.clone(), data.mail.clone());
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

/// #Arpwatch
/// Path to get current arp results
/// Url: ${hostname}/arpwatch
#[get("/arpwatch")]
fn arp(data: web::Data<Data>) -> HttpResponse {
    match data.db.get_entry() {
        Some(arp) => {
            data.db.remove_entry().unwrap();
            HttpResponse::Ok().json(arp)
        }
        None => HttpResponse::NoContent().finish(),
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
}

impl Data {
    fn new(
        tera: tera::Tera,
        splunk: Option<std::sync::Arc<config::Splunk>>,
        mail: std::sync::Arc<config::Mail>,
    ) -> Data {
        Data {
            tera,
            db: db::DBC::new("/tmp/arp.db"),
            splunk,
            mail,
        }
    }
}

pub fn run(
    config: config::Webserver,
    splunk: Option<std::sync::Arc<config::Splunk>>,
    mail: std::sync::Arc<config::Mail>,
) -> std::io::Result<()> {
    println!("Starting webserver on {}:{}", config.address, config.port);
    println!("Mounting: {}", env!("CARGO_MANIFEST_DIR"));
    HttpServer::new(move || {
        let tera = compile_templates!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/**/*"));
        let data = Data::new(tera, splunk.clone(), mail.clone());
        App::new()
            .data(data)
            .service(actix_files::Files::new("/static", "./static").show_files_listing())
            .service(sensor)
            .service(index)
            .service(test)
            .service(arp)
    })
    .bind(&format!("{}:{}", config.address, config.port))?
    .run()
}
