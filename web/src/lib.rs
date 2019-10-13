#[macro_use]
extern crate tera;

use actix_files::NamedFile;
use actix_web::{error, get, web, App, Error, HttpResponse, HttpServer, Result};
use db;
use scanner;
use std::path::PathBuf;

/// #Sensor
/// Report down sensors
/// Url: ${hostname}/network
#[get("/sensor/{service}")]
fn down(service: web::Path<String>) -> Result<String> {
    println!("Sensor {} down!", service);
    Ok(format!("Sensor: {} is down!", service))
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
            data.db.remove_entry();
            HttpResponse::Ok().json(arp)
        }
        None => HttpResponse::NoContent().finish(),
    }
}

/// #/scan
/// Path to get current nmap results
/// Url: ${hostname}/scan
#[get("/scan")]
fn scan() -> HttpResponse {
    let scan = scanner::scanner::run();
    match scan {
        Ok(output) => HttpResponse::Ok().json(output),
        Err(_) => HttpResponse::from_error(error::ErrorInternalServerError("NMAP installed?")),
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
}

impl Data {
    fn new(tera: tera::Tera) -> Data {
        Data {
            tera,
            db: db::DBC::new("/tmp/arp.db"),
        }
    }
}

pub fn run() -> std::io::Result<()> {
    println!("Starting webserver on 8080");
    println!("Mounting: {}", env!("CARGO_MANIFEST_DIR"));
    HttpServer::new(|| {
        let tera = compile_templates!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/**/*"));
        let data = Data::new(tera);

        App::new()
            .data(data)
            .service(actix_files::Files::new("/static", "./static").show_files_listing())
            .service(index)
            .service(test)
            .service(arp)
            .service(scan)
    })
    .bind("0.0.0.0:8080")?
    .run()
}
