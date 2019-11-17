#[macro_use]
extern crate tera;

use actix_identity::Identity;
use actix_identity::{CookieIdentityPolicy, IdentityService};
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Result};
use algorithm;
use config;
use db;
use serde::{Deserialize, Serialize};

/// # Login
/// Login user and sensor
#[post("/login")]
fn login(data: web::Data<Data>, params: web::Form<Login>, id: Identity) -> HttpResponse {
    // Fix for prod
    // Only for demostrative purpose.
    if params.username.as_ref().unwrap_or(&"unknown".to_owned()) == &data.config.username
        && params.password.as_ref().unwrap_or(&"unknown".to_owned()) == &data.config.password
    {
        id.remember(data.config.username.to_owned());
    }
    HttpResponse::Found().header("location", "/port").finish()
}

/// # Logout
/// Logout user and sensor
#[get("/logout")]
fn logout(id: Identity) -> HttpResponse {
    // Fix for prod
    // Only for demostrative purpose.
    id.forget();
    HttpResponse::Found().header("location", "/").finish()
}

/// #Sensor
/// Report down sensors
/// Url: ${hostname}/network
#[get("/sensor/{host}/{sensor}/{state}")]
fn sensor(path: web::Path<algorithm::Prtg>, data: web::Data<Data>) -> Result<String> {
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
        .render("login.html", &tera::Context::new())
        .unwrap();
    Ok(HttpResponse::Ok().content_type("text/html").body(ctx))
}

/// #Port
/// Portoverview
/// Url: /port
#[get("/port")]
fn port(tmpl: web::Data<Data>, id: Identity) -> Result<HttpResponse> {
    if id.identity().unwrap_or_else(|| "unknown".to_owned()) == tmpl.config.username {
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
    } else {
        Ok(HttpResponse::Found().header("location", "/").finish())
    }
}

/// #Arpwatch
/// Path to get current arp results
/// Url: ${hostname}/arpwatch
#[get("/arp")]
fn arpoverview(data: web::Data<Data>, id: Identity) -> HttpResponse {
    if id.identity().unwrap_or_else(|| "unknown".to_owned()) == data.config.username {
        let mut context = tera::Context::new();
        if let Some(db) = &data.db {
            match db.get_entry() {
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
        } else {
            HttpResponse::Found().header("location", "/404").finish()
        }
    } else {
        HttpResponse::Found().header("location", "/").finish()
    }
}

#[derive(Serialize, Deserialize)]
struct Login {
    username: Option<String>,
    password: Option<String>,
}

struct Data {
    tera: tera::Tera,
    db: Option<db::DBC>,
    splunk: Option<std::sync::Arc<config::Splunk>>,
    mail: std::sync::Arc<config::Mail>,
    portscan: Option<std::sync::Arc<config::Portscan>>,
    config: std::sync::Arc<config::Webserver>,
}

impl Data {
    fn new(
        tera: tera::Tera,
        splunk: Option<std::sync::Arc<config::Splunk>>,
        mail: std::sync::Arc<config::Mail>,
        portscan: Option<std::sync::Arc<config::Portscan>>,
        config: std::sync::Arc<config::Webserver>,
        arpscan: Option<std::sync::Arc<config::Arpscan>>,
    ) -> Data {
        let path_to_db = if let Some(db_config) = arpscan {
            Some(db::DBC::new(&db_config.db))
        } else {
            None
        };

        Data {
            tera,
            db: path_to_db,
            splunk,
            mail,
            portscan,
            config,
        }
    }
}

pub fn run(
    config: std::sync::Arc<config::Webserver>,
    splunk: Option<std::sync::Arc<config::Splunk>>,
    mail: std::sync::Arc<config::Mail>,
    portscan: Option<std::sync::Arc<config::Portscan>>,
    arpscan: Option<std::sync::Arc<config::Arpscan>>,
) -> std::io::Result<()> {
    println!("Starting webserver on {}:{}", config.address, config.port);
    let arc = config.clone();
    HttpServer::new(move || {
        let mount = if cfg!(target_os = "linux") {
            concat!("/etc/nidhogg/templates/**/*")
        } else {
            concat!(r#"C:\Programme\nidhogg\templates\**\*"#)
        };

        let static_web = if cfg!(target_os = "linux") {
            "/etc/nidhogg/static".to_string()
        } else {
            r#"C:\Programme\nidhogg\static"#.to_string()
        };

        let tera = compile_templates!(mount);
        let data = Data::new(
            tera,
            splunk.clone(),
            mail.clone(),
            portscan.clone(),
            arc.clone(),
            arpscan.clone(),
        );
        App::new()
            .data(data)
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(&[0; 32])
                    .name("Nidhogg")
                    .secure(false),
            ))
            .service(actix_files::Files::new("/static", static_web).show_files_listing())
            .service(sensor)
            .service(index)
            .service(port)
            .service(login)
            .service(logout)
            .service(arpoverview)
    })
    .bind(&format!("{}:{}", config.address, config.port))?
    .run()
}
