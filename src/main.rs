use fern::colors::{Color, ColoredLevelConfig};
use fern::Dispatch;
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore};
use wow_login_messages::helper::{tokio_read_initial_message, InitialMessage};
use wow_login_messages::ClientMessage;

use std::error::Error;
use std::fs::{File, OpenOptions};
use std::sync::Arc;

pub mod config;
use config::Config;

#[derive(Serialize, Deserialize, Clone)]
pub struct BannedConnection {
    pub ip: String,
    pub invalid_packets: u32,
}

async fn handle(mut stream: tokio::net::TcpStream, config: Arc<Mutex<Config>>) {
    let Ok(peer_addr) = stream.peer_addr() else {
        log::warn!("Unable to get peer address, rejecting");
        return;
    };

    // only happens on mutex poison
    let mut cfg = config.lock().await;

    cfg.banned_connections
        .iter()
        .filter(|ip| ip.ip == peer_addr.ip().to_string())
        .for_each(|ip| {
            if ip.invalid_packets >= cfg.max_invalid_packets {
                log::warn!(
                    "Banned connection from {:#?} attempting to connect, dropping",
                    peer_addr
                );
                return;
            }
        });

    log::info!("New connection from: {:#?}", peer_addr);
    let opcode = tokio_read_initial_message(&mut stream).await;

    let opcode = match opcode {
        Ok(o) => o,
        Err(e) => {
            if cfg
                .banned_connections
                .iter()
                .find(|ip| ip.ip == peer_addr.ip().to_string())
                .is_none()
            {
                cfg.banned_connections.push(BannedConnection {
                    ip: peer_addr.ip().to_string(),
                    invalid_packets: 1,
                });
            } else {
                let mut index = 0;
                for (i, connection) in cfg.banned_connections.iter().enumerate() {
                    if connection.ip == peer_addr.ip().to_string() {
                        index = i;
                    }
                }
                cfg.banned_connections[index].invalid_packets += 1;
            }

            log::warn!(
                "Error failing to parse auth packet, possible ddos! : {:#?}",
                e
            );

            return;
        }
    };
    log::debug!("Validated packet from {:#?}", peer_addr);
    log::info!("Proxying packet from {:#?} to authserver", peer_addr);

    relay(stream, opcode, &cfg.auth_host).await;
}

async fn relay(mut stream: tokio::net::TcpStream, opcode: InitialMessage, auth_host: &str) {
    let Ok(mut auth_stream) = tokio::net::TcpStream::connect(auth_host).await else {
        log::error!("Unable to connect to authserver");
        return;
    };
    log::info!("Connected to authserver, relaying..");
    log::info!("Sending logon packet to authserver");

    // TODO: refactor this, i dont think we even have to care what packet it is.
    match opcode {
        InitialMessage::Logon(l) => {
            // convert the bottom line into let else syntax

            match l.tokio_write(&mut auth_stream).await {
                Ok(_) => {}
                Err(e) => {
                    log::error!("Error sending logon packet to authserver: {:#?}", e);
                    return;
                }
            }

            log::info!("Sent logon packet to authserver");
        }
        InitialMessage::Reconnect(r) => match r.tokio_write(&mut auth_stream).await {
            Ok(_) => {}
            Err(e) => {
                log::error!("Error sending reconnect packet to authserver: {:#?}", e);
                return;
            }
        },
    };

    let (mut client_r, mut client_w) = stream.split();
    let (mut server_r, mut server_w) = auth_stream.split();

    let client_to_server = tokio::io::copy(&mut client_r, &mut server_w);
    let server_to_client = tokio::io::copy(&mut server_r, &mut client_w);

    tokio::select! {
        result = client_to_server => {
            // Client to server transfer is complete
            if let Err(e) = result {
                log::debug!("Client to server transfer failed: {}", e);
            } else {
                log::debug!("Client to server transfer complete");
            }
        }
        result = server_to_client => {
            // Server to client transfer is complete
            if let Err(e) = result {
                log::debug!("Server to client transfer failed: {}", e);
            } else {
                log::debug!("Server to client transfer complete");
            }
        }
    }
}

/// Responsible for writing the ban file to disk
async fn ban_service(config: Arc<Mutex<Config>>) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        log::debug!("Writing ban file to disk");
        let cfg = config.lock().await;

        let banned_connections = cfg.banned_connections.clone();

        let Ok(file) = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&cfg.ban_file) else {
                log::error!("Unable to open ban file for writing");
                return;
            };

        match serde_json::to_writer_pretty(file, &banned_connections) {
            Ok(_) => {}
            Err(e) => {
                log::error!("Unable to write ban file: {:#?}", e);
                return;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let colors = ColoredLevelConfig::new()
        .info(Color::Green)
        .debug(Color::Cyan);
    Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}:{}] {}",
                chrono::Local::now().format("[%H:%M:%S]"),
                colors.color(record.level()),
                record.file().unwrap_or_default(),
                record.line().unwrap_or_default(),
                message
            ))
        })
        .level(LevelFilter::Debug)
        .chain(std::io::stdout())
        .chain(fern::log_file(format!(
            "{}-srp_proxy.log",
            chrono::Local::now().format("[%Y-%m-%d]")
        ))?)
        .apply()?;

    let mut config = match Config::new() {
        Ok(c) => c,
        Err(e) => {
            log::error!("Error reading config file: {:#?}", e);
            return Ok(());
        }
    };

    let banned_connections: Vec<BannedConnection> = match serde_json::from_reader(
        File::open(&config.ban_file).expect("Failed to open banned connections file"),
    ) {
        Ok(b) => b,
        Err(e) => {
            log::error!("Error reading banned connections file: {:#?}", e);
            return Ok(());
        }
    };

    config.banned_connections = banned_connections;

    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let listener = TcpListener::bind(&config.proxy_host).await?;

    log::info!("SRP Proxy ready, listening on: {}", config.proxy_host);

    // TODO: change this to RwLock too for even better performance
    let config = Arc::new(Mutex::new(config));

    tokio::spawn(ban_service(config.clone()));

    loop {
        let config = config.clone();
        let semaphore = semaphore.clone();
        let (stream, _) = listener.accept().await?;

        tokio::spawn(async move {
            if semaphore.try_acquire().is_err() {
                log::warn!("Max connections reached, dropping connection");
                return;
            }

            handle(stream, config).await;
            semaphore.add_permits(1);
            log::info!("Client disconnected, releasing permit");
        });
    }
}
