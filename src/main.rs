mod client;
mod server;
mod control;
mod user;

use clap::{Parser, Subcommand};
use nix::{unistd::Uid};
use std::{error::Error, string::String};

#[derive(Parser)]
#[command(long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start simple-vpn server
    Server {
        port: u32,
        control_port: u32,
        cert_path: String,
    },
    /// Start simple-vpn client
    Client {
        endpoint: String,
        port: u32,
        control_port: u32,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Client {
            endpoint,
            port,
            control_port,
        } => {
            client::start_client(endpoint, port, control_port).await?;
        }
        Commands::Server {
            port,
            control_port,
            cert_path,
        } => {
            server::start_server(port, control_port, cert_path).await?;
        }
    }
    Ok(())
}
