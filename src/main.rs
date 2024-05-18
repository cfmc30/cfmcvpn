mod client;
mod server;
mod control;
mod user_database;
mod user_manager;
mod tunnel;

use clap::{Parser, Subcommand};
use std::{error::Error, string::String};

extern crate pretty_env_logger;

#[derive(Parser)]
#[command(long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start cfmcvpn server
    Server {
        port: u32,
        control_port: u32,
        cert_path: String,
    },
    /// Start cfmcvpn client
    Client {
        /// Server Hostname
        endpoint: String,
        /// Server Data Port
        port: u32,
        /// Server Control Port
        control_port: u32,
    },
    /// Register a new user
    Register{
        /// Server Hostname
        endpoint: String,
        /// Server Data Port
        port: u32,
        /// Server Control Port
        control_port: u32,
    },
}


#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    pretty_env_logger::init();
    match &cli.command {
        Commands::Client {
            endpoint,
            port,
            control_port,
        } => {
            client::start_client(endpoint, port, control_port).await?;
        }
        Commands::Register{
            endpoint,
            port,
            control_port,
        } => {
            client::register_user(endpoint, port, control_port).await?;
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
