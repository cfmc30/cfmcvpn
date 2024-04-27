
use crate::control::{self, ClientMsg};

use std::error::Error;
use serde::Deserialize;
use tokio::fs::File;
use tokio::net::UdpSocket;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_native_tls::native_tls;
use tokio_native_tls::native_tls::Identity;

async fn control_even() {

}


pub async fn start_server(
    port: &u32,
    control_port: &u32,
    cert_path: &String,
) -> Result<(), Box<dyn Error>> {
    // open an virtual interface for VPN

    let sock = UdpSocket::bind(format!("0.0.0.0:{}", port)).await?;
    let control_channel: TcpListener =
        TcpListener::bind(format!("0.0.0.0:{}", control_port)).await?;
    let mut buf = [0; 2048];

    // open cert_path
    let mut cert_file = File::open(cert_path).await?;
    let mut cert_cnt: Vec<u8> = Vec::new();
    cert_file.read_to_end(&mut cert_cnt).await?;

    let cert = Identity::from_pkcs12(cert_cnt.as_slice(), "12345678")?;
    let tls_acceptor =
        tokio_native_tls::TlsAcceptor::from(native_tls::TlsAcceptor::builder(cert).build()?);
    
    loop {
        let (socket, remote_addr) = control_channel.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        println!("Accept control connection from {}", remote_addr);
        tokio::spawn(async move {
            // Accept the TLS connection.
            let mut tls_stream = tls_acceptor.accept(socket).await.expect("accept error");
            // In a loop, read data from the socket and write the data back.
            
            let mut buf = Vec::new();
            let n = tls_stream
                .read_to_end(&mut buf)
                .await
                .expect("failed to read data from socket");
    
            if n == 0 {
                // connection closed
                return;
            }
            
            let client_msg: ClientMsg = serde_json::from_slice(buf.as_slice()).unwrap();

            println!("Recv Client Msg: {:?}", client_msg);
            
        });
    }
    // let mut config = tun::Configuration::default();
    // config.address((10, 0, 0, 1))
    //        .netmask((255, 255, 255, 0))
    //        .up();

    // #[cfg(target_os = "linux")]
    // config.platform(|config| {
    // 	config.packet_information(true);
    // });
    // let mut dev = tun::create(&config).unwrap();
    // let mut buf = [0; 4096];
    Ok(())
}
