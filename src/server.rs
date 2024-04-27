use std::error::Error;
use tokio::fs::File;
use tokio::net::UdpSocket;
use tun::r#async;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_native_tls::native_tls;
use tokio_native_tls::native_tls::Identity;

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
        println!("Accept connection from {}", remote_addr);
        tokio::spawn(async move {
            // Accept the TLS connection.
            let mut tls_stream = tls_acceptor.accept(socket).await.expect("accept error");
            // In a loop, read data from the socket and write the data back.

            let mut buf = [0; 1024];
            let n = tls_stream
                .read(&mut buf)
                .await
                .expect("failed to read data from socket");

            if n == 0 {
                return;
            }
            println!("read={}", unsafe {
                String::from_utf8_unchecked(buf[0..n].into())
            });
            tls_stream
                .write_all(&buf[0..n])
                .await
                .expect("failed to write data to socket");
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
