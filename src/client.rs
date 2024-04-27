use std::error::Error;
use tokio::{io::AsyncWriteExt, net::{TcpStream, UdpSocket}};
use tokio_native_tls::native_tls::TlsConnector;

pub async fn start_client(
    endpoint: &String,
    port: &u32,
    ctl_port: &u32,
) -> Result<(), Box<dyn Error>> {
    // open an virtual interface for VPN
    let endpoint = format!("{}:{}", endpoint, ctl_port);
    let ctl_stm = TcpStream::connect().await?;
    
    let addr = endpoint
        .to_socket_addrs()?
        .next()
        .ok_or(format!("failed to resolve {}", endpoint))?;

    let cx = TlsConnector::builder().build()?;
    let cx = tokio_native_tls::TlsConnector::from(cx);

    let mut ctl_stm = cx.connect("127.0.0.1", ctl_stm).await?;
    
    ctl_stm.write_all("My name is Van.".as_bytes());

    // let remote_addr = format!("{}:{}", endpoint, port);
    // let mut buf = [0; 2048];
    //    let sock = UdpSocket::bind("127.0.0.1:0").await?;
    //    sock.send_to("Hello world!".as_bytes(), remote_addr).await?;
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
